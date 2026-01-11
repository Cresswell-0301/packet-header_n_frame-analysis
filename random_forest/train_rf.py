import os, glob, argparse, math, json, sys
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.ensemble import RandomForestClassifier

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from common_args import add_common_args
from config import MODEL_DEFAULTS

FEATURES = [
    "len_bytes","vlan_id","vlan_prio",
    "ip_version","ip_tos","dscp","ecn","ip_total_len","ip_id",
    "ip_flags_df","ip_flags_mf","ip_frag_off","ttl_hlim","ip_proto",
    "ip_hdr_checksum","ipv4_checksum_ok","ip_ihl_bytes",
    "l4_proto","sport","dport","tcp_win","tcp_hdr_len","l4_checksum_ok",
    "flow_pkts","flow_bytes","flow_iat_min","flow_iat_avg","flow_iat_max",
    # derived TCP flag bits:
    "tcp_flag_SYN","tcp_flag_ACK","tcp_flag_FIN","tcp_flag_RST","tcp_flag_PSH","tcp_flag_URG",
]
TARGET = "label"

LABEL_CANDIDATES = [
    "label","Label","Labels","class","Class","Attack","attack",
    "Category","Traffic","target","y"
]

CANON = {
    "benign": "benign",
    "normal": "benign",
    "good": "benign",
    "attack": "attack",
    "malicious": "attack",
    "anomaly": "attack",
    "bad": "attack",
    "tampered": "tampered",
    "tainted": "tampered",
}

def _normalize_label(v):
    if isinstance(v, (int, float)) and not (isinstance(v, float) and math.isnan(v)):
        return "attack" if int(v) == 1 else "benign"
    
    s = str(v).strip().lower()

    return CANON.get(s, s)

def _label_from_scores_row(row):
    if "ip_score" in row and not pd.isna(row["ip_score"]):
        s = float(row["ip_score"])
    elif "risk_score" in row and not pd.isna(row["risk_score"]):
        s = float(row["risk_score"])
    else:
        return None
    
    if s >= 70: return "attack"

    if s >= 40: return "tampered"

    return "benign"

def _flags_to_bits(v):
    # Default empty
    out = {
        "tcp_flag_SYN": 0, "tcp_flag_ACK": 0, "tcp_flag_FIN": 0,
        "tcp_flag_RST": 0, "tcp_flag_PSH": 0, "tcp_flag_URG": 0
    }

    # NaN/None
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return out

    # Bitmask
    if isinstance(v, (int, float)) and not (isinstance(v, float) and math.isnan(v)):
        b = int(v)
        out["tcp_flag_FIN"] = 1 if (b & 0x01) else 0
        out["tcp_flag_SYN"] = 1 if (b & 0x02) else 0
        out["tcp_flag_RST"] = 1 if (b & 0x04) else 0
        out["tcp_flag_PSH"] = 1 if (b & 0x08) else 0
        out["tcp_flag_ACK"] = 1 if (b & 0x10) else 0
        out["tcp_flag_URG"] = 1 if (b & 0x20) else 0
        return out

    # String tokens
    s = str(v).upper()
    out["tcp_flag_SYN"] = 1 if "S" in s else 0
    out["tcp_flag_ACK"] = 1 if "A" in s else 0
    out["tcp_flag_FIN"] = 1 if "F" in s else 0
    out["tcp_flag_RST"] = 1 if "R" in s else 0
    out["tcp_flag_PSH"] = 1 if "P" in s else 0
    out["tcp_flag_URG"] = 1 if "U" in s else 0
    return out

def _prep_chunk(df: pd.DataFrame, label_col: str | None) -> pd.DataFrame:
    # keep features + tcp_flags + label candidates + score columns
    keep = set(FEATURES + ["tcp_flags"] + LABEL_CANDIDATES + ["ip_score", "risk_score"])
    df = df[[c for c in df.columns if c in keep]].copy()

    # Expand tcp_flags -> bits
    if "tcp_flags" in df.columns:
        bits = df["tcp_flags"].apply(_flags_to_bits).apply(pd.Series)
        df = pd.concat([df.drop(columns=["tcp_flags"]), bits], axis=1)

    # Ensure all flag columns exist
    for k in ["tcp_flag_SYN","tcp_flag_ACK","tcp_flag_FIN","tcp_flag_RST","tcp_flag_PSH","tcp_flag_URG"]:
        if k not in df.columns:
            df[k] = 0

    # Find label column
    tgt = None
    if label_col and label_col in df.columns:
        tgt = label_col
    else:
        for c in LABEL_CANDIDATES:
            if c in df.columns:
                tgt = c
                break

    # Create TARGET
    if tgt is None:
        if ("ip_score" in df.columns) or ("risk_score" in df.columns):
            df[TARGET] = df.apply(_label_from_scores_row, axis=1)
        else:
            df[TARGET] = np.nan
    else:
        if tgt != TARGET:
            df.rename(columns={tgt: TARGET}, inplace=True)

    # Convert feature columns to numeric + fillna(0) ONLY for features
    for c in [c for c in df.columns if c != TARGET]:
        if df[c].dtype == object:
            df[c] = pd.to_numeric(df[c], errors="coerce")

    df[[c for c in df.columns if c != TARGET]] = df[[c for c in df.columns if c != TARGET]].fillna(0)

    # Normalize labels and filter
    df[TARGET] = df[TARGET].apply(_normalize_label)
    df = df[df[TARGET].isin(["benign","tampered","attack"])]

    final_cols = [c for c in FEATURES if c in df.columns] + [TARGET]

    return df[final_cols]

def list_files(folder: str, pattern: str="*.csv"):
    files = sorted(glob.glob(os.path.join(folder, pattern), recursive=True))

    if not files:
        print(f"[warn] No files matched: {os.path.join(folder, pattern)}")
        return []
    
    print(f"[info] Matched {len(files)} CSV files:")

    for i, f in enumerate(files, 1):
        print(f"  {i:03d}: {f}")

    return files

def build_args():
    ap = argparse.ArgumentParser()

    add_common_args(ap)

    d = MODEL_DEFAULTS["rf"]

    ap.add_argument("--model-out", default=d["model_out"])
    ap.add_argument("--meta-out", default=d["meta_out"])
    ap.add_argument("--n-estimators", type=int, default=d["n_estimators"])
    ap.add_argument("--max-depth", type=int, default=d["max_depth"])

    return ap.parse_args()

def main():
    args = build_args()

    buf = []
    n_kept = 0
    n_files = 0

    files = list_files(args.data_dir, args.pattern)

    if not files:
        return

    for f in files:
        n_files += 1
        kept_in_file = 0

        print(f"\n[file] {f}")

        for chunk_i, chunk in enumerate(
            pd.read_csv(f, chunksize=args.chunksize, low_memory=False), 1
        ):
            print(f"  [chunk] {chunk_i} rows={len(chunk):,}")

            # stop reading this file once we kept enough rows from it
            if args.rows_per_file > 0 and kept_in_file >= args.rows_per_file:
                print(f"  [file-cap] reached rows-per-file={args.rows_per_file:,}, stop reading rest of file.")
                break

            df = _prep_chunk(chunk, label_col=args.label_col)

            if TARGET not in df.columns:
                print(f"[warn] {f} missing '{TARGET}', skipping chunk")
                continue

            # stratified sampling
            p = args.per_chunk_sample
            if 0 < p < 1.0 and len(df):
                df = df.groupby(TARGET, group_keys=False).sample(
                    frac=p,
                    random_state=args.random_state
                )

            # enforce per-file KEPT cap after filtering/sampling
            if args.rows_per_file > 0:
                remaining = args.rows_per_file - kept_in_file
                if remaining <= 0:
                    print(f"  [file-cap] reached rows-per-file={args.rows_per_file:,}, stop reading rest of file.")
                    break
                if len(df) > remaining:
                    df = df.sample(n=remaining, random_state=args.random_state)

            if len(df) == 0:
                continue

            buf.append(df)
            kept_in_file += len(df)
            n_kept += len(df)

            print(
                f"[load] {os.path.basename(f)}  +{len(df):,} rows  file_kept={kept_in_file:,}"
            )

            if n_kept >= args.max_rows:
                print(f"[cap] Reached max-rows={args.max_rows:,}, stopping load.")
                break

        if n_kept >= args.max_rows:
            break

    if not buf:
        print("No training data loaded.")
        return

    data = pd.concat(buf, ignore_index=True)
    print(data["label"].value_counts(dropna=False))
    print(f"\nTraining rows: {len(data):,}  from files: {n_files}")

    # Only keep features that exist after union across files
    used_features = [c for c in FEATURES if c in data.columns]
    X = data[used_features].astype(np.float32)
    y = data[TARGET].apply(_normalize_label).astype(str)

    # Split
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, random_state=args.random_state, stratify=y
    )

    # Model
    rf = RandomForestClassifier(
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        n_jobs=-1,
        class_weight="balanced_subsample",
        random_state=args.random_state,
    )
    rf.fit(X_train, y_train)

    # Eval
    y_pred = rf.predict(X_val)
    
    print("\nConfusion Matrix:\n", confusion_matrix(y_val, y_pred))
    print("\nClassification Report:\n", classification_report(y_val, y_pred, digits=4))

    cm = confusion_matrix(y_val, y_pred)
    cr = classification_report(y_val, y_pred, digits=4)

    report_file = os.path.join("random_forest", "rf_model_report.txt")

    with open(report_file, "w") as f:
        f.write("Confusion Matrix:\n")
        f.write(str(cm))
        f.write("\n\nClassification Report:\n")
        f.write(str(cr))

    print(f"Evaluation report saved to {report_file}")

    # Save
    joblib.dump({"model": rf, "features": used_features}, args.model_out)
    print(f"\nSaved model -> {args.model_out}")

    meta = {
        "features": used_features,
        "target": TARGET,
        "params": {
            "n_estimators": args.n_estimators,
            "max_depth": args.max_depth,
            "class_weight": "balanced_subsample",
            "random_state": args.random_state,
        },
        "data_dir": args.data_dir,
        "pattern": args.pattern,
        "max_rows": args.max_rows,
        "per_chunk_sample": args.per_chunk_sample,
    }
    with open(args.meta_out, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    print(f"Saved meta   -> {args.meta_out}")

if __name__ == "__main__":
    main()
