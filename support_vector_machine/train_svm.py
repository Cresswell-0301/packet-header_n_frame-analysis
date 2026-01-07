import os, glob, argparse, math, json
import joblib
import numpy as np
import pandas as pd
from typing import Iterator
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV

FEATURES = [
    "len_bytes","vlan_id","vlan_prio",
    "ip_version","ip_tos","dscp","ecn","ip_total_len","ip_id",
    "ip_flags_df","ip_flags_mf","ip_frag_off","ttl_hlim","ip_proto",
    "ip_hdr_checksum","ipv4_checksum_ok","ip_ihl_bytes",
    "l4_proto","sport","dport","tcp_win","tcp_hdr_len","l4_checksum_ok",
    "flow_pkts","flow_bytes","flow_iat_min","flow_iat_avg","flow_iat_max",
    "tcp_flag_SYN","tcp_flag_ACK","tcp_flag_FIN","tcp_flag_RST","tcp_flag_PSH","tcp_flag_URG",
]

TARGET = "label"

LABEL_CANDIDATES = ["label","Label","Labels","class","Class","Attack","attack","Category","Traffic","target","y"]

CANON = {
    "benign":"benign","normal":"benign","good":"benign",
    "attack":"attack","malicious":"attack","anomaly":"attack","bad":"attack",
    "tampered":"tampered","tainted":"tampered",
}

def _normalize_label(v):
    if isinstance(v, (int, float)) and not (isinstance(v, float) and math.isnan(v)):
        return "attack" if int(v) == 1 else "benign"
    
    s = str(v).strip().lower()

    return CANON.get(s, s)

def _flags_to_bits(v):
    out = {"tcp_flag_SYN":0,"tcp_flag_ACK":0,"tcp_flag_FIN":0,"tcp_flag_RST":0,"tcp_flag_PSH":0,"tcp_flag_URG":0}

    if v is None or (isinstance(v, float) and math.isnan(v)):
        return out
    
    if isinstance(v, (int, float)) and not (isinstance(v, float) and math.isnan(v)):
        b = int(v)
        out["tcp_flag_FIN"] = 1 if (b & 0x01) else 0
        out["tcp_flag_SYN"] = 1 if (b & 0x02) else 0
        out["tcp_flag_RST"] = 1 if (b & 0x04) else 0
        out["tcp_flag_PSH"] = 1 if (b & 0x08) else 0
        out["tcp_flag_ACK"] = 1 if (b & 0x10) else 0
        out["tcp_flag_URG"] = 1 if (b & 0x20) else 0
        return out
    s = str(v).upper()
    out["tcp_flag_SYN"] = 1 if "S" in s else 0
    out["tcp_flag_ACK"] = 1 if "A" in s else 0
    out["tcp_flag_FIN"] = 1 if "F" in s else 0
    out["tcp_flag_RST"] = 1 if "R" in s else 0
    out["tcp_flag_PSH"] = 1 if "P" in s else 0
    out["tcp_flag_URG"] = 1 if "U" in s else 0
    return out

def _find_label_col(df: pd.DataFrame, label_col: str | None):
    if label_col and label_col in df.columns:
        return label_col
    for c in LABEL_CANDIDATES:
        if c in df.columns:
            return c
    return None

def _prep_chunk(df: pd.DataFrame, label_col: str | None) -> pd.DataFrame:
    # ✅ Detect label column BEFORE dropping columns
    tgt = _find_label_col(df, label_col)

    # ✅ Now decide what columns to keep
    keep = set(FEATURES + ["tcp_flags"] + LABEL_CANDIDATES)
    if tgt is not None:
        keep.add(tgt)  # ensure the real label column is not dropped

    # ✅ Filter columns
    df = df[[c for c in df.columns if c in keep]].copy()

    # Debug AFTER filtering (tgt is known now)
    print("[debug] chosen label col:", tgt, "| cols(after keep) first10:", list(df.columns)[:10])

    # Expand tcp flags if present
    if "tcp_flags" in df.columns:
        bits = df["tcp_flags"].apply(_flags_to_bits).apply(pd.Series)
        df = pd.concat([df.drop(columns=["tcp_flags"]), bits], axis=1)

    # Ensure flag columns exist
    for k in ["tcp_flag_SYN","tcp_flag_ACK","tcp_flag_FIN","tcp_flag_RST","tcp_flag_PSH","tcp_flag_URG"]:
        if k not in df.columns:
            df[k] = 0

    # Standardize label column name to TARGET
    if tgt is None:
        # No label available -> create it (but will be invalid for supervised training)
        df[TARGET] = np.nan
    else:
        if tgt != TARGET and tgt in df.columns:
            df.rename(columns={tgt: TARGET}, inplace=True)

    # Convert feature columns to numeric
    for c in [c for c in df.columns if c != TARGET]:
        if df[c].dtype == object:
            df[c] = pd.to_numeric(df[c], errors="coerce")

    df[[c for c in df.columns if c != TARGET]] = df[[c for c in df.columns if c != TARGET]].fillna(0)

    # Normalize and filter labels (only works if labels exist)
    df[TARGET] = df[TARGET].apply(_normalize_label)
    df = df[df[TARGET].isin(["benign", "tampered", "attack"])]

    # Final column order
    final_cols = [c for c in FEATURES if c in df.columns] + [TARGET]

    return df[final_cols]

def iter_dataset(folder: str, pattern: str, chunksize: int):
    files = sorted(glob.glob(os.path.join(folder, pattern), recursive=True))

    if not files:
        print(f"[warn] No files matched: {os.path.join(folder, pattern)}")
        return
    
    print(f"[info] Matched {len(files)} CSV files")

    for f in files:
        print(f"\n[file] {f}")

        for chunk_i, chunk in enumerate(pd.read_csv(f, chunksize=chunksize, low_memory=False), 1):
            print(f"  [chunk] {chunk_i} rows={len(chunk):,}")

            yield f, chunk

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default="cleaned_dataset")
    ap.add_argument("--pattern", default="*.csv")
    ap.add_argument("--model-out", default="svm_model.joblib")
    ap.add_argument("--meta-out", default="svm_model_meta.json")
    ap.add_argument("--max-rows", type=int, default=999999999, help="SVM: keep this smaller than RF")
    ap.add_argument("--per-chunk-sample", type=float, default=0.50)
    ap.add_argument("--random-state", type=int, default=42)
    ap.add_argument("--label-col", default="Label")
    ap.add_argument("--chunksize", type=int, default=200000)
    ap.add_argument("--C", type=float, default=1.0)
    ap.add_argument("--calib-method", default="sigmoid", choices=["sigmoid","isotonic"])
    args = ap.parse_args()

    rng = np.random.RandomState(args.random_state)
    buf, n_kept = [], 0

    for f, chunk in iter_dataset(args.data_dir, args.pattern, args.chunksize):
        df = _prep_chunk(chunk, label_col=args.label_col)

        p = args.per_chunk_sample

        if 0 < p < 1.0 and len(df):
            df = df.groupby(TARGET, group_keys=False).sample(
                frac=p,
                random_state=args.random_state
            )

        assert TARGET in df.columns, f"label dropped! cols={df.columns.tolist()}"

        buf.append(df)
        n_kept += len(df)

        print(f"[load] +{len(df):,} rows  total={n_kept:,}")

        if n_kept >= args.max_rows:
            print(f"[cap] Reached max-rows={args.max_rows:,}, stopping load.")
            break

    if not buf:
        print("No training data loaded.")
        return

    data = pd.concat(buf, ignore_index=True)

    print(data[TARGET].value_counts())

    used_features = [c for c in FEATURES if c in data.columns]
    X = data[used_features].astype(np.float32)
    y = data[TARGET].astype(str)

    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, random_state=args.random_state, stratify=y
    )

    # Linear SVM core (fast) + calibration (probabilities)
    base = LinearSVC(C=args.C, class_weight="balanced", random_state=args.random_state, max_iter=20_000)

    clf = Pipeline(steps=[
        ("scaler", StandardScaler(with_mean=False)),  # sparse-friendly; also OK for dense
        ("svm_cal", CalibratedClassifierCV(base, method=args.calib_method, cv=3))
    ])

    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_val)

    print("\nConfusion Matrix:\n", confusion_matrix(y_val, y_pred, labels=["attack","benign","tampered"]))
    print(classification_report(y_val, y_pred, digits=4, zero_division=0))

    joblib.dump({"model": clf, "features": used_features}, args.model_out)
    print(f"\nSaved model -> {args.model_out}")

    meta = {
        "features": used_features,
        "target": TARGET,
        "svm": {"type":"LinearSVC", "C":args.C, "class_weight":"balanced"},
        "calibration": {"method":args.calib_method, "cv":3},
        "max_rows": args.max_rows,
        "per_chunk_sample": args.per_chunk_sample
    }

    with open(args.meta_out, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    print(f"Saved meta   -> {args.meta_out}")

if __name__ == "__main__":
    main()
