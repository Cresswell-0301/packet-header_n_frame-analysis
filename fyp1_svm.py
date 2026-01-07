import argparse, time, struct, os, math, csv
import pandas as _pd
from collections import defaultdict
from scapy.all import sniff, PcapWriter, get_if_list, \
    Ether, Dot1Q, \
    IP, IPv6, TCP, UDP, Raw
from scapy.interfaces import resolve_iface

try:
    import pandas as pd
except Exception:
    pd = None

try:
    from scapy.arch.windows import get_windows_if_list
except Exception:
    get_windows_if_list = None

from joblib import load
import numpy as np

DEFAULT_IFACE = None

def safe_get(p, layer):
    try: 
        return p[layer]
    except Exception: 
        return None

def u16(b, off): 
    return (b[off]<<8) | b[off+1]

def ones_comp_sum(data):
    import struct as _s
    
    if len(data) % 2:
        data += b'\x00'
    
    s = sum(_s.unpack("!%dH" % (len(data)//2), data))
    
    while s >> 16: 
        s = (s & 0xFFFF) + (s >> 16)
    
    return (~s) & 0xFFFF

def ipv4_hdr_checksum_ok(ip):
    hdr = bytes(ip)[:ip.ihl*4]
    hdr = hdr[:10] + b'\x00\x00' + hdr[12:]
    return ones_comp_sum(hdr) == ip.chksum

def l4_checksum_ok(pkt):
    ip = safe_get(pkt, IP) or safe_get(pkt, IPv6)
    tcp, udp = safe_get(pkt, TCP), safe_get(pkt, UDP)
    
    if not ip or not (tcp or udp): 
        return None
    
    if tcp:
        seg = bytes(tcp)
        proto = 6
    else:
        seg = bytes(udp)
        proto = 17
    
    if IP in pkt:
        src = bytes(map(int, pkt[IP].src.split(".")))
        dst = bytes(map(int, pkt[IP].dst.split(".")))
        ph  = src + dst + struct.pack("!BBH", 0, proto, len(seg))
    else:
        # IPv6
        import ipaddress as _ip
        
        src = int(_ip.IPv6Address(pkt[IPv6].src)).to_bytes(16, 'big')
        dst = int(_ip.IPv6Address(pkt[IPv6].dst)).to_bytes(16, 'big')
        ph  = src + dst + struct.pack("!I3xB", len(seg), proto)
    
    if proto == 6: 
        seg = seg[:16] + b'\x00\x00' + seg[18:]
    else:           
        seg = seg[:6]  + b'\x00\x00' + seg[8:]
    
    calc = ones_comp_sum(ph + seg)
    return calc == (tcp.chksum if tcp else udp.chksum)

def parse_tcp_options(tcp):
    opts = []

    for k,v in (tcp.options or []):
        if k == 'MSS':       
            opts.append(("opt_mss", v))
        elif k == 'WScale':  
            opts.append(("opt_wscale", v))
        elif k == 'SAckOK':  
            opts.append(("opt_sackok", 1))
        elif k == 'Timestamp': 
            opts.append(("opt_tsval", v[0]))
            opts.append(("opt_tsecr", v[1]))

    return dict(opts)

def parse_tls_sni(payload_bytes):
    b = payload_bytes

    try:
        if len(b) < 5 or b[0] != 0x16: 
            return None
        
        rec_len = u16(b,3)

        if len(b) < 5+rec_len: 
            return None
        
        hs = b[5:5+rec_len]

        if len(hs) < 4 or hs[0] != 0x01: 
            return None
        if len(hs) < 4+34: 
            return None
        
        off = 4+34
        
        if off >= len(hs): 
            return None
        
        sid_len = hs[off]
        off += 1 + sid_len
        
        if off+2 > len(hs): 
            return None
        
        cs_len = u16(hs, off)
        off += 2 + cs_len
        
        if off+1 > len(hs): 
            return None
        
        cm_len = hs[off]
        off += 1 + cm_len
        
        if off+2 > len(hs): 
            return None
        
        ext_len = u16(hs, off)
        off += 2
        end = min(len(hs), off + ext_len)

        while off + 4 <= end:
            etype = u16(hs, off)
            elen = u16(hs, off+2)
            off += 4

            if etype == 0 and off + 2 <= end:
                lst_len = u16(hs, off)
                p = off+2
                
                while p + 3 <= off+2+lst_len and p + 3 <= end:
                    nt = hs[p]
                    nlen = u16(hs, p+1)
                    p += 3

                    if nt == 0 and p + nlen <= end:
                        return hs[p:p+nlen].decode("idna", "ignore")
                    
                    p += nlen
            off += elen
    except Exception:
        return None
    
    return None

def parse_http(payload_bytes):
    try:
        head = payload_bytes.split(b"\r\n\r\n",1)[0]

        if not head: 
            return None, None, None
        
        lines = head.split(b"\r\n")
        
        if lines[0].startswith((b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ")):
            parts = lines[0].split(b" ")
            method = parts[0].decode(errors='ignore'); path = parts[1].decode(errors='ignore')
            host = ""
            
            for ln in lines[1:]:
                low = ln.lower()
                
                if low.startswith(b"host:"):
                    host = ln.split(b":",1)[1].strip().decode(errors='ignore')
                    break
            
            return method, host, path
        
        if lines[0].startswith(b"HTTP/"):
            return "RESP", None, lines[0].decode(errors='ignore')
    except Exception:
        pass
    return None, None, None

# flow stats store
flows = defaultdict(lambda: {"pkts": 0, "bytes": 0, "first": None, "last": None, "iat_min": None, "iat_max": None, "iat_sum": 0.0})
t0 = None

# feature columns
FEATURE_COLS = [
# Metadata
    "frame_no", "ts_epoch", "t_rel", "ts_local", "len_bytes",

# L2
    "eth_src", "eth_dst", "eth_type", "vlan_id", "vlan_prio",

# L3 - IPv4 Header
    # Version
    "ip_version",
    
    # Type of Service
    "ip_tos", "dscp", "ecn",

    # Total Length
    "ip_total_len",

    # Identification
    "ip_id",

    # Flag & Fragment Offset
    "ip_flags_df", "ip_flags_mf", "ip_frag_off",

    # TTL & Protocol
    "ttl_hlim", "ip_proto",

    # Header Checksum
    "ip_hdr_checksum", "ipv4_checksum_ok",
    
    # Source & Destination IP
    "ip_src", "ip_dst",

    # Extra
    "ip_ihl_bytes",

# L4
    "l4_proto", "sport", "dport", "tcp_flags", "tcp_win", "tcp_hdr_len", "l4_checksum_ok",

# Simple Flow
    "flow_pkts", "flow_bytes", "flow_iat_min", "flow_iat_avg", "flow_iat_max",
]

def five_tuple(pkt):
    if IP in pkt:
        s,d = pkt[IP].src, pkt[IP].dst
        proto = pkt[IP].proto
    elif IPv6 in pkt:
        s,d = pkt[IPv6].src, pkt[IPv6].dst
        proto = pkt[IPv6].nh
    else:
        return None
    
    if TCP in pkt: 
        sp,dp = pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt: 
        sp,dp = pkt[UDP].sport, pkt[UDP].dport
    else: 
        sp=dp=None

    return (s,d,proto,sp,dp)

def update_flow_stats(pkt, rawlen):
    global t0
    ts = float(getattr(pkt, "time", time.time()))

    if t0 is None: 
        t0 = ts

    key = five_tuple(pkt)
    
    if key:
        f = flows[key]
        f["pkts"] += 1; 
        f["bytes"] += rawlen
        
        if f["first"] is None: 
            f["first"] = ts
        
        if f["last"] is not None:
            iat = ts - f["last"]
            f["iat_sum"] = (f["iat_sum"] or 0.0) + iat
            f["iat_min"] = iat if f["iat_min"] is None else min(f["iat_min"], iat)
            f["iat_max"] = iat if f["iat_max"] is None else max(f["iat_max"], iat)
        
        f["last"] = ts

def flow_stats_for(pkt):
    key = five_tuple(pkt)
    
    if not key: 
        return (0,0,0.0,0.0,0.0)
    
    f = flows[key]
    pkts = f["pkts"]; 
    by = f["bytes"]
    
    if pkts and pkts > 1:
        iat_avg = (f["iat_sum"] or 0.0) / (pkts - 1)
    else:
        iat_avg = 0.0

    return (pkts, by, f["iat_min"] or 0.0, iat_avg, f["iat_max"] or 0.0)

def time_local(ts, t0, fmt):
    rel = ts - (t0 or ts)
    lt = time.localtime(ts)
    ms = int((ts - int(ts)) * 1000)
    ts_human = time.strftime("%Y-%m-%d %H:%M:%S", lt) + f".{ms:03d}"

    if fmt == 'log':
        return ts_human, rel, ts
    elif fmt == 'csv':
        return ts_human

def feature_row(n, pkt, raw):
    # time
    ts = float(getattr(pkt, "time", time.time()))
    t_rel = ts - (t0 or ts)

    # L2
    eth = safe_get(pkt, Ether)
    vlan = safe_get(pkt, Dot1Q)

    eth_type = None
    vlan_id = None
    vlan_prio = None

    if eth:
        eth_type = f"0x{eth.type:04x}"

    if vlan:
        # handle stacked VLANs by taking outermost first
        vlan_id = vlan.vlan
        vlan_prio = vlan.prio

    # L3
    ip_ver = ip_tos = ip_src = ip_dst = ttl_hlim = dscp = ecn = ip_df = ip_mf = ip_frag_off = ip4_ok = None

    ip_ihl_bytes = ip_total_len = ip_id = ip_proto = ip_hdr_checksum = None

    if IP in pkt:
        ip = pkt[IP]
        ip_ver = int(getattr(ip, "version", 4))
        ip_tos = int(getattr(ip, "tos", 0))
        ip_src = ip.src
        ip_dst = ip.dst
        ttl_hlim = ip.ttl
        dscp = (ip.tos>>2)&0x3F
        ecn = ip.tos&0x3

        ip_df = int(getattr(ip.flags, "DF", 0))
        ip_mf = int(getattr(ip.flags, "MF", 0))
        ip_frag_off = int(ip.frag)

        ip_ihl_bytes   = int(ip.ihl or 0) * 4
        ip_total_len   = int(getattr(ip, "len", 0))
        ip_id          = int(getattr(ip, "id", 0))
        ip_proto       = int(getattr(ip, "proto", 0))
        ip_hdr_checksum= int(getattr(ip, "chksum", 0))

        try: 
            ip4_ok = int(bool(ipv4_hdr_checksum_ok(ip)))
        except Exception: 
            ip4_ok = None

    elif IPv6 in pkt:
        ip = pkt[IPv6]
        ip_ver = int(getattr(ip, "version", 6))
        ip_src = ip.src
        ip_dst = ip.dst
        ttl_hlim = ip.hlim
        dscp = (getattr(ip,"tc",0)>>2)&0x3F
        ecn = getattr(ip,"tc",0)&0x3
        ip_df = ip_mf = ip_frag_off = None
        ip4_ok = None

    # L4
    l4_proto = sport = dport = tcp_flags = tcp_win = tcp_hlen = l4_ok = None

    if TCP in pkt:
        t = pkt[TCP]
        l4_proto = 6
        sport = t.sport
        dport = t.dport
        tcp_flags = str(t.flags)
        tcp_win = int(t.window)
        tcp_hlen = (t.dataofs or 0)*4

    if UDP in pkt:
        u = pkt[UDP]
        l4_proto = 17
        sport = u.sport
        dport = u.dport

    try:
        ok = l4_checksum_ok(pkt)
        l4_ok = None if ok is None else int(bool(ok))
    except Exception:
        l4_ok = None
    
    # flow stats (after update_flow_stats was called)
    f_pkts, f_bytes, f_iat_min, f_iat_avg, f_iat_max = flow_stats_for(pkt)
    
    ts_human = time_local(float(getattr(pkt, "time", time.time())), t0, 'csv')

    return {
    # Metadata
        "frame_no": n, 
        "ts_epoch": ts, 
        "t_rel": t_rel,
        "ts_local": ' ' + ts_human,
        "len_bytes": len(raw),

    # L2
        "eth_src": eth.src if eth else None, 
        "eth_dst": eth.dst if eth else None, 
        "eth_type": eth_type,
        "vlan_id": vlan_id,
        "vlan_prio": vlan_prio,

    # L3 - IPv4 Header
        # Version
        "ip_version": ip_ver,
        
        # Type of Service
        "ip_tos": ip_tos,
        "dscp": dscp, 
        "ecn": ecn,

        # Total Length
        "ip_total_len": ip_total_len,

        # Identification
        "ip_id": ip_id,

        # Flag & Fragment Offset
        "ip_flags_df": ip_df, 
        "ip_flags_mf": ip_mf, 
        "ip_frag_off": ip_frag_off, 

        # TTL & Protocol
        "ttl_hlim": ttl_hlim, 
        "ip_proto": ip_proto,

        # Header Checksum
        "ip_hdr_checksum": ip_hdr_checksum,
        "ipv4_checksum_ok": ip4_ok,
        
        # Source & Destination IP
        "ip_src": ip_src, 
        "ip_dst": ip_dst, 

        # Extra
        "ip_ihl_bytes": ip_ihl_bytes,

    # L4
        "l4_proto": l4_proto,

        "sport": sport, 
        "dport": dport, 

        "tcp_flags": tcp_flags,
        "tcp_win": tcp_win, 
        "tcp_hdr_len": tcp_hlen, 

        "l4_checksum_ok": l4_ok,

    # Simple Flow
        "flow_pkts": f_pkts, 
        "flow_bytes": f_bytes, 
        "flow_iat_min": f_iat_min, 
        "flow_iat_avg": f_iat_avg, 
        "flow_iat_max": f_iat_max
    }

# Log text format
def format_headers(p, n):
    ts_human, rel, ts = time_local(float(getattr(p, "time", time.time())), t0, 'log')
    lines = [f"\n=== Frame {n} ===", f"ts_epoch={ts:.6f} ts_local={ts_human} t_rel={rel:.6f}s"]
    eth = safe_get(p, Ether)
    vlan = safe_get(p, Dot1Q)

    if eth: 
        lines.append(f"L2: Ethernet src={eth.src} dst={eth.dst} type=0x{eth.type:04x}")
    
    while vlan:
        lines.append(f"  VLAN id={vlan.vlan} pri={vlan.prio}")
        vlan = vlan.payload if isinstance(vlan.payload, Dot1Q) else None

    ip4 = safe_get(p, IP)
    ip6 = safe_get(p, IPv6)
    
    if ip4:
        dscp = (ip4.tos>>2)&0x3F
        ecn = ip4.tos&0x3

        lines.append(f"L3: IPv4 {ip4.src}->{ip4.dst} proto={ip4.proto} ttl={ip4.ttl} id={ip4.id} flags={ip4.flags} DSCP={dscp} ECN={ecn} frag_off={ip4.frag}")

        try: 
            lines.append(f"  IPv4_checksum={'OK' if ipv4_hdr_checksum_ok(ip4) else 'BAD'}")
        except: 
            lines.append("  IPv4_checksum=NA")
    if ip6:
        lines.append(f"L3: IPv6 {ip6.src}->{ip6.dst} nh={ip6.nh} hlim={ip6.hlim} tc={getattr(ip6,'tc',0)}")
    
    tcp = safe_get(p, TCP)
    udp = safe_get(p, UDP)
    
    if tcp:
        lines.append(f"L4: TCP {tcp.sport}->{tcp.dport} seq={tcp.seq} ack={tcp.ack} flags={tcp.flags} win={tcp.window}")
    
    if udp:
        lines.append(f"L4: UDP {udp.sport}->{udp.dport} len={udp.len}")
    
    if (ip4 or ip6) and (tcp or udp):
        try:
            ok = l4_checksum_ok(p)
            lines.append(f"  L4_checksum={'OK' if ok else 'BAD' if ok is False else 'NA'}")
        except: 
            lines.append("  L4_checksum=NA")
    
    payload = bytes(p[Raw].load) if Raw in p else b""

    if tcp and payload:
        sni = parse_tls_sni(payload); 

        if sni: 
            lines.append(f"TLS SNI={sni}")

        m,h,pp = parse_http(payload)

        if m: 
            lines.append(f"HTTP {m} host={h} path={pp}")

    return "\n".join(lines)

def _heuristic_ip_score(row):
    score = 0
    
    # Header integrity
    if row.get("ipv4_checksum_ok") == 0:
        score += 35

    if row.get("l4_checksum_ok") == 0:
        score += 25

    # Fragmentation/flags
    if (row.get("ip_flags_mf") == 1) or (row.get("ip_frag_off", 0) > 0):
        score += 10

    # TTL out-of-typical range (common 32/64/128/255; penalize very low)
    ttl = row.get("ttl_hlim") or 0

    if 0 < ttl < 20:
        score += 10

    # Suspicious TCP flags (e.g., just SYN+FIN or empty)
    flags = (row.get("tcp_flags") or "").upper()

    if "SF" in flags or flags == "":
        score += 5

    # DSCP/ECN unusual (light nudge only)
    dscp = row.get("dscp") or 0

    if dscp not in (0, 8, 16, 24, 32, 46):  # common DSCPs
        score += 3

    dp = row.get("dport")

    # focus ports
    if dp in (22, 80, 443, 445):
        score += 2

    return max(0, min(100, score))

def _risk_from_ip_score(ip_score):
    # treat ip_score as base; cap 100
    return max(0, min(100, int(ip_score)))

def score_packet(args):
    scores_out = "scores.csv"

    try:
        _df = _pd.read_csv(args.scores_csv)

        num_cols = ["ipv4_checksum_ok", "l4_checksum_ok", "ip_flags_mf", "ip_frag_off", "ttl_hlim", "dscp", "dport"]
        
        for c in num_cols:
            _df[c] = _pd.to_numeric(_df.get(c), errors="coerce").fillna(0).astype(int)

        _df["tcp_flags"] = _df.get("tcp_flags").fillna("").astype(str)

        ip_scores = []
        risk_scores = []

        for _, r in _df.iterrows():
            s = _heuristic_ip_score(r)
            ip_scores.append(s)
            rs = _risk_from_ip_score(s)
            risk_scores.append(rs)

        _df["ip_score"] = ip_scores
        _df["risk_score"] = risk_scores

        # add the three columns to the end
        final_cols = list(_df.columns)

        # new columns are moved to the tail in exact order
        for c in ("ip_score", "risk_score"):
            final_cols.remove(c)

        final_cols = final_cols + ["ip_score", "risk_score"]

        _df.to_csv(scores_out, index=False, columns=final_cols)
        
        print(f"Scores written         : {scores_out}")

    except Exception as e:
            print(f"\nFailed to write {scores_out}: {e}")

    return None

def run_ml_detection(model_path, input_csv, output_csv):
    try:
        print("\nRunning ML detection...\n")

        # Load trained model bundle
        bundle = load(model_path)
        model = bundle["model"]
        features = bundle["features"]

        # Load scored packets
        df = _pd.read_csv(input_csv)
        df = expand_tcp_flags(df)

        # Ensure all required features exist
        for f in features:
            if f not in df.columns:
                df[f] = 0
            
            # Convert to numeric (handles strings/None) then fill NaN
            df[f] = _pd.to_numeric(df[f], errors="coerce").fillna(0)
            
        # Final safety: replace any remaining inf/-inf/NaN
        X = df[features].replace([np.inf, -np.inf], 0).fillna(0).astype(np.float32)

        proba = model.predict_proba(X)
        confidences = proba.max(axis=1)
        
        df["label"] = [
            apply_confidence_policy(c) for c in confidences
        ]

        df["confidence"] = confidences
        
        df.to_csv(output_csv, index=False)
        
        print(f"ML detection written   : {output_csv}")
        print(df["label"].value_counts())

    except Exception as e:
        print(f"[ML detection failed] {e}")

    return output_csv

def expand_tcp_flags(df):
    flags = df.get("tcp_flags", "").fillna("").astype(str).str.upper()

    df["tcp_flag_SYN"] = flags.str.contains("S").astype(int)
    df["tcp_flag_ACK"] = flags.str.contains("A").astype(int)
    df["tcp_flag_FIN"] = flags.str.contains("F").astype(int)
    df["tcp_flag_RST"] = flags.str.contains("R").astype(int)
    df["tcp_flag_PSH"] = flags.str.contains("P").astype(int)
    df["tcp_flag_URG"] = flags.str.contains("U").astype(int)

    return df

def apply_confidence_policy(conf):
    if conf >= 0.90:
        return "attack"
    elif conf >= 0.60:
        return "tampered"
    else:
        return "benign"

EXCLUDE_KEYWORDS = (
    "loopback", "wan miniport", "virtual", "vmware", "hyper-v",
    "bluetooth", "wi-fi direct", "tunnel", "teredo", "isatap"
)

def good_capture_ifaces(include_virtual=False, verbose=True):
    if get_windows_if_list:
        raw = get_windows_if_list() or []
        primary, fallback = [], []
        for x in raw:
            guid = x.get("guid")
            if not guid:
                continue
            name = rf"\Device\NPF_{guid}"
            desc = (x.get("description") or "").lower()
            ips  = x.get("ips") or []

            # always keep a full fallback list 
            fallback.append(name)

            if (not include_virtual) and any(k in desc for k in EXCLUDE_KEYWORDS):
                continue

            # prefer devices with an IPv4 address
            if not any("." in ip for ip in ips):
                continue

            primary.append(name)

        if primary:
            return primary
        if verbose:
            print("[warn] primary scan empty; falling back to ALL devices.")
        return fallback

    return list(get_if_list() or [])

# main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-l", "--list", action="store_true")
    ap.add_argument("-i", "--iface",  default=DEFAULT_IFACE)
    ap.add_argument("-f", "--bpf", default="ip and tcp and (port 22 or port 80 or port 443 or port 445)")
    ap.add_argument("-o", "--outfile", default="capture_live.pcap")
    ap.add_argument("--log", default="capture_live.txt")
    ap.add_argument("--features-csv", default="features.csv", help="CSV feature output")
    ap.add_argument("--features-parquet", default=None, help="Optional Parquet output (requires pyarrow)")
    ap.add_argument("--preview-only", action="store_true")
    ap.add_argument("--preview-bytes", type=int, default=32)
    ap.add_argument("-c", "--count", type=int, default=0)
    ap.add_argument("-t", "--seconds", type=int, default=0)
    ap.add_argument("--include-virtual",  action="store_true", help="Include virtual/WAN/loopback adapters in capture candidates")
    ap.add_argument("--ifaces",  default=None, help="Comma-separated Npcap device names to sniff (overrides auto selection)")

    args = ap.parse_args()

    # display list of interfaces
    if args.list:
        # list interfaces and exit
        if get_windows_if_list:
            for i, itf in enumerate(get_windows_if_list(), 1):
                ips = ",".join(itf.get("ips", []) or [])
                print(f"{i}. {itf['name']}  guid={{{itf['guid']}}}  ip={ips}  desc={itf['description']}")
        else:
            for i, iface in enumerate(get_if_list(), 1):
                print(f"{i}. {iface}")
        return
    
    if args.ifaces:
        candidates = [s.strip() for s in args.ifaces.split(",") if s.strip()]
    else:
        candidates = good_capture_ifaces(include_virtual=True)

    all_ifaces = []

    print("\nValidating capture interfaces...")

    for iface in candidates:
        try:
            resolve_iface(iface)
            all_ifaces.append(iface)
        except Exception:
            pass

    if not all_ifaces:
        print("No valid interfaces found (all candidates failed to resolve).")
        return
    
    iface_names = {}

    if get_windows_if_list:
        try:
            for x in get_windows_if_list():
                guid = x.get("guid")
                if guid:
                    # map device path to interface name
                    friendly = x.get("name") or x.get("description") or "Unknown"
                    dev_path = rf"\Device\NPF_{guid}"
                    iface_names[dev_path] = friendly
        except:
            pass
    
    # overwrite outputs
    for p in (args.outfile, args.log, args.features_csv, args.features_parquet):
        if p and os.path.exists(p): 
            os.remove(p)
        if p and os.path.exists(p): 
            os.remove(p)
    
    log = open(args.log, "w", encoding="utf-8")
    writer = None
    rows = []
    n = 0

    def handle(pkt):
        nonlocal writer, n, rows
        global t0

        if writer is None:
            writer = PcapWriter(args.outfile, append=False, sync=True)

        raw = bytes(pkt)
        ts = float(getattr(pkt, "time", time.time()))

        if t0 is None: 
            t0 = ts

        writer.write(pkt)
        n += 1

        # update flow stats first
        update_flow_stats(pkt, len(raw))

        # features
        row = feature_row(n, pkt, raw)
        rows.append(row)

        header = format_headers(pkt, n)

        # Write header to log
        log.write(header + "\n")
        
        if args.preview_only:
            k = min(len(raw), args.preview_bytes)
            line = f"PayloadPreview({k}B): {raw[:k].hex(' ')}"
        else:
            line = f"FrameBytes({len(raw)}B): {raw.hex(' ')}"

        # Write to log
        log.write(line + "\n")
        log.flush()

    print("\nCapturing on valid interfaces:")
    
    for idx, itf in enumerate(all_ifaces, 1):
        friendly_name = iface_names.get(itf, "Interface")
        print(f"  {idx}. {friendly_name} => {itf}")

    print(f"\nWriting to   : {args.outfile}")
    print(f"Logging to   : {args.log}")
    print(f"Features CSV : {args.features_csv}")

    if args.bpf: 
        print(f"Filter       : {args.bpf}")

    try:
        print("\nCapture started... Press Ctrl+C to stop.")

        sniff(iface=all_ifaces, prn=handle, store=False, filter=args.bpf,
              count=args.count if args.count>0 else 0,
              timeout=args.seconds if args.seconds>0 else None)
    except KeyboardInterrupt:
        pass
    finally:
        # flow summary to log
        log.write("\n=== Flow summary ===\n")

        for k,v in flows.items():
            s,d,proto,sp,dp = k
            dur = (v["last"]-v["first"]) if (v["first"] and v["last"]) else 0.0
            iat_avg = (v["iat_sum"]/max(1,(v["pkts"]-1))) if v["pkts"]>1 else 0.0
            line = f"{s}:{sp} -> {d}:{dp} proto={proto} pkts={v['pkts']} bytes={v['bytes']} dur={dur:.6f}s iat_min={v['iat_min'] or 0:.6f}s iat_avg={iat_avg:.6f}s iat_max={v['iat_max'] or 0:.6f}s"
            log.write(line+"\n")
        log.close()

        if writer: 
            writer.close()

        print("\nCapture stopped.\n")
        
        print(f"Total packets captured : {n}")
        print(f"Total flows            : {len(flows)}\n")

        print(f"PCAP written           : {args.outfile}")
        print(f"Log written            : {args.log}")
        
        # write features
        if pd is None:
            # minimal CSV writer without pandas
            with open(args.features_csv, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=FEATURE_COLS, extrasaction="ignore")
                w.writeheader()

                for r in rows: 
                    w.writerow(r)
        else:
            if rows:
                df = pd.DataFrame(rows, columns=FEATURE_COLS)
                df.to_csv(args.features_csv, index=False)

                if args.features_parquet:
                    try:
                        df.to_parquet(args.features_parquet, index=False)
                    except Exception as e:
                        print(f"Parquet write failed       : {e}")
            else:
                print("No packets captured, skipping CSV generation.")

        print(f"Features written       : {args.features_csv}")

        if args.features_parquet:
            print(f"Parquet written       : {args.features_parquet}")

        args.scores_csv = run_ml_detection(
            model_path="./support_vector_machine/svm_model.joblib",
            input_csv="features.csv",
            output_csv="scores.csv"
        )

        print("\nScoring packets...\n")

        score_packet(args)

        print("\nExit.")

if __name__ == "__main__":
    import struct
    main()