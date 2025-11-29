import argparse, time, struct, os, math
from collections import defaultdict
from scapy.all import sniff, PcapWriter, get_if_list, \
    Ether, Dot1Q, RadioTap, Dot11, CookedLinux, \
    ARP, IP, IPv6, TCP, UDP, ICMP, Raw, DNS, DNSQR, DNSRR
from scapy.packet import NoPayload
try:
    import pandas as pd
except Exception:
    pd = None

try:
    from scapy.arch.windows import get_windows_if_list
except Exception:
    get_windows_if_list = None

DEFAULT_IFACE = r"\Device\NPF_{8AA9DF64-690E-4864-B382-29FCA46A2482}"

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
flows = defaultdict(lambda: {"pkts":0,"bytes":0,"first":None,"last":None,"iat_min":None,"iat_max":None,"iat_sum":0.0})
t0 = None

# -------- feature engineering --------
FEATURE_COLS = [
    # time
    "frame_no","ts_epoch","t_rel","len_bytes",

    # L2
    "eth_src","eth_dst","eth_type","vlan_id","vlan_prio",

    # L3
    "ip_version","ip_src","ip_dst","ttl_hlim","dscp","ecn","ip_flags_df","ip_flags_mf","ip_frag_off","ipv4_checksum_ok",

    # L4
    "l4_proto","sport","dport","tcp_flags","tcp_win","tcp_hdr_len","udp_len","l4_checksum_ok",

    # TCP opts
    "opt_mss","opt_wscale","opt_sackok","opt_tsval","opt_tsecr",

    # L7
    "dns_qname","dns_a","dns_aaaa","dns_cname","tls_sni","http_method","http_host","http_path",

    # simple flow
    "flow_pkts","flow_bytes","flow_iat_min","flow_iat_avg","flow_iat_max"
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
    ip_ver = ip_src = ip_dst = ttl_hlim = dscp = ecn = ip_df = ip_mf = ip_frag_off = ip4_ok = None

    if IP in pkt:
        ip = pkt[IP]
        ip_ver = 4
        ip_src = ip.src
        ip_dst = ip.dst
        ttl_hlim = ip.ttl
        dscp = (ip.tos>>2)&0x3F
        ecn = ip.tos&0x3

        ip_df = int(getattr(ip.flags, "DF", 0))
        ip_mf = int(getattr(ip.flags, "MF", 0))
        ip_frag_off = int(ip.frag)

        try: 
            ip4_ok = int(bool(ipv4_hdr_checksum_ok(ip)))
        except Exception: 
            ip4_ok = None

    elif IPv6 in pkt:
        ip = pkt[IPv6]
        ip_ver = 6
        ip_src = ip.src
        ip_dst = ip.dst
        ttl_hlim = ip.hlim
        dscp = (getattr(ip,"tc",0)>>2)&0x3F
        ecn = getattr(ip,"tc",0)&0x3
        ip_df = ip_mf = ip_frag_off = None
        ip4_ok = None

    # L4
    l4_proto = sport = dport = tcp_flags = tcp_win = tcp_hlen = udp_len = l4_ok = None

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
        udp_len = int(u.len)

    try:
        ok = l4_checksum_ok(pkt)
        l4_ok = None if ok is None else int(bool(ok))
    except Exception:
        l4_ok = None
    
    # TCP options
    opt_mss = opt_wscale = opt_sackok = opt_tsval = opt_tsecr = None

    if TCP in pkt:
        opts = parse_tcp_options(pkt[TCP])
        opt_mss    = opts.get("opt_mss")
        opt_wscale = opts.get("opt_wscale")
        opt_sackok = opts.get("opt_sackok")
        opt_tsval  = opts.get("opt_tsval")
        opt_tsecr  = opts.get("opt_tsecr")
    # L7
    dns_qname = dns_a = dns_aaaa = dns_cname = None

    d = safe_get(pkt, DNS)

    if d:
        if d.qr==0 and d.qd:
            dns_qname = d.qd.qname.decode(errors='ignore')

        if d.qr==1 and d.an:
            # collect first occurrence of types
            for i in range(int(d.ancount or 0)):
                rr = d.an[i]
                if isinstance(rr, DNSRR):
                    if rr.type == 1 and dns_a is None: 
                        dns_a = str(rr.rdata)
                    if rr.type == 28 and dns_aaaa is None: 
                        dns_aaaa = str(rr.rdata)
                    if rr.type == 5 and dns_cname is None:
                        try: 
                            dns_cname = rr.rdata.decode(errors='ignore')
                        except: 
                            dns_cname = str(rr.rdata)
    tls_sni = http_method = http_host = http_path = None

    payload = bytes(pkt[Raw].load) if Raw in pkt else b""

    if TCP in pkt and payload:
        sni = parse_tls_sni(payload)

        if sni: 
            tls_sni = sni

        m,h,p = parse_http(payload)

        if m: 
            http_method = m
            http_host = h
            http_path = p

    # flow stats (after update_flow_stats was called)
    f_pkts, f_bytes, f_iat_min, f_iat_avg, f_iat_max = flow_stats_for(pkt)
    
    return {
        "frame_no": n, 
        
        "ts_epoch": ts, 

        "t_rel": t_rel, 

        "len_bytes": len(raw),

        "eth_src": eth.src if eth else None, 
        "eth_dst": eth.dst if eth else None, 
        "eth_type": eth_type,

        "vlan_id": vlan_id, 
        "vlan_prio": vlan_prio,

        "ip_version": ip_ver, 
        "ip_src": ip_src, 
        "ip_dst": ip_dst, 

        "ttl_hlim": ttl_hlim, 

        "dscp": dscp, 

        "ecn": ecn,

        "ip_flags_df": ip_df, 
        "ip_flags_mf": ip_mf, 
        "ip_frag_off": ip_frag_off, 

        "ipv4_checksum_ok": ip4_ok,

        "l4_proto": l4_proto, 

        "sport": sport, 
        "dport": dport, 

        "tcp_flags": tcp_flags,
        "tcp_win": tcp_win, 
        "tcp_hdr_len": tcp_hlen, 

        "udp_len": udp_len, 

        "l4_checksum_ok": l4_ok,

        "opt_mss": opt_mss, 
        "opt_wscale": opt_wscale, 
        "opt_sackok": opt_sackok, 
        "opt_tsval": opt_tsval, 
        "opt_tsecr": opt_tsecr,

        "dns_qname": dns_qname, 
        "dns_a": dns_a, 
        "dns_aaaa": dns_aaaa, 
        "dns_cname": dns_cname,

        "tls_sni": tls_sni, 

        "http_method": http_method, 
        "http_host": http_host, 
        "http_path": http_path,

        "flow_pkts": f_pkts, 
        "flow_bytes": f_bytes, 
        "flow_iat_min": f_iat_min, 
        "flow_iat_avg": f_iat_avg, 
        "flow_iat_max": f_iat_max
    }

# -------- logging text (unchanged core pretty log) --------
def format_headers(p, n):
    ts = float(getattr(p, "time", time.time()))
    rel = ts - (t0 or ts)
    lt = time.localtime(ts)
    ms = int((ts - int(ts)) * 1000)
    ts_human = time.strftime("%Y-%m-%d %H:%M:%S", lt) + f".{ms:03d}"
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

# -------- main --------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-l","--list",action="store_true")
    ap.add_argument("-i","--iface", default=DEFAULT_IFACE)
    ap.add_argument("-f","--bpf",default="ip and tcp and (port 22 or port 80 or port 443 or port 445)")
    ap.add_argument("-o","--outfile",default="capture_live.pcap")
    ap.add_argument("--log",default="capture_live.txt")
    ap.add_argument("--features-csv",default="features.csv", help="CSV feature output")
    ap.add_argument("--features-parquet",default=None, help="Optional Parquet output (requires pyarrow)")
    ap.add_argument("--preview-only",action="store_true")
    ap.add_argument("--preview-bytes",type=int,default=32)
    ap.add_argument("-c","--count",type=int,default=0)
    ap.add_argument("-t","--seconds",type=int,default=0)
    args = ap.parse_args()

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

    # overwrite outputs
    for p in (args.outfile, args.log, args.features_csv, args.features_parquet):
        if p and os.path.exists(p): 
            os.remove(p)
        if p and os.path.exists(p): 
            os.remove(p)

    # prepare writers
    log = open(args.log, "w", encoding="utf-8")
    writer = None
    rows = []  # buffer features if pandas unavailable; else we’ll build DataFrame at end
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

        # pretty log
        header = format_headers(pkt, n)
        print(header)
        log.write(header + "\n")
        
        if args.preview_only:
            k = min(len(raw), args.preview_bytes)
            line = f"PayloadPreview({k}B): {raw[:k].hex(' ')}"
        else:
            line = f"FrameBytes({len(raw)}B): {raw.hex(' ')}"

        print(line)
        log.write(line + "\n")
        log.flush()

    print(f"Capturing on: {args.iface}")
    print(f"Writing to:   {args.outfile}")
    print(f"Logging to:   {args.log}")
    print(f"Features CSV: {args.features_csv}")

    if args.bpf: 
        print(f"Filter:       {args.bpf}")

    try:
        sniff(iface=args.iface, prn=handle, store=False, filter=args.bpf,
              count=args.count if args.count>0 else 0,
              timeout=args.seconds if args.seconds>0 else None)
    except KeyboardInterrupt:
        pass
    finally:
        # flow summary to log
        log.write("\n=== Flow summary ===\n")
        print("\n=== Flow summary ===")

        for k,v in flows.items():
            s,d,proto,sp,dp = k
            dur = (v["last"]-v["first"]) if (v["first"] and v["last"]) else 0.0
            iat_avg = (v["iat_sum"]/max(1,(v["pkts"]-1))) if v["pkts"]>1 else 0.0
            line = f"{s}:{sp} -> {d}:{dp} proto={proto} pkts={v['pkts']} bytes={v['bytes']} dur={dur:.6f}s iat_min={v['iat_min'] or 0:.6f}s iat_avg={iat_avg:.6f}s iat_max={v['iat_max'] or 0:.6f}s"
            log.write(line+"\n")
            print(line)
        log.close()

        if writer: 
            writer.close()

        # write features
        if pd is None:
            # minimal CSV writer without pandas
            import csv

            with open(args.features_csv, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=FEATURE_COLS, extrasaction="ignore")
                w.writeheader()

                for r in rows: 
                    w.writerow(r)
        else:
            df = pd.DataFrame(rows, columns=FEATURE_COLS)
            df.to_csv(args.features_csv, index=False)

            if args.features_parquet:
                try:
                    df.to_parquet(args.features_parquet, index=False)
                except Exception as e:
                    print(f"Parquet write failed: {e}")

        print(f"\nFeatures written: {args.features_csv}")

        if args.features_parquet:
            print(f"Parquet written:  {args.features_parquet}")

        print("\nStopped.")

if __name__ == "__main__":
    import struct
    main()
