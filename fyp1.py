import argparse, time, struct, os, csv, json, ipaddress
import pandas as pd
from collections import defaultdict
from scapy.all import sniff, PcapWriter, get_if_list, \
    Ether, Dot1Q, ARP, \
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
from urllib.parse import urlencode
from urllib.request import urlopen, Request
from dotenv import load_dotenv

load_dotenv()

DEFAULT_IFACE = None

SCAMALYTICS_BASE_URL = os.getenv("SCAMALYTICS_BASE_URL")
SCAMALYTICS_USER = os.getenv("SCAMALYTICS_USER")
SCAMALYTICS_KEY = os.getenv("SCAMALYTICS_KEY")
SCAMALYTICS_TIMEOUT = float(os.getenv("SCAMALYTICS_TIMEOUT", "3.0"))

scamalytics_cache = {}

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


def parse_tls_sni(b):
    try:
        if len(b) < 9 or b[0] != 0x16:
            return None

        rec_len = int.from_bytes(b[3:5], "big")
        if len(b) < 5 + rec_len:
            return None

        rec = b[5:5 + rec_len]

        # ClientHello handshake
        if len(rec) < 4 or rec[0] != 0x01:
            return None

        hs_len = int.from_bytes(rec[1:4], "big")
        if len(rec) < 4 + hs_len:
            return None

        ch = rec[4:4 + hs_len]

        p = 0

        # legacy_version (2) + random (32)
        if p + 34 > len(ch):
            return None
        p += 34

        # session_id
        if p + 1 > len(ch):
            return None
        sid_len = ch[p]
        p += 1
        if p + sid_len > len(ch):
            return None
        p += sid_len

        # cipher_suites
        if p + 2 > len(ch):
            return None
        cs_len = int.from_bytes(ch[p:p+2], "big")
        p += 2
        if p + cs_len > len(ch):
            return None
        p += cs_len

        # compression_methods
        if p + 1 > len(ch):
            return None
        comp_len = ch[p]
        p += 1
        if p + comp_len > len(ch):
            return None
        p += comp_len

        # extensions
        if p + 2 > len(ch):
            return None
        ext_total = int.from_bytes(ch[p:p+2], "big")
        p += 2
        ext_end = p + ext_total
        if ext_end > len(ch):
            return None

        while p + 4 <= ext_end:
            etype = int.from_bytes(ch[p:p+2], "big")
            elen = int.from_bytes(ch[p+2:p+4], "big")
            p += 4

            if p + elen > ext_end:
                return None

            if etype == 0:  # server_name
                ext = ch[p:p+elen]

                if len(ext) < 5:
                    return None

                list_len = int.from_bytes(ext[0:2], "big")
                q = 2
                list_end = min(2 + list_len, len(ext))

                while q + 3 <= list_end:
                    name_type = ext[q]
                    name_len = int.from_bytes(ext[q+1:q+3], "big")
                    q += 3

                    if q + name_len > list_end:
                        return None

                    if name_type == 0:
                        return ext[q:q+name_len].decode("ascii", "ignore")

                    q += name_len

                return None

            p += elen

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


def parse_ssh_banner(payload_bytes):
    try:
        if not payload_bytes:
            return None

        text = payload_bytes.decode("utf-8", errors="ignore").strip()

        if text.startswith("SSH-"):
            first_line = text.splitlines()[0].strip()

            if len(first_line) <= 255:
                return first_line
    except Exception:
        return None

    return None


# flow stats store
flows = defaultdict(lambda: {
    # Basic volume & timing
    "pkts": 0,
    "bytes": 0,
    "first": None,
    "last": None,

    # Inter arrival time (IAT)
    "iat_min": None,
    "iat_max": None,
    "iat_sum": 0.0,

    # direction counters : Client → Server (forward) ; Server → Client (reverse)
    "fwd_pkts": 0,
    "rev_pkts": 0,
    "fwd_bytes": 0,
    "rev_bytes": 0,

    # TCP behaviour
    "syn_count": 0, # connection start
    "ack_count": 0, # normal traffic
    "fin_count": 0, # normal close
    "rst_count": 0, # abnormal reset
    "psh_count": 0, # data push

    # handshake tracking
    "syn_seen": 0,
    "synack_seen": 0,
    "ack_seen_after_synack": 0,

    # integrity / anomaly counters
    "bad_ip_checksum_count": 0, # corrupted / crafted packets
    "bad_l4_checksum_count": 0, # suspicious or forged traffic
    "frag_count": 0, # fragmentation attack / evasion
    "mac_ip_inconsistent_count": 0, # spoofing
    "low_ttl_count": 0, # scanning / crafted packets
    "unusual_dscp_count": 0, # covert channel / QoS abuse

    # protocol hints
    "http_seen": 0, # 80
    "tls_seen": 0, # 443
    "dns_seen": 0,
    "ssh_seen": 0, # 22
    "smb_seen": 0, # 445

    # protocol evidence source
    "http_payload_detected": 0,
    "http_port_fallback": 0,
    "tls_payload_detected": 0,
    "tls_port_fallback": 0,

    # SSH details
    "ssh_payload_detected": 0,
    "ssh_port_fallback": 0,
    "ssh_detect_source": "",
    "ssh_banner": "",

    # HTTP details
    "http_method": "",
    "http_host": "",
    "http_path": "",
    "http_buffer": b"",
    "http_done": 0,

    # TLS details
    "tls_sni": "",
    "tls_buffer": b"",
    "tls_sni_done": 0,

    # source labels
    "http_detect_source": "",
    "tls_detect_source": "",

    # ports / endpoints
    "sport_set": set(),
    "dport_set": set(),

    # explanation
    "reasons": set(),
})

ip_to_macs = defaultdict(set)
mac_to_ips = defaultdict(set)
ip_mac_first_seen = {}
ip_mac_last_seen = {}

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

# MAC-IP
    "src_ip_mac_consistent", # 1 = only one MAC seen for this source IP so far , 0 = multiple MACs have claimed this source IP
    "src_ip_mac_seen_mac_count", # how many distinct MACs have claimed this source IP
    "src_mac_ip_seen_ip_count", # how many distinct MACs have claimed this source IP
    "src_mac_ip_spoof_suspect", # binary suspicion flag

# L4
    "l4_proto", "sport", "dport", "tcp_flags", "tcp_win", "tcp_hdr_len", "l4_checksum_ok",

# Flow
    "flow_pkts",
    "flow_bytes",
    "flow_iat_min",
    "flow_iat_avg",
    "flow_iat_max",

# Extended Flow
    "flow_duration",
    "flow_fwd_pkts",
    "flow_rev_pkts",
    "flow_fwd_bytes",
    "flow_rev_bytes",
    "flow_syn_count",
    "flow_ack_count",
    "flow_fin_count",
    "flow_rst_count",
    "flow_psh_count",
    "flow_syn_seen",
    "flow_synack_seen",
    "flow_ack_seen_after_synack",
    "flow_bad_ip_checksum_count",
    "flow_bad_l4_checksum_count",
    "flow_frag_count",
    "flow_low_ttl_count",
    "flow_unusual_dscp_count",
    "flow_unique_sports",
    "flow_unique_dports",
    "flow_protocol_hint",
    "flow_http_seen",
    "flow_http_payload_detected",
    "flow_http_port_fallback",
    "flow_http_detect_source",
    "flow_tls_payload_detected",
    "flow_tls_port_fallback",
    "flow_tls_detect_source",
    "flow_http_method",
    "flow_http_host",
    "flow_http_path",
    "flow_tls_seen",
    "flow_tls_sni",
    "flow_risk_score",
    "flow_risk_level",
    "flow_risk_reason",
]


def packet_tuple(pkt):
    if IP in pkt:
        s, d = pkt[IP].src, pkt[IP].dst
        proto = pkt[IP].proto
    elif IPv6 in pkt:
        s, d = pkt[IPv6].src, pkt[IPv6].dst
        proto = pkt[IPv6].nh
    else:
        return None

    if TCP in pkt:
        sp, dp = pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt:
        sp, dp = pkt[UDP].sport, pkt[UDP].dport
    else:
        return None

    return (s, d, proto, sp, dp)


def canonical_flow_key(pkt):
    t = packet_tuple(pkt)

    if not t:
        return None

    s, d, proto, sp, dp = t

    if (s, sp) <= (d, dp):
        return (s, d, proto, sp, dp)
    else:
        return (d, s, proto, dp, sp)


def packet_direction(pkt, flow_key):
    t = packet_tuple(pkt)

    if not t or not flow_key:
        return None

    s, d, proto, sp, dp = t
    fs, fd, fproto, fsp, fdp = flow_key

    if (s, d, proto, sp, dp) == (fs, fd, fproto, fsp, fdp):
        return "fwd"

    return "rev"


def update_flow_stats(pkt, rawlen):
    global t0
    ts = float(getattr(pkt, "time", time.time()))

    if t0 is None:
        t0 = ts

    key = canonical_flow_key(pkt)

    if not key:
        return

    direction = packet_direction(pkt, key)
    f = flows[key]

    f["pkts"] += 1
    f["bytes"] += rawlen

    if f["first"] is None:
        f["first"] = ts

    if f["last"] is not None:
        iat = ts - f["last"]
        f["iat_sum"] += iat
        f["iat_min"] = iat if f["iat_min"] is None else min(f["iat_min"], iat)
        f["iat_max"] = iat if f["iat_max"] is None else max(f["iat_max"], iat)

    f["last"] = ts

    if direction == "fwd":
        f["fwd_pkts"] += 1
        f["fwd_bytes"] += rawlen
    else:
        f["rev_pkts"] += 1
        f["rev_bytes"] += rawlen

    if TCP in pkt:
        flags = str(pkt[TCP].flags).upper()

        if "S" in flags:
            f["syn_count"] += 1

        if "A" in flags:
            f["ack_count"] += 1

        if "F" in flags:
            f["fin_count"] += 1

        if "R" in flags:
            f["rst_count"] += 1

        if "P" in flags:
            f["psh_count"] += 1

        if "S" in flags and "A" not in flags:
            f["syn_seen"] = 1

        if "S" in flags and "A" in flags:
            f["synack_seen"] = 1

        # final ACK of 3-way handshake
        if "A" in flags and "S" not in flags and f["synack_seen"]:
            f["ack_seen_after_synack"] = 1

    if TCP in pkt:
        f["sport_set"].add(int(pkt[TCP].sport))
        f["dport_set"].add(int(pkt[TCP].dport))
    elif UDP in pkt:
        f["sport_set"].add(int(pkt[UDP].sport))
        f["dport_set"].add(int(pkt[UDP].dport))

    if IP in pkt:
        try:
            if not ipv4_hdr_checksum_ok(pkt[IP]):
                f["bad_ip_checksum_count"] += 1
        except Exception:
            pass

        if int(getattr(pkt[IP].flags, "MF", 0)) == 1 or int(pkt[IP].frag) > 0:
            f["frag_count"] += 1
            f["reasons"].add("flow_fragmented")

        ttl = int(getattr(pkt[IP], "ttl", 0) or 0)

        if 0 < ttl < 20:
            f["low_ttl_count"] += 1
            f["reasons"].add("flow_low_ttl")

        dscp = (int(getattr(pkt[IP], "tos", 0)) >> 2) & 0x3F

        if dscp not in (0, 8, 16, 24, 32, 46):
            f["unusual_dscp_count"] += 1
            f["reasons"].add("flow_unusual_dscp")

    try:
        l4_ok = l4_checksum_ok(pkt)

        if l4_ok is False:
            count_bad = True

            if TCP in pkt:
                flags = str(pkt[TCP].flags).upper()

                # ignore pure ACK packets
                if flags == "A":
                    count_bad = False

            if count_bad:
                f["bad_l4_checksum_count"] += 1
    except Exception:
        pass

    if TCP in pkt:
        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)

        payload = bytes(pkt[Raw].load) if Raw in pkt else b""

        # SSH detection
        ssh_port_match = 22 in (sport, dport)

        ssh_banner = parse_ssh_banner(payload)

        if ssh_banner:
            f["ssh_seen"] = 1
            f["ssh_payload_detected"] = 1
            f["ssh_port_fallback"] = 0
            f["ssh_detect_source"] = "payload"

            if not f["ssh_banner"]:
                f["ssh_banner"] = ssh_banner

        elif ssh_port_match:
            f["ssh_seen"] = 1
            f["ssh_port_fallback"] = 1

            if not f["ssh_detect_source"]:
                f["ssh_detect_source"] = "port"

        # HTTP detection
        http_port_match = sport in (80, 8080, 8000, 8888) or dport in (80, 8080, 8000, 8888)
        
        if not f.get("http_done", 0):

            # only buffer likely HTTP traffic
            if http_port_match and payload:
                f["http_buffer"] += payload

            # limit buffer size
            if len(f["http_buffer"]) > 4096:
                f["http_buffer"] = f["http_buffer"][-4096:]

            # try parse once full header exists
            if b"\r\n\r\n" in f["http_buffer"]:
                method, host, path = parse_http(f["http_buffer"])

                if method and method != "RESP":
                    f["http_seen"] = 1
                    f["http_payload_detected"] = 1
                    f["http_port_fallback"] = 0
                    f["http_detect_source"] = "payload"

                    if not f["http_method"]:
                        f["http_method"] = method
                    if host and not f["http_host"]:
                        f["http_host"] = host
                    if path and not f["http_path"]:
                        f["http_path"] = path

                    f["http_done"] = 1
                    f["http_buffer"] = b""

                elif method == "RESP":
                    f["http_seen"] = 1
                    f["http_payload_detected"] = 1
                    f["http_port_fallback"] = 0
                    f["http_detect_source"] = "payload"

                    if not f["http_method"]:
                        f["http_method"] = "RESP"
                    if not f["http_path"]:
                        f["http_path"] = path or ""

                    f["http_done"] = 1
                    f["http_buffer"] = b""

        # fallback only if no payload detection
        if http_port_match and not f["http_payload_detected"]:
            f["http_seen"] = 1
            f["http_port_fallback"] = 1
            if not f["http_detect_source"]:
                f["http_detect_source"] = "port"

        # TLS detection
        tls_port_match = 443 in (sport, dport)

        if not f["tls_sni_done"]:
            if dport == 443 and payload and len(payload) >= 6 and payload[0] == 0x16 and payload[5] == 0x01:
                if not f["tls_buffer"]:
                    f["tls_buffer"] = payload
                else:
                    f["tls_buffer"] += payload

            elif dport == 443 and payload and f["tls_buffer"]:
                f["tls_buffer"] += payload

            if len(f["tls_buffer"]) >= 5:
                needed = 5 + u16(f["tls_buffer"], 3)

                if len(f["tls_buffer"]) >= needed:
                    candidate = f["tls_buffer"][:needed]
                    sni = parse_tls_sni(candidate)

                    if sni:
                        f["tls_seen"] = 1
                        f["tls_payload_detected"] = 1
                        f["tls_port_fallback"] = 0
                        f["tls_sni"] = sni
                        f["reasons"].add(f"tls_sni:{sni}")
                        f["tls_detect_source"] = "payload"

                    f["tls_sni_done"] = 1
                    f["tls_buffer"] = b""

        # only fallback to port when payload proof was NOT found
        if tls_port_match and not f["tls_payload_detected"]:
            f["tls_seen"] = 1
            f["tls_port_fallback"] = 1
            if not f["tls_detect_source"]:
                f["tls_detect_source"] = "port"

        # SMB protocols
        if 445 in (sport, dport):
            f["smb_seen"] = 1

    elif UDP in pkt:
        sport = int(pkt[UDP].sport)
        dport = int(pkt[UDP].dport)

        if 53 in (sport, dport):
            f["dns_seen"] += 1

def flow_stats_for(pkt):
    key = canonical_flow_key(pkt)

    if not key:
        return None

    f = flows[key]
    pkts = f["pkts"]
    iat_avg = (f["iat_sum"] / (pkts - 1)) if pkts > 1 else 0.0
    duration = (f["last"] - f["first"]) if (f["first"] is not None and f["last"] is not None) else 0.0

    return {
        "pkts": pkts,
        "bytes": f["bytes"],
        "iat_min": f["iat_min"] or 0.0,
        "iat_avg": iat_avg,
        "iat_max": f["iat_max"] or 0.0,
        "duration": duration,
        "fwd_pkts": f["fwd_pkts"],
        "rev_pkts": f["rev_pkts"],
        "fwd_bytes": f["fwd_bytes"],
        "rev_bytes": f["rev_bytes"],
        "syn_count": f["syn_count"],
        "ack_count": f["ack_count"],
        "fin_count": f["fin_count"],
        "rst_count": f["rst_count"],
        "psh_count": f["psh_count"],
        "bad_ip_checksum_count": f["bad_ip_checksum_count"],
        "bad_l4_checksum_count": f["bad_l4_checksum_count"],
        "frag_count": f["frag_count"],
        "low_ttl_count": f["low_ttl_count"],
        "unusual_dscp_count": f["unusual_dscp_count"],
        "unique_sports": len(f["sport_set"]),
        "unique_dports": len(f["dport_set"]),

        "http_seen": f["http_seen"],
        "http_payload_detected": f["http_payload_detected"],
        "http_port_fallback": f["http_port_fallback"],
        "http_detect_source": f["http_detect_source"],
        "http_method": f["http_method"],
        "http_host": f["http_host"],
        "http_path": f["http_path"],

        "tls_seen": f["tls_seen"],
        "tls_payload_detected": f["tls_payload_detected"],
        "tls_port_fallback": f["tls_port_fallback"],
        "tls_detect_source": f["tls_detect_source"],
        "tls_sni": f["tls_sni"],

        "ssh_seen": f["ssh_seen"],
        "ssh_payload_detected": f["ssh_payload_detected"],
        "ssh_port_fallback": f["ssh_port_fallback"],
        "ssh_detect_source": f["ssh_detect_source"],
        "ssh_banner": f["ssh_banner"],
        
        "dns_seen": f["dns_seen"],
        "smb_seen": f["smb_seen"],
        "syn_seen": f["syn_seen"],
        "synack_seen": f["synack_seen"],
        "ack_seen_after_synack": f["ack_seen_after_synack"],
        "reasons": ",".join(sorted(f["reasons"])) if f["reasons"] else "flow_normal"
    }


def time_local(ts, t0, fmt):
    rel = ts - (t0 or ts)
    lt = time.localtime(ts)
    ms = int((ts - int(ts)) * 1000)
    ts_human = time.strftime("%Y-%m-%d %H:%M:%S", lt) + f".{ms:03d}"

    if fmt == 'log':
        return ts_human, rel, ts
    elif fmt == 'csv':
        return ts_human


def update_mac_ip_consistency(eth_src, ip_src, ts):
    if not eth_src or not ip_src:
        return {
            "src_ip_mac_consistent": None,
            "src_ip_mac_seen_mac_count": 0,
            "src_mac_ip_seen_ip_count": 0,
            "src_mac_ip_spoof_suspect": 0,
        }

    ip_src = str(ip_src).strip()
    eth_src = str(eth_src).lower().strip()

    ip_to_macs[ip_src].add(eth_src)
    mac_to_ips[eth_src].add(ip_src)

    pair_key = (ip_src, eth_src)

    if pair_key not in ip_mac_first_seen:
        ip_mac_first_seen[pair_key] = ts
        
    ip_mac_last_seen[pair_key] = ts

    mac_count_for_ip = len(ip_to_macs[ip_src])
    ip_count_for_mac = len(mac_to_ips[eth_src])

    if mac_count_for_ip <= 1:
        consistent = 1
    else:
        consistent = 0

    spoof_suspect = 0

    if mac_count_for_ip > 1:
        spoof_suspect = 1
    elif ip_count_for_mac > 5:
        spoof_suspect = 1

    return {
        "src_ip_mac_consistent": consistent,
        "src_ip_mac_seen_mac_count": mac_count_for_ip,
        "src_mac_ip_seen_ip_count": ip_count_for_mac,
        "src_mac_ip_spoof_suspect": spoof_suspect,
    }


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

    is_ip_packet = 0

    if IP in pkt:
        ip = pkt[IP]
        ip_ver = int(getattr(ip, "version", 4))
        ip_tos = int(getattr(ip, "tos", 0))
        ip_src = ip.src
        ip_dst = ip.dst
        is_ip_packet = 1
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
        is_ip_packet = 1
        ttl_hlim = ip.hlim
        dscp = (getattr(ip,"tc",0)>>2)&0x3F
        ecn = getattr(ip,"tc",0)&0x3
        ip_df = ip_mf = ip_frag_off = None
        ip4_ok = None

    # MAC-IP consistency
    mac_ip_info = {
        "src_ip_mac_consistent": None,
        "src_ip_mac_seen_mac_count": 0,
        "src_mac_ip_seen_ip_count": 0,
        "src_mac_ip_spoof_suspect": 0,
    }

    if is_ip_packet and ip_src:
        mac_ip_info = update_mac_ip_consistency(
            eth.src if eth else None,
            ip_src,
            ts
        )

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
    flow = flow_stats_for(pkt)

    if flow is None:
        flow = {
            "pkts": 0, 
            "bytes": 0, 
            "iat_min": 0.0, 
            "iat_avg": 0.0, 
            "iat_max": 0.0,
            "duration": 0.0, 
            "fwd_pkts": 0, 
            "rev_pkts": 0, 
            "fwd_bytes": 0, 
            "rev_bytes": 0,
            "syn_count": 0, 
            "ack_count": 0, 
            "fin_count": 0, 
            "rst_count": 0, 
            "psh_count": 0,
            "bad_ip_checksum_count": 0, 
            "bad_l4_checksum_count": 0, 
            "frag_count": 0,
            "low_ttl_count": 0, 
            "unusual_dscp_count": 0,
            "unique_sports": 0, 
            "unique_dports": 0,

            "http_seen": 0, 
            "http_payload_detected": 0,
            "http_port_fallback": 0,
            "http_detect_source": "",
            "http_method": "",
            "http_host": "",
            "http_path": "",
            "http_buffer": b"",
            "http_done": 0,

            "tls_seen": 0, 
            "tls_sni": "",
            "tls_payload_detected": 0,
            "tls_port_fallback": 0,
            "tls_detect_source": "",

            "ssh_seen": 0, 
            "ssh_payload_detected": 0,
            "ssh_port_fallback": 0,
            "ssh_detect_source": "",
            "ssh_banner": "",

            "dns_seen": 0, 
            "smb_seen": 0,
            "syn_seen": 0,
            "synack_seen": 0,
            "ack_seen_after_synack": 0,
            "reasons": "flow_normal"
        }

    flow_protocol_hint = detect_flow_protocol_hint(flow)
    flow_risk_score, flow_risk_level, flow_risk_reason = score_flow_behavior(flow)
    
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

    # MAC-IP
        "src_ip_mac_consistent": mac_ip_info["src_ip_mac_consistent"],
        "src_ip_mac_seen_mac_count": mac_ip_info["src_ip_mac_seen_mac_count"],
        "src_mac_ip_seen_ip_count": mac_ip_info["src_mac_ip_seen_ip_count"],
        "src_mac_ip_spoof_suspect": mac_ip_info["src_mac_ip_spoof_suspect"],

    # L4
        "l4_proto": l4_proto,

        "sport": sport, 
        "dport": dport, 

        "tcp_flags": tcp_flags,
        "tcp_win": tcp_win, 
        "tcp_hdr_len": tcp_hlen, 

        "l4_checksum_ok": l4_ok,

    # Flow Stats
        "flow_pkts": flow["pkts"],
        "flow_bytes": flow["bytes"],
        "flow_iat_min": flow["iat_min"],
        "flow_iat_avg": flow["iat_avg"],
        "flow_iat_max": flow["iat_max"],

        "flow_duration": flow["duration"],
        "flow_fwd_pkts": flow["fwd_pkts"],
        "flow_rev_pkts": flow["rev_pkts"],
        "flow_fwd_bytes": flow["fwd_bytes"],
        "flow_rev_bytes": flow["rev_bytes"],
        "flow_syn_count": flow["syn_count"],
        "flow_ack_count": flow["ack_count"],
        "flow_fin_count": flow["fin_count"],
        "flow_rst_count": flow["rst_count"],
        "flow_psh_count": flow["psh_count"],
        "flow_syn_seen": flow["syn_seen"],
        "flow_synack_seen": flow["synack_seen"],
        "flow_ack_seen_after_synack": flow["ack_seen_after_synack"],
        "flow_bad_ip_checksum_count": flow["bad_ip_checksum_count"],
        "flow_bad_l4_checksum_count": flow["bad_l4_checksum_count"],
        "flow_frag_count": flow["frag_count"],
        "flow_low_ttl_count": flow["low_ttl_count"],
        "flow_unusual_dscp_count": flow["unusual_dscp_count"],
        "flow_unique_sports": flow["unique_sports"],
        "flow_unique_dports": flow["unique_dports"],
        "flow_protocol_hint": flow_protocol_hint,

        "flow_http_seen": flow["http_seen"],
        "flow_http_payload_detected": flow["http_payload_detected"],
        "flow_http_port_fallback": flow["http_port_fallback"],
        "flow_http_detect_source": flow["http_detect_source"],
        "flow_http_method": flow["http_method"],
        "flow_http_host": flow["http_host"],
        "flow_http_path": flow["http_path"],

        "flow_tls_seen": flow["tls_seen"],
        "flow_tls_payload_detected": flow["tls_payload_detected"],
        "flow_tls_port_fallback": flow["tls_port_fallback"],
        "flow_tls_detect_source": flow["tls_detect_source"],
        "flow_tls_sni": flow["tls_sni"],

        "flow_ssh_seen": flow["ssh_seen"],
        "flow_ssh_payload_detected": flow["ssh_payload_detected"],
        "flow_ssh_port_fallback": flow["ssh_port_fallback"],
        "flow_ssh_detect_source": flow["ssh_detect_source"],
        "flow_ssh_banner": flow["ssh_banner"],

        "flow_risk_score": flow_risk_score,
        "flow_risk_level": flow_risk_level,
        "flow_risk_reason": flow_risk_reason,
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


def detect_flow_protocol_hint(flow):

    # strongest = payload-confirmed
    if flow.get("http_payload_detected", 0):
        return "http"
    
    if flow.get("tls_sni"):
        return "tls"

    if flow.get("tls_payload_detected", 0):
        return "tls"

    # then port fallback
    if flow.get("http_port_fallback", 0):
        return "http"

    if flow.get("tls_port_fallback", 0):
        return "tls"

    if flow.get("ssh_payload_detected", 0):
        return "ssh"

    if flow.get("ssh_seen", 0):
        return "ssh"

    if flow.get("smb_seen", 0):
        return "smb"

    if flow.get("dns_seen", 0):
        return "dns"

    return "unknown"


def score_flow_behavior(flow):
    score = 0
    reasons = []

    if flow["bad_ip_checksum_count"] > 0:
        score += 25
        reasons.append("flow_bad_ip_checksum")

    # 1 = ignored , 2 = very weak signal
    if flow["bad_l4_checksum_count"] >= 3:
        score += 10
        reasons.append("flow_bad_l4_checksum")
    elif flow["bad_l4_checksum_count"] == 2:
        score += 5

    if flow["frag_count"] > 0:
        score += 10
        reasons.append("flow_fragmented")

    if flow["low_ttl_count"] > 0:
        score += 8
        reasons.append("flow_low_ttl")

    if flow["unusual_dscp_count"] > 0:
        score += 5
        reasons.append("flow_unusual_dscp")

    # SYN without ACK
    if flow["syn_count"] > 3 and flow["ack_count"] == 0:
        score += 20
        reasons.append("syn_without_ack")

    # RST-heavy flow
    if flow["rst_count"] > 2:
        score += 10
        reasons.append("many_rst")

    # Incomplete handshake
    if flow.get("syn_seen", 0) == 1:
        if flow.get("synack_seen", 0) == 0:
            score += 15
            reasons.append("incomplete_handshake_no_synack")
        elif flow.get("ack_seen_after_synack", 0) == 0:
            score += 12
            reasons.append("incomplete_handshake_no_final_ack")

    # Direction imbalance
    fwd = int(flow.get("fwd_pkts", 0) or 0)
    rev = int(flow.get("rev_pkts", 0) or 0)

    if fwd >= 6 and rev == 0:
        score += 15
        reasons.append("direction_imbalance_no_response")
    elif fwd >= 10 and rev > 0 and fwd >= (rev * 4):
        score += 10
        reasons.append("direction_imbalance")

    if flow["unique_dports"] > 5:
        score += 15
        reasons.append("multi_port_targeting")

    if flow["duration"] < 1.0 and flow["pkts"] > 10:
        score += 10
        reasons.append("short_burst_flow")

    score = max(0, min(100, score))

    if score >= 70:
        level = "high"
    elif score >= 40:
        level = "medium"
    else:
        level = "low"

    return score, level, ",".join(reasons) if reasons else "flow_normal"


def heuristic_score_reason(row):
    reasons = []

    if row.get("ipv4_checksum_ok") == 0:
        reasons.append("ipv4_checksum_bad")

    if row.get("l4_checksum_ok") == 0:
        flags = str(row.get("tcp_flags") or "").upper()

        if flags != "A":
            reasons.append("l4_checksum_bad")

    if (row.get("ip_flags_mf") == 1) or ((row.get("ip_frag_off") or 0) > 0):
        reasons.append("fragmented_packet")

    if row.get("src_ip_mac_consistent") == 0:
        reasons.append("src_ip_mac_inconsistent")

    ttl = row.get("ttl_hlim") or 0

    if 0 < ttl < 20:
        reasons.append("low_ttl")

    flags = (row.get("tcp_flags") or "").upper()

    if "SF" in flags or flags == "":
        reasons.append("suspicious_tcp_flags")

    dscp = row.get("dscp") or 0

    if dscp not in (0, 8, 16, 24, 32, 46):
        reasons.append("unusual_dscp")

    dp = row.get("dport")

    if dp in (22, 80, 443, 445):
        reasons.append("focus_port")
    
    if int(row.get("flow_risk_score", 0) or 0) >= 40:
        reasons.append("flow_behavior_suspicious")

    if int(row.get("flow_unique_dports", 0) or 0) > 5:
        reasons.append("multi_port_targeting")

    if int(row.get("flow_syn_count", 0) or 0) > 3 and int(row.get("flow_ack_count", 0) or 0) == 0:
        reasons.append("syn_without_ack")

    if not reasons:
        reasons.append("heuristic_normal")

    return ",".join(reasons)


def _heuristic_ip_fraud_score(row):
    score = 0

    # Header integrity
    if row.get("ipv4_checksum_ok") == 0:
        score += 35

    if row.get("l4_checksum_ok") == 0:
        score += 25

    # Fragmentation/flags
    if (row.get("ip_flags_mf") == 1) or (row.get("ip_frag_off", 0) > 0):
        score += 10

    if row.get("src_ip_mac_consistent") == 0:
        score += 20
    
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

    # flow-based
    flow_score = int(row.get("flow_risk_score", 0) or 0)
    score += min(25, flow_score // 2)

    if int(row.get("flow_unique_dports", 0) or 0) > 5:
        score += 10

    if int(row.get("flow_syn_count", 0) or 0) > 3 and int(row.get("flow_ack_count", 0) or 0) == 0:
        score += 10

    return max(0, min(100, score))


def risk_from_ip_fraud_score(ip_fraud_score):
    ip_fraud_score = max(0, min(100, int(ip_fraud_score)))

    if ip_fraud_score >= 90:
        return "very high"
    elif ip_fraud_score >= 70:
        return "high"
    elif ip_fraud_score >= 40:
        return "medium"
    else:
        return "low"


def is_public_routable_ip(value):
    try:
        ip_obj = ipaddress.ip_address(str(value))
    except Exception:
        return False

    return not (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    )


def scamalytics_lookup(ip_addr, api_user, api_key, timeout=SCAMALYTICS_TIMEOUT):
    if not api_user or not api_key:
        return None, "api_missing_heuristic"

    if not ip_addr:
        return None, "no_ip_heuristic"

    ip_addr = str(ip_addr).strip()

    if not is_public_routable_ip(ip_addr):
        return None, "private_ip_heuristic"

    cache_key = (ip_addr, api_user)

    if cache_key in scamalytics_cache:
        return scamalytics_cache[cache_key], "public_ip_scamalytics"

    query = urlencode({"key": api_key, "ip": ip_addr})
    url = f"{SCAMALYTICS_BASE_URL}/{api_user}/?{query}"
    req = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "fyp1-scoring/1.0"
        }
    )

    try:
        with urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
    except Exception:
        return None, "api_failed_heuristic"

    scam = payload.get("scamalytics", {}) or {}

    try:
        score = int(float(scam.get("scamalytics_score", 0)))
    except Exception:
        score = None

    risk = scam.get("scamalytics_risk")

    result = {
        "ip_fraud_score": score,
        "risk_level": str(risk).strip().lower() if risk is not None else None,
        "source": "scamalytics",
        "reason": str(risk).strip().lower() if risk is not None else "scamalytics_unknown",
        "raw": payload,
    }

    scamalytics_cache[cache_key] = result

    return result, result["reason"]


def score_row(row, api_user, api_key):
    for candidate_ip in (row.get("ip_src"), row.get("ip_dst")):
        lookup, reason = scamalytics_lookup(candidate_ip, api_user, api_key)

        if lookup and lookup.get("ip_fraud_score") is not None:
            return (
                lookup["ip_fraud_score"], 
                (lookup.get("risk_level") or risk_from_ip_fraud_score(lookup["ip_fraud_score"])), 
                "scamalytics", 
                reason
            )

    heuristic_score = _heuristic_ip_fraud_score(row)
    heuristic_reason = heuristic_score_reason(row)

    return (
        heuristic_score,
        risk_from_ip_fraud_score(heuristic_score),
        "heuristic",
        heuristic_reason
    )


def score_packet(args):
    scores_out = "scores.csv"

    try:
        df = pd.read_csv(args.scores_csv)

        num_cols = ["ipv4_checksum_ok", "l4_checksum_ok", "ip_flags_mf", "ip_frag_off", "ttl_hlim", "dscp", "dport"]
        
        for c in num_cols:
            df[c] = pd.to_numeric(df.get(c), errors="coerce").fillna(0).astype(int)

        df["tcp_flags"] = df.get("tcp_flags").fillna("").astype(str)

        ip_fraud_scores = []
        risk_levels = []
        score_sources = []
        score_reasons = []

        api_user = args.scamalytics_user or SCAMALYTICS_USER
        api_key = args.scamalytics_key or SCAMALYTICS_KEY

        for _, r in df.iterrows():
            s, rs, source, reason = score_row(r, api_user=api_user, api_key=api_key)
            ip_fraud_scores.append(s)
            risk_levels.append(rs)
            score_sources.append(source)
            score_reasons.append(reason)

        df["ip_fraud_score"] = ip_fraud_scores
        df["ip_fraud_score_display"] = df["ip_fraud_score"].astype(str) + "/100"
        df["risk_level"] = risk_levels
        df["risk_score_source"] = score_sources
        df["risk_score_reason"] = score_reasons

        # add score columns to the end in exact order
        final_cols = list(df.columns)

        for c in (
            "ip_fraud_score", 
            "ip_fraud_score_display", 
            "risk_level",
            "risk_score_source", 
            "risk_score_reason"
        ):
            final_cols.remove(c)

        final_cols = final_cols + [
            "ip_fraud_score", 
            "ip_fraud_score_display", 
            "risk_level",
            "risk_score_source", 
            "risk_score_reason"
            ]

        df.to_csv(scores_out, index=False, columns=final_cols)
        
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
        df = pd.read_csv(input_csv)
        df = expand_tcp_flags(df)

        # Ensure all required features exist
        for f in features:
            if f not in df.columns:
                df[f] = 0

        # Align feature matrix
        X = df[features].astype(np.float32)

        proba = model.predict_proba(X)
        confidences = proba.max(axis=1)
        
        df["label"] = [
            apply_confidence_policy(c) for c in confidences
        ]
        
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
    elif conf >= 0.80:
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


def export_flows_csv(path="flows.csv"):
    records = []

    for key, f in flows.items():
        s, d, proto, sp, dp = key
        pkts = f["pkts"]

        duration = (f["last"] - f["first"]) if (f["first"] is not None and f["last"] is not None) else 0.0
        iat_avg = (f["iat_sum"] / (pkts - 1)) if pkts > 1 else 0.0

        # scoring view:
        flow_stats = {
            "pkts": pkts,
            "bytes": f["bytes"],
            "iat_min": f["iat_min"] or 0.0,
            "iat_avg": iat_avg,
            "iat_max": f["iat_max"] or 0.0,
            "duration": duration,
            "fwd_pkts": f["fwd_pkts"],
            "rev_pkts": f["rev_pkts"],
            "fwd_bytes": f["fwd_bytes"],
            "rev_bytes": f["rev_bytes"],
            "syn_count": f["syn_count"],
            "ack_count": f["ack_count"],
            "fin_count": f["fin_count"],
            "rst_count": f["rst_count"],
            "psh_count": f["psh_count"],
            "bad_ip_checksum_count": f["bad_ip_checksum_count"],
            "bad_l4_checksum_count": f["bad_l4_checksum_count"],
            "frag_count": f["frag_count"],
            "low_ttl_count": f["low_ttl_count"],
            "unusual_dscp_count": f["unusual_dscp_count"],
            "unique_sports": len(f["sport_set"]),
            "unique_dports": len(f["dport_set"]),

            "http_seen": f["http_seen"],
            "http_payload_detected": f["http_payload_detected"],
            "http_port_fallback": f["http_port_fallback"],
            "http_detect_source": f["http_detect_source"],
            "http_method": f["http_method"],
            "http_host": f["http_host"],
            "http_path": f["http_path"],

            "tls_seen": f["tls_seen"],
            "tls_payload_detected": f["tls_payload_detected"],
            "tls_port_fallback": f["tls_port_fallback"],
            "tls_detect_source": f["tls_detect_source"],
            "tls_sni": f["tls_sni"],

            "ssh_seen": f["ssh_seen"],
            "ssh_payload_detected": f["ssh_payload_detected"],
            "ssh_port_fallback": f["ssh_port_fallback"],
            "ssh_detect_source": f["ssh_detect_source"],
            "ssh_banner": f["ssh_banner"],

            "dns_seen": f["dns_seen"],
            "smb_seen": f["smb_seen"],

            "syn_seen": f["syn_seen"],
            "synack_seen": f["synack_seen"],
            "ack_seen_after_synack": f["ack_seen_after_synack"],
            "reasons": ",".join(sorted(f["reasons"])) if f["reasons"] else "flow_normal",
        }

        proto_hint = detect_flow_protocol_hint(flow_stats)
        risk_score, risk_level, risk_reason = score_flow_behavior(flow_stats)

        # export row
        row = {
            "flow_src_ip": s,
            "flow_dst_ip": d,
            "flow_proto": proto,
            "flow_src_port": sp,
            "flow_dst_port": dp,

            "flow_pkts": flow_stats["pkts"],
            "flow_bytes": flow_stats["bytes"],
            "flow_duration": flow_stats["duration"],
            "flow_iat_min": flow_stats["iat_min"],
            "flow_iat_avg": flow_stats["iat_avg"],
            "flow_iat_max": flow_stats["iat_max"],

            "flow_fwd_pkts": flow_stats["fwd_pkts"],
            "flow_rev_pkts": flow_stats["rev_pkts"],
            "flow_fwd_bytes": flow_stats["fwd_bytes"],
            "flow_rev_bytes": flow_stats["rev_bytes"],

            "flow_syn_count": flow_stats["syn_count"],
            "flow_ack_count": flow_stats["ack_count"],
            "flow_fin_count": flow_stats["fin_count"],
            "flow_rst_count": flow_stats["rst_count"],
            "flow_psh_count": flow_stats["psh_count"],

            "flow_bad_ip_checksum_count": flow_stats["bad_ip_checksum_count"],
            "flow_bad_l4_checksum_count": flow_stats["bad_l4_checksum_count"],
            "flow_frag_count": flow_stats["frag_count"],
            "flow_low_ttl_count": flow_stats["low_ttl_count"],
            "flow_unusual_dscp_count": flow_stats["unusual_dscp_count"],

            "flow_unique_sports": flow_stats["unique_sports"],
            "flow_unique_dports": flow_stats["unique_dports"],

            "flow_http_seen": flow_stats["http_seen"],
            "flow_http_payload_detected": f["http_payload_detected"],
            "flow_http_port_fallback": f["http_port_fallback"],
            "flow_http_detect_source": f["http_detect_source"],
            "flow_http_method": flow_stats["http_method"],
            "flow_http_host": flow_stats["http_host"],
            "flow_http_path": flow_stats["http_path"],

            "flow_tls_seen": flow_stats["tls_seen"],
            "flow_tls_payload_detected": f["tls_payload_detected"],
            "flow_tls_port_fallback": f["tls_port_fallback"],
            "flow_tls_detect_source": f["tls_detect_source"],
            "flow_tls_sni": flow_stats["tls_sni"],

            "flow_ssh_seen": flow_stats["ssh_seen"],
            "flow_ssh_payload_detected": f["ssh_payload_detected"],
            "flow_ssh_port_fallback": f["ssh_port_fallback"],
            "flow_ssh_detect_source": f["ssh_detect_source"],
            "flow_ssh_banner": f["ssh_banner"],

            "flow_dns_seen": flow_stats["dns_seen"],
            "flow_smb_seen": flow_stats["smb_seen"],

            "flow_syn_seen": flow_stats["syn_seen"],
            "flow_synack_seen": flow_stats["synack_seen"],
            "flow_ack_seen_after_synack": flow_stats["ack_seen_after_synack"],
            
            "flow_protocol_hint": proto_hint,
            "flow_risk_score": risk_score,
            "flow_risk_level": risk_level,
            "flow_risk_reason": risk_reason,
        }

        records.append(row)

    if records:
        pd.DataFrame(records).to_csv(path, index=False)


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
    ap.add_argument("--scamalytics-user", default=None)
    ap.add_argument("--scamalytics-key", default=None)

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
    for p in (args.outfile, args.log, args.features_csv, args.features_parquet, 'flows.csv', 'scores.csv'):
        try:
            if p and os.path.exists(p):
                os.remove(p)
        except Exception:
            pass
    
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

        export_flows_csv("flows.csv")
        print("Flows written          : flows.csv")

        if args.features_parquet:
            print(f"Parquet written       : {args.features_parquet}")

        args.scores_csv = run_ml_detection(
            model_path="./random_forest/rf_model.joblib",
            input_csv="features.csv",
            output_csv="scores.csv"
        )

        print("\nScoring packets...\n")

        score_packet(args)


if __name__ == "__main__":
    import struct
    main()