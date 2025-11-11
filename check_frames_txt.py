# check_frames_txt.py
# Usage:
#   python check_frames_txt.py D:\test\live.txt --out D:\test\result.txt
import sys, re, binascii, argparse
from typing import Optional, Tuple

FRAME_SPLIT = re.compile(r"^\s*=== Frame (\d+) ===\s*$")
LEN_LINE    = re.compile(r"^FrameBytes\((\d+)B\):\s*(.+)$")

def parse_hex(s: str) -> bytes:
    return bytes.fromhex(s.strip())

def u16(b: bytes, off: int) -> int:
    return (b[off] << 8) | b[off+1]

def check_ipv4(pay: bytes) -> Tuple[bool, str, Optional[int], Optional[int]]:
    if len(pay) < 20: return False, "IPv4: payload < 20", None, None
    ver_ihl = pay[0]; ver, ihl = ver_ihl >> 4, ver_ihl & 0x0F
    if ver != 4: return False, f"IPv4: version={ver}", None, None
    ip_hlen = ihl * 4
    if ip_hlen < 20 or len(pay) < ip_hlen: return False, f"IPv4: bad IHL={ihl}", None, None
    totlen = u16(pay, 2); proto = pay[9]
    if totlen != len(pay): return False, f"IPv4: total_length {totlen} != {len(pay)}", proto, ip_hlen
    return True, "ok", proto, ip_hlen

def check_ipv6(pay: bytes) -> Tuple[bool, str, Optional[int], Optional[int]]:
    if len(pay) < 40: return False, "IPv6: payload < 40", None, None
    if (pay[0] >> 4) != 6: return False, f"IPv6: version={(pay[0]>>4)}", None, None
    payload_len = u16(pay, 4); nexthdr = pay[6]; total = 40 + payload_len
    if total != len(pay): return False, f"IPv6: total {total} != {len(pay)}", nexthdr, 40
    return True, "ok", nexthdr, 40

def check_udp(seg: bytes) -> Tuple[bool, str]:
    if len(seg) < 8: return False, "UDP: segment < 8"
    udplen = u16(seg, 4)
    if udplen != len(seg): return False, f"UDP: length {udplen} != {len(seg)}"
    return True, "ok"

def check_tcp(seg: bytes) -> Tuple[bool, str]:
    if len(seg) < 20: return False, "TCP: segment < 20"
    data_offset = (seg[12] >> 4) * 4
    if data_offset < 20 or data_offset > len(seg): return False, f"TCP: bad header length {data_offset}"
    return True, "ok"

def analyze_frame(raw: bytes) -> Tuple[bool, str]:
    if len(raw) < 14: return False, "Ethernet: frame < 14"
    eth_type = u16(raw, 12); offset = 14
    # VLAN(s)
    if eth_type == 0x8100:
        if len(raw) < 18: return False, "802.1Q: frame < 18"
        eth_type = u16(raw, 16); offset = 18
        while eth_type == 0x8100:
            if len(raw) < offset + 4: return False, "QinQ: truncated"
            eth_type = u16(raw, offset + 2); offset += 4
    pay = raw[offset:]
    if eth_type == 0x0800:  # IPv4
        ok, msg, proto, ip_hlen = check_ipv4(pay)
        if not ok: return False, msg
        l4 = pay[ip_hlen:]
        if proto == 17:
            ok2, msg2 = check_udp(l4);  return (ok2, msg2 if not ok2 else "ok IPv4/UDP")
        if proto == 6:
            ok2, msg2 = check_tcp(l4);  return (ok2, msg2 if not ok2 else "ok IPv4/TCP")
        return True, f"ok IPv4/nh={proto}"
    if eth_type == 0x86DD:  # IPv6
        ok, msg, nh, ip_hlen = check_ipv6(pay)
        if not ok: return False, msg
        l4 = pay[ip_hlen:]
        if nh == 17:
            ok2, msg2 = check_udp(l4);  return (ok2, msg2 if not ok2 else "ok IPv6/UDP")
        if nh == 6:
            ok2, msg2 = check_tcp(l4);  return (ok2, msg2 if not ok2 else "ok IPv6/TCP")
        return True, f"ok IPv6/nh={nh}"
    return True, f"ok ethertype 0x{eth_type:04x}"

def iter_frames_from_txt(path: str):
    cur_n = None; decl = None
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = FRAME_SPLIT.match(line)
            if m:
                if cur_n is not None and decl is not None:
                    yield cur_n, decl
                cur_n = int(m.group(1)); decl = None
                continue
            m2 = LEN_LINE.match(line.strip())
            if m2:
                decl = (int(m2.group(1)), m2.group(2).strip())
        if cur_n is not None and decl is not None:
            yield cur_n, decl

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("txt", nargs="?", default="D:\\test\\capture_live.txt", help="path to capture_live.txt")
    ap.add_argument("--out", default="result.txt", help="output report file")
    args = ap.parse_args()

    total = good = bad = 0
    lines_out = []
    for n, (decl_len, hexstr) in iter_frames_from_txt(args.txt):
        total += 1
        try:
            raw = parse_hex(hexstr)
        except binascii.Error as e:
            bad += 1
            lines_out.append(f"[Frame {n}] ERROR: hex parse failed: {e}")
            continue
        if len(raw) != decl_len:
            bad += 1
            lines_out.append(f"[Frame {n}] ERROR: declared {decl_len}B != actual {len(raw)}B")
            continue
        ok, msg = analyze_frame(raw)
        if ok:
            good += 1
            lines_out.append(f"[Frame {n}] OK: {msg}")
        else:
            bad += 1
            lines_out.append(f"[Frame {n}] ERROR: {msg}")

    lines_out.append(f"\nSummary: total={total} ok={good} errors={bad}")
    with open(args.out, "w", encoding="utf-8") as fo:
        fo.write("\n".join(lines_out))

    # also print a one-line summary
    print(f"written: {args.out}  total={total} ok={good} errors={bad}")
    if bad:
        sys.exit(2)

if __name__ == "__main__":
    main()
