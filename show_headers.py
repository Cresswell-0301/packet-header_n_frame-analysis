import sys
from scapy.all import (
    PcapReader,  # streams large pcaps
    Ether, Dot1Q, CookedLinux, Raw,
    RadioTap, Dot11,
    ARP, IP, IPv6,
    TCP, UDP, ICMP, ICMPv6EchoRequest, ICMPv6EchoReply
)
from scapy.packet import NoPayload

pcap = sys.argv[1] if len(sys.argv) > 1 else "capture.pcap"

def safe_get(pkt, layer):
    try:
        return pkt[layer]
    except Exception:
        return None

def pkt_time(pkt):
    try:
        return pkt.time
    except Exception:
        return None

def print_if_present(tag, value):
    if value is not None:
        print(f"  {tag}: {value}")

with PcapReader(pcap) as r:
    for i, p in enumerate(r, 1):
        print(f"\n=== Frame {i} ===")
        print_if_present("timestamp", pkt_time(p))
        print_if_present("frame_len", len(p) if hasattr(p, "__len__") else None)

        # Radiotap / 802.11 (Wi-Fi)
        rt = safe_get(p, RadioTap)
        if rt:
            print("L2: Radiotap")
            print_if_present("  dbm_antsignal", getattr(rt, "dBm_AntSignal", None))
            print_if_present("  rate", getattr(rt, "Rate", None))
            print_if_present("  channel_freq", getattr(rt, "ChannelFrequency", None))
        d11 = safe_get(p, Dot11)
        if d11:
            print("L2: 802.11")
            print_if_present("  type_subtype", getattr(d11, "type", None) if d11 else None)
            print_if_present("  addr1(DA)", getattr(d11, "addr1", None))
            print_if_present("  addr2(SA)", getattr(d11, "addr2", None))
            print_if_present("  addr3(BSSID)", getattr(d11, "addr3", None))

        # Ethernet / SLL
        eth = safe_get(p, Ether)
        if eth:
            print("L2: Ethernet")
            print_if_present("  src", eth.src)
            print_if_present("  dst", eth.dst)
            print_if_present("  type", hex(eth.type))
            # VLAN stacking
            vlan = safe_get(p, Dot1Q)
            while vlan:
                print(f"  VLAN: id={vlan.vlan} pri={vlan.prio} cfi={vlan.id}")
                vlan = vlan.payload if isinstance(vlan.payload, Dot1Q) else None
        sll = safe_get(p, CookedLinux)
        if sll and not eth and not d11:
            print("L2: Linux SLL")
            print_if_present("  src", getattr(sll, "src", None))
            print_if_present("  type", hex(getattr(sll, "proto", 0)))

        # ARP
        arp = safe_get(p, ARP)
        if arp:
            print("L3: ARP")
            print_if_present("  op", arp.op)
            print_if_present("  hwsrc", arp.hwsrc)
            print_if_present("  hwdst", arp.hwdst)
            print_if_present("  psrc", arp.psrc)
            print_if_present("  pdst", arp.pdst)

        # IPv4
        ip4 = safe_get(p, IP)
        if ip4:
            print("L3: IPv4")
            print_if_present("  src", ip4.src)
            print_if_present("  dst", ip4.dst)
            print_if_present("  proto", ip4.proto)
            print_if_present("  ttl", ip4.ttl)
            print_if_present("  id", ip4.id)
            print_if_present("  flags", ip4.flags)
            print_if_present("  frag", ip4.frag)

        # IPv6
        ip6 = safe_get(p, IPv6)
        if ip6:
            print("L3: IPv6")
            print_if_present("  src", ip6.src)
            print_if_present("  dst", ip6.dst)
            print_if_present("  nh", ip6.nh)
            print_if_present("  hlim", ip6.hlim)

        # TCP
        tcp = safe_get(p, TCP)
        if tcp:
            print("L4: TCP")
            print_if_present("  sport", tcp.sport)
            print_if_present("  dport", tcp.dport)
            print_if_present("  seq", tcp.seq)
            print_if_present("  ack", tcp.ack)
            print_if_present("  flags", tcp.flags)
            print_if_present("  window", tcp.window)

        # UDP
        udp = safe_get(p, UDP)
        if udp:
            print("L4: UDP")
            print_if_present("  sport", udp.sport)
            print_if_present("  dport", udp.dport)
            print_if_present("  len", udp.len)

        # ICMPv4
        icmp = safe_get(p, ICMP)
        if icmp:
            print("L4: ICMP")
            print_if_present("  type", icmp.type)
            print_if_present("  code", icmp.code)

        # ICMPv6 echo quick check
        if safe_get(p, ICMPv6EchoRequest) or safe_get(p, ICMPv6EchoReply):
            print("L4: ICMPv6 Echo")

        # Show first bytes of payload after headers
        payload = p.lastlayer()
        if not isinstance(payload, NoPayload) and not isinstance(payload, Raw):
            payload = payload.payload
        if isinstance(payload, Raw) and payload.load:
            data = bytes(payload.load)
            preview = data[:32].hex(" ")
            print(f"Payload_preview(32B): {preview}")
