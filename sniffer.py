

#!/usr/bin/env python3
"""CodeAlpha Cyber Security Internship - Task 1: Basic Network Sniffer."""

import argparse
from collections import Counter
from datetime import datetime

from scapy.all import sniff, wrpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from scapy.packet import Raw

IP_PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}

captured = []
stats = Counter()


def payload_preview(pkt, limit=60):
    if Raw in pkt:
        data = bytes(pkt[Raw].load)[:limit]
        return "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return ""


def describe(pkt):
    ts = datetime.now().strftime("%H:%M:%S")

    if IP in pkt:
        src, dst = pkt[IP].src, pkt[IP].dst
        proto = IP_PROTOCOLS.get(pkt[IP].proto, f"IP-{pkt[IP].proto}")
    elif IPv6 in pkt:
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
        proto = IP_PROTOCOLS.get(pkt[IPv6].nh, f"IPv6-{pkt[IPv6].nh}")
    elif ARP in pkt:
        stats["ARP"] += 1
        return f"[{ts}] ARP {pkt[ARP].psrc} -> {pkt[ARP].pdst} (op={pkt[ARP].op})"
    else:
        return None

    stats[proto] += 1
    extra = ""

    if TCP in pkt:
        extra = f"{pkt[TCP].sport} -> {pkt[TCP].dport} flags={pkt[TCP].flags}"
    elif UDP in pkt:
        extra = f"{pkt[UDP].sport} -> {pkt[UDP].dport}"
    elif ICMP in pkt:
        extra = f"type={pkt[ICMP].type} code={pkt[ICMP].code}"

    line = f"[{ts}] {proto:<5} {src} -> {dst} {extra} len={len(pkt)}"
    preview = payload_preview(pkt)
    if preview:
        line += f"\n           payload: {preview}"
    return line


def handle(pkt):
    captured.append(pkt)
    line = describe(pkt)
    if line:
        print(line)


def main():
    parser = argparse.ArgumentParser(description="Basic network sniffer (Scapy)")
    parser.add_argument("-i", "--iface", help="Network interface")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Packets to capture; 0 means until stopped")
    parser.add_argument("-f", "--filter", default="",
                        help="Optional BPF filter, e.g. icmp")
    parser.add_argument("-w", "--write", help="Save packets to a PCAP file")
    args = parser.parse_args()

    print("Sniffing... press Ctrl+C to stop.\n")
    try:
        sniff(iface=args.iface, filter=args.filter or None,
              count=args.count, prn=handle, store=False)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("Permission denied. Run with sudo.")
        return

    print(f"\n--- Summary: {len(captured)} packets ---")
    for proto, count in stats.most_common():
        print(f"{proto:<8}{count}")

    if args.write and captured:
        wrpcap(args.write, captured)
        print(f"Saved capture to {args.write}")


if __name__ == "__main__":
    main()


