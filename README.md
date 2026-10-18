
# CodeAlpha Basic Network Sniffer

## Project Overview
This project is a basic network sniffer developed using Python and Scapy as part of the CodeAlpha Cyber Security Internship.

The program captures network packets from a selected network interface and displays useful information, including source and destination IP addresses, protocols, port numbers, and packet payload previews.

## Features
- Capture packets from a specified network interface.
- Display source and destination addresses.
- Identify protocols such as ICMP, UDP, TCP, ARP, IPv4, and IPv6 where supported by the program.
- Display source and destination port numbers when available.
- Apply packet-capture filters.
- Display a summary of captured packets.
- Save captured packets in PCAP format for later analysis.

## Technologies Used
- Python 3
- Scapy
- Kali Linux
- Git

## Requirements
- Python 3
- Scapy
- Appropriate permissions to capture network traffic

## Installation
Install Scapy using:

```bash
python3 -m pip install scapy
```

## Usage
Navigate to the project directory:

```bash
cd ~/CodeAlpha_BasicNetworkSniffer
```

Capture 30 packets and save them:

```bash
sudo python3 sniffer.py -i eth0 -c 30 -w capture.pcap
```

Capture ICMP packets:

```bash
sudo python3 sniffer.py -i eth0 -c 10 -f "icmp" -w icmp_capture.pcap
```

Capture UDP packets:

```bash
sudo python3 sniffer.py -i eth0 -c 10 -f "udp" -w udp_capture.pcap
```

## Testing
The following tests were performed:

1. Python syntax was checked successfully.
2. General packet capture collected 30 packets.
3. The ICMP filter captured 10 packets.
4. The UDP filter captured 10 packets.
5. Scapy successfully read the saved ICMP and UDP capture files.

## Output Files
- `capture.pcap` — general network traffic.
- `icmp_capture.pcap` — ICMP traffic.
- `udp_capture.pcap` — UDP traffic.

## Responsible Use
Use this tool only on networks and devices you own or have explicit permission to monitor. Packet captures may contain sensitive information.

## Author
CodeAlpha Cyber Security Internship Project

