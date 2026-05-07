"""
Traffic simulator — injects crafted packets to trigger anomaly detection.
Must be run as Administrator (same requirement as the sniffer).
"""
import time
import random
from scapy.all import IP, TCP, UDP, send, conf

conf.verb = 0

# Fake source IPs — clearly test traffic, easy to spot in the dashboard
SCANNER_IP   = "10.99.1.1"   # will trigger port scan
FLOODER_IP   = "10.99.2.1"   # will trigger high volume
TARGET_IP    = "192.0.2.1"   # RFC 5737 documentation range — safe sink


def simulate_port_scan(n_ports=20):
    print(f"[*] Port scan: sending SYN to {n_ports} ports from {SCANNER_IP} ...")
    for port in range(7000, 7000 + n_ports):
        pkt = IP(src=SCANNER_IP, dst=TARGET_IP) / TCP(dport=port, sport=54321, flags="S")
        send(pkt)
        time.sleep(0.03)
    print(f"[+] Port scan done  ({n_ports} ports -> threshold is 15)")


def simulate_high_volume(n_packets=120):
    print(f"[*] High volume: sending {n_packets} UDP packets from {FLOODER_IP} ...")
    for _ in range(n_packets):
        sport = random.randint(1024, 65535)
        pkt = IP(src=FLOODER_IP, dst=TARGET_IP) / UDP(dport=9000, sport=sport, len=20)
        send(pkt)
    print(f"[+] High volume done  ({n_packets} pkts in <10s -> threshold is 100)")


if __name__ == "__main__":
    print("\n  Traffic Anomaly Simulator")
    print("  ==========================")
    print(f"  Scanner source : {SCANNER_IP}")
    print(f"  Flooder source : {FLOODER_IP}")
    print(f"  Sink target    : {TARGET_IP} (RFC 5737 — safe)\n")

    simulate_port_scan()
    time.sleep(1)
    simulate_high_volume()

    print("\n  Done — check the Anomaly Alerts panel in the dashboard.")
