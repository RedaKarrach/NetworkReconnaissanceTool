"""
victim_agent.py — Run on the Windows 10 VM (as Administrator)
=============================================================
Sniffs the local network interface with Scapy, detects SYN flood
and ARP spoofing in real time, and POSTs alerts to the host dashboard.

Usage:
    pip install scapy requests
    python victim_agent.py

Requirements:
    - Run as Administrator (Windows) or root (Linux)
    - Npcap installed on Windows (https://npcap.com)
    - Dashboard reachable at DASHBOARD_URL
"""

import time
import sys
import requests
from collections import defaultdict

try:
    from scapy.all import sniff, ARP, TCP, IP, conf
except ImportError:
    print("[!] Scapy not found. Run: pip install scapy")
    sys.exit(1)

# ── Configuration ─────────────────────────────────────────────────────────────
DASHBOARD_URL  = "http://192.168.56.1:8000/api/alerts/"   # Host machine IP
AGENT_NAME     = "win-victim"
MY_IP          = "192.168.56.20"

# Detection thresholds (must match detection.py on the server)
SYN_THRESHOLD  = 200   # SYNs from same IP within SYN_WINDOW seconds
SYN_WINDOW     = 10    # seconds
ARP_COOLDOWN   = 5     # seconds before re-alerting same IP

# ── State ─────────────────────────────────────────────────────────────────────
arp_table       = {}                    # ip -> mac
syn_window      = defaultdict(list)     # src_ip -> [timestamps]
arp_alerted_at  = {}                    # ip -> last_alert_timestamp

# ─────────────────────────────────────────────────────────────────────────────
def post_alert(type_, src, dst, severity, message):
    """Send alert to the Django dashboard."""
    payload = {
        "agent":    AGENT_NAME,
        "type":     type_,
        "src_ip":   src,
        "dst_ip":   dst,
        "severity": severity,
        "message":  message,
    }
    try:
        resp = requests.post(DASHBOARD_URL, json=payload, timeout=3)
        status = "OK" if resp.status_code == 201 else f"HTTP {resp.status_code}"
        print(f"  [ALERT SENT] {severity.upper():8s} | {type_:16s} | {message[:60]} [{status}]")
    except requests.exceptions.ConnectionError:
        print(f"  [ERR] Dashboard unreachable at {DASHBOARD_URL}")
    except Exception as e:
        print(f"  [ERR] {e}")


# ─────────────────────────────────────────────────────────────────────────────
def on_packet(pkt):
    now = time.time()

    # ── ARP spoofing detection ────────────────────────────────────────────────
    if ARP in pkt and pkt[ARP].op == 2:          # ARP reply
        ip  = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc

        if ip in arp_table and arp_table[ip] != mac:
            # Avoid alert storm for the same IP
            last = arp_alerted_at.get(ip, 0)
            if now - last > ARP_COOLDOWN:
                post_alert(
                    type_    = "arp_anomaly",
                    src      = mac,
                    dst      = ip,
                    severity = "high",
                    message  = (
                        f"ARP spoof detected: {ip} changed MAC "
                        f"from {arp_table[ip]} to {mac}"
                    )
                )
                arp_alerted_at[ip] = now

        arp_table[ip] = mac   # update table

    # ── SYN flood detection ───────────────────────────────────────────────────
    if IP in pkt and TCP in pkt and pkt[TCP].flags == 0x02:   # SYN only
        src   = pkt[IP].src
        dport = pkt[TCP].dport

        # Slide the window
        syn_window[src] = [t for t in syn_window[src] if now - t < SYN_WINDOW]
        syn_window[src].append(now)

        count = len(syn_window[src])
        if count >= SYN_THRESHOLD:
            post_alert(
                type_    = "syn_flood",
                src      = src,
                dst      = MY_IP,
                severity = "critical",
                message  = (
                    f"SYN flood from {src}: "
                    f"{count} SYN/s on port {dport}"
                )
            )
            syn_window[src].clear()   # reset to avoid alert storm


# ─────────────────────────────────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("  Victim Agent — Network Intrusion Detection")
    print("=" * 60)
    print(f"  Agent name : {AGENT_NAME}")
    print(f"  My IP      : {MY_IP}")
    print(f"  Dashboard  : {DASHBOARD_URL}")
    print(f"  Thresholds : SYN flood > {SYN_THRESHOLD}/10s | ARP cooldown {ARP_COOLDOWN}s")
    print("=" * 60)

    # Verify dashboard is reachable
    print("\n[*] Checking dashboard connectivity...", end=" ")
    try:
        requests.get(DASHBOARD_URL.replace("/api/alerts/", "/api/"), timeout=3)
        print("OK")
    except Exception:
        print("UNREACHABLE — alerts will fail until dashboard is up")

    print(f"\n[*] Starting packet capture on {MY_IP}...")
    print("[*] Press Ctrl+C to stop\n")

    try:
        sniff(prn=on_packet, store=False, filter="arp or tcp")
    except KeyboardInterrupt:
        print("\n[*] Agent stopped.")
    except PermissionError:
        print("\n[!] Permission denied. Run as Administrator.")
        sys.exit(1)


if __name__ == "__main__":
    main()
