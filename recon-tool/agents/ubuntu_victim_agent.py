"""
ubuntu_victim_agent.py — Run on the Ubuntu "server" VM (as root)
=================================================================
Sniffs the local interface with Scapy, detects SYN flood
and ARP spoofing in real time, and POSTs alerts to the host dashboard.

Usage:
    pip install scapy requests
    sudo python ubuntu_victim_agent.py

Requirements:
    - Run as root (Linux)
    - Dashboard reachable at DASHBOARD_URL
"""

import time
import sys
import os
import requests
import subprocess
import platform
from collections import defaultdict

try:
    from scapy.all import sniff, ARP, TCP, IP, ICMP, conf, get_if_list, get_if_addr
except ImportError:
    print("[!] Scapy not found. Run: pip install scapy")
    sys.exit(1)

# ── Configuration ─────────────────────────────────────────────────────────────
DASHBOARD_URL  = os.environ.get("DASHBOARD_URL", "http://192.168.56.1:8000/api/alerts/")
PACKET_URL     = os.environ.get("PACKET_URL", "http://192.168.56.1:8000/api/packets/")
AGENT_NAME     = os.environ.get("AGENT_NAME", "ubuntu-server")
MY_IP          = os.environ.get("MY_IP", "192.168.56.30")

# Detection thresholds (must match detection.py on the server)
SYN_THRESHOLD  = 200   # SYNs from same IP within SYN_WINDOW seconds
SYN_WINDOW     = 10    # seconds
ARP_COOLDOWN   = 5     # seconds before re-alerting same IP
SYN_TOTAL_THRESHOLD = 200   # total SYNs to same dst port within SYN_WINDOW
SYN_TOTAL_COOLDOWN  = 8     # seconds before re-alerting same dst port
PORT_SWEEP_THRESHOLD = 15   # distinct ports from same source within PORT_SWEEP_WINDOW
PORT_SWEEP_WINDOW    = 30   # seconds

# Auto-block settings
AUTO_BLOCK_ATTACKS = True
BLOCK_COOLDOWN = 60   # seconds between block attempts for same IP
BLOCK_RULE_PREFIX = "ReconTool AutoBlock"

# ── State ─────────────────────────────────────────────────────────────────────
arp_table       = {}                    # ip -> mac
syn_window      = defaultdict(list)     # src_ip -> [timestamps]
arp_alerted_at  = {}                    # ip -> last_alert_timestamp
syn_total_window = defaultdict(list)    # dst_port -> [timestamps]
syn_total_alerted_at = {}               # dst_port -> last_alert_timestamp
port_sweep_window = defaultdict(list)   # src_ip -> [(ts, dport)]
port_sweep_alerted_at = {}              # src_ip -> last_alert_timestamp
blocked_at = {}                          # ip -> last_block_timestamp

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


def post_packet(summary, flags, src_ip, dst_ip, proto, ttl=0):
    payload = {
        "summary": summary,
        "flags": flags,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": proto,
        "ttl": ttl,
    }
    try:
        requests.post(PACKET_URL, json=payload, timeout=2)
    except Exception:
        pass


def _find_ip_by_mac(mac, exclude_ip=None):
    for ip, known_mac in arp_table.items():
        if ip == exclude_ip:
            continue
        if known_mac == mac:
            return ip
    return None


def _block_ip(ip, reason, now=None):
    if not AUTO_BLOCK_ATTACKS:
        return False
    if not ip or ip in {"0.0.0.0", "127.0.0.1"}:
        return False

    now = now or time.time()
    last = blocked_at.get(ip, 0)
    if now - last < BLOCK_COOLDOWN:
        return False

    if platform.system().lower().startswith("win"):
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={BLOCK_RULE_PREFIX} {ip}", "dir=in", "action=block",
            f"remoteip={ip}", "enable=yes"
        ]
    else:
        cmd = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]

    try:
        subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        blocked_at[ip] = now
        post_alert(
            type_="auto_block",
            src=ip,
            dst=MY_IP,
            severity="high",
            message=f"Auto-blocked {ip} ({reason})"
        )
        return True
    except Exception as e:
        print(f"  [ERR] Failed to block {ip}: {e}")
        return False


# ─────────────────────────────────────────────────────────────────────────────

def on_packet(pkt):
    now = time.time()

    # ── ARP spoofing detection ────────────────────────────────────────────────
    if ARP in pkt:
        ip  = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc
        op  = int(pkt[ARP].op)

        if op == 1:
            summary = f"ARP request: who has {pkt[ARP].pdst}? tell {ip}"
            flags = "ARP-REQ"
        else:
            summary = f"ARP reply: {ip} is at {mac}"
            flags = "ARP-REPLY"

        post_packet(
            summary=summary,
            flags=flags,
            src_ip=ip,
            dst_ip=pkt[ARP].pdst if op == 1 else "broadcast",
            proto="ARP",
            ttl=0
        )

        if op == 2:
            if ip in arp_table and arp_table[ip] != mac:
                last = arp_alerted_at.get(ip, 0)
                if now - last > ARP_COOLDOWN:
                    attacker_ip = _find_ip_by_mac(mac, exclude_ip=ip)
                    post_alert(
                        type_    = "arp_anomaly",
                        src      = attacker_ip or mac,
                        dst      = ip,
                        severity = "high",
                        message  = (
                            f"ARP spoof detected: {ip} changed MAC "
                            f"from {arp_table[ip]} to {mac}"
                        )
                    )
                    if attacker_ip:
                        _block_ip(attacker_ip, "ARP spoofing", now)
                    arp_alerted_at[ip] = now

            arp_table[ip] = mac

    # ── TCP packet logging + SYN flood detection ─────────────────────────────
    if IP in pkt and TCP in pkt:
        src   = pkt[IP].src
        dport = pkt[TCP].dport
        flags = str(pkt[TCP].flags)

        post_packet(
            summary=f"TCP {flags} from {src} → {MY_IP}:{dport}",
            flags=flags,
            src_ip=src,
            dst_ip=MY_IP,
            proto="TCP",
            ttl=pkt[IP].ttl
        )

        if pkt[TCP].flags != 0x02:
            return

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
            _block_ip(src, "SYN flood", now)
            syn_window[src].clear()

        syn_total_window[dport] = [t for t in syn_total_window[dport] if now - t < SYN_WINDOW]
        syn_total_window[dport].append(now)
        total_count = len(syn_total_window[dport])
        last_total_alert = syn_total_alerted_at.get(dport, 0)
        if total_count >= SYN_TOTAL_THRESHOLD and (now - last_total_alert) > SYN_TOTAL_COOLDOWN:
            post_alert(
                type_    = "syn_flood_distributed",
                src      = "multiple",
                dst      = f"{MY_IP}:{dport}",
                severity = "critical",
                message  = (
                    f"Distributed SYN flood suspected: {total_count} SYN/{SYN_WINDOW}s "
                    f"on {MY_IP}:{dport}"
                )
            )
            syn_total_alerted_at[dport] = now
            syn_total_window[dport].clear()

        port_sweep_window[src] = [(t, p) for (t, p) in port_sweep_window[src] if now - t < PORT_SWEEP_WINDOW]
        port_sweep_window[src].append((now, dport))
        distinct_ports = len({p for _, p in port_sweep_window[src]})
        last_sweep_alert = port_sweep_alerted_at.get(src, 0)
        if distinct_ports >= PORT_SWEEP_THRESHOLD and (now - last_sweep_alert) > 5:
            post_alert(
                type_    = "port_sweep",
                src      = src,
                dst      = MY_IP,
                severity = "medium",
                message  = (
                    f"Nmap-like port scan detected from {src}: "
                    f"{distinct_ports} ports in {PORT_SWEEP_WINDOW}s"
                )
            )
            _block_ip(src, "Port sweep", now)
            port_sweep_alerted_at[src] = now
            port_sweep_window[src].clear()

    # ── ICMP logging + redirect detection ─────────────────────────────────────
    if IP in pkt and ICMP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        icmp_type = int(pkt[ICMP].type)
        flags = "ICMP-REDIRECT" if icmp_type == 5 else f"ICMP-{icmp_type}"

        post_packet(
            summary=f"ICMP type {icmp_type} from {src} → {dst}",
            flags=flags,
            src_ip=src,
            dst_ip=dst,
            proto="ICMP",
            ttl=pkt[IP].ttl,
        )

        if icmp_type == 5:
            post_alert(
                type_="icmp_redirect",
                src=src,
                dst=dst,
                severity="high",
                message=f"ICMP redirect detected from {src} to {dst}",
            )
            _block_ip(src, "ICMP redirect", now)


# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  Ubuntu Server Agent — Network Intrusion Detection")
    print("=" * 60)
    print(f"  Agent name : {AGENT_NAME}")
    print(f"  My IP      : {MY_IP}")
    print(f"  Dashboard  : {DASHBOARD_URL}")
    print(
        f"  Thresholds : SYN/src > {SYN_THRESHOLD}/{SYN_WINDOW}s "
        f"| SYN/total > {SYN_TOTAL_THRESHOLD}/{SYN_WINDOW}s "
        f"| Sweep > {PORT_SWEEP_THRESHOLD}/{PORT_SWEEP_WINDOW}s "
        f"| ARP cooldown {ARP_COOLDOWN}s"
    )
    print("=" * 60)

    print("\n[*] Checking dashboard connectivity...", end=" ")
    try:
        requests.get(DASHBOARD_URL.replace("/api/alerts/", "/api/"), timeout=3)
        print("OK")
    except Exception:
        print("UNREACHABLE — alerts will fail until dashboard is up")

    print(f"\n[*] Starting packet capture on {MY_IP}...")
    print("[*] Press Ctrl+C to stop\n")

    try:
        iface = conf.iface
        for name in get_if_list():
            try:
                if get_if_addr(name) == MY_IP:
                    iface = name
                    break
            except Exception:
                continue
        sniff(prn=on_packet, store=False, filter="arp or tcp or icmp", iface=iface)
    except KeyboardInterrupt:
        print("\n[*] Agent stopped.")
    except PermissionError:
        print("\n[!] Permission denied. Run as root.")
        sys.exit(1)


if __name__ == "__main__":
    main()
