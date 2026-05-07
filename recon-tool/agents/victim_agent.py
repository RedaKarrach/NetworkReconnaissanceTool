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
import subprocess
import platform
import os
import argparse
import socket
from collections import defaultdict

try:
    from scapy.all import sniff, ARP, TCP, IP, ICMP, conf, get_if_list, get_if_addr
except ImportError:
    print("[!] Scapy not found. Run: pip install scapy")
    sys.exit(1)

# ── Configuration ─────────────────────────────────────────────────────────────
DASHBOARD_URL  = os.environ.get("DASHBOARD_URL", "http://192.168.56.1:8000/api/alerts/")
PACKET_URL     = os.environ.get("PACKET_URL", "http://192.168.56.1:8000/api/packets/")
AGENT_NAME     = os.environ.get("AGENT_NAME", platform.node() or "victim-agent")
MY_IP          = os.environ.get("MY_IP", "")
AUTOSTART_NAME = os.environ.get("AUTOSTART_NAME", "ReconVictimAgent")

# Detection thresholds (must match detection.py on the server)
SYN_THRESHOLD  = int(os.environ.get("SYN_THRESHOLD", "200"))   # SYNs from same IP within SYN_WINDOW seconds
SYN_WINDOW     = int(os.environ.get("SYN_WINDOW", "10"))      # seconds
ARP_COOLDOWN   = int(os.environ.get("ARP_COOLDOWN", "5"))     # seconds before re-alerting same IP
SYN_TOTAL_THRESHOLD = int(os.environ.get("SYN_TOTAL_THRESHOLD", "200"))   # total SYNs to same dst port within SYN_WINDOW
SYN_TOTAL_COOLDOWN  = int(os.environ.get("SYN_TOTAL_COOLDOWN", "8"))      # seconds before re-alerting same dst port
PORT_SWEEP_THRESHOLD = int(os.environ.get("PORT_SWEEP_THRESHOLD", "3"))   # distinct ports from same source within window
PORT_SWEEP_WINDOW    = int(os.environ.get("PORT_SWEEP_WINDOW", "10"))     # seconds

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
def _quote_windows(arg):
    return f'"{str(arg).replace("\"", "\\\"")}"'


def _detect_local_ip():
    if MY_IP:
        return MY_IP

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            ip = sock.getsockname()[0]
            if ip:
                return ip
    except Exception:
        pass

    try:
        return get_if_addr(conf.iface)
    except Exception:
        return "127.0.0.1"


def _runtime_command(dashboard_url, packet_url, agent_name, my_ip):
    script_path = os.path.abspath(__file__)
    cmd = [
        sys.executable,
        script_path,
        "--dashboard-url", dashboard_url,
        "--packet-url", packet_url,
        "--agent-name", agent_name,
        "--my-ip", my_ip,
    ]
    return cmd


def _windows_task_exists(name: str) -> bool:
    result = subprocess.run(["schtasks", "/Query", "/TN", name], capture_output=True, text=True)
    return result.returncode == 0


def _install_windows_task(name: str, task_run: str, trigger: str) -> None:
    create_cmd = [
        "schtasks", "/Create", "/F", "/SC", trigger,
        "/TN", name,
        "/TR", task_run,
        "/RL", "HIGHEST",
        "/RU", "SYSTEM",
        "/DELAY", "0000:30",
    ]
    completed = subprocess.run(create_cmd, capture_output=True, text=True)
    if completed.returncode != 0:
        raise RuntimeError((completed.stderr or completed.stdout or "schtasks failed").strip())


def install_autostart(dashboard_url, packet_url, agent_name, my_ip):
    cmd = _runtime_command(dashboard_url, packet_url, agent_name, my_ip)

    if os.name == "nt":
        task_run = " ".join(_quote_windows(part) for part in cmd)
        start_name = AUTOSTART_NAME
        logon_name = f"{AUTOSTART_NAME}-Logon"
        _install_windows_task(start_name, task_run, "ONSTART")
        _install_windows_task(logon_name, task_run, "ONLOGON")
        return f"Installed Windows startup tasks: {start_name}, {logon_name}"

    service_name = f"{AUTOSTART_NAME}.service"
    service_path = f"/etc/systemd/system/{service_name}"
    exec_cmd = " ".join(f'"{part}"' for part in cmd)
    service_body = "\n".join([
        "[Unit]",
        "Description=Recon Tool Victim Detection Agent",
        "After=network-online.target",
        "Wants=network-online.target",
        "",
        "[Service]",
        "Type=simple",
        f"ExecStart={exec_cmd}",
        "Restart=always",
        "RestartSec=3",
        "",
        "[Install]",
        "WantedBy=multi-user.target",
        "",
    ])

    try:
        with open(service_path, "w", encoding="utf-8") as handle:
            handle.write(service_body)
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", "--now", service_name], check=True)
    except PermissionError as exc:
        raise RuntimeError("Permission denied writing systemd service; run as root/sudo.") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"systemctl failed: {exc}") from exc

    return f"Installed Linux systemd service: {service_name}"


def uninstall_autostart():
    if os.name == "nt":
        names = [AUTOSTART_NAME, f"{AUTOSTART_NAME}-Logon"]
        for name in names:
            subprocess.run(["schtasks", "/Delete", "/F", "/TN", name], capture_output=True, text=True)
        return f"Removed Windows startup tasks: {', '.join(names)}"

    service_name = f"{AUTOSTART_NAME}.service"
    service_path = f"/etc/systemd/system/{service_name}"
    try:
        subprocess.run(["systemctl", "disable", "--now", service_name], check=False)
        if os.path.exists(service_path):
            os.remove(service_path)
        subprocess.run(["systemctl", "daemon-reload"], check=True)
    except PermissionError as exc:
        raise RuntimeError("Permission denied removing systemd service; run as root/sudo.") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"systemctl failed: {exc}") from exc

    return f"Removed Linux systemd service: {service_name}"


def _autostart_installed():
    if os.name == "nt":
        start_name = AUTOSTART_NAME
        logon_name = f"{AUTOSTART_NAME}-Logon"
        return _windows_task_exists(start_name) and _windows_task_exists(logon_name)

    service_name = f"{AUTOSTART_NAME}.service"
    result = subprocess.run(["systemctl", "is-enabled", service_name],
                            capture_output=True, text=True)
    return result.returncode == 0


# ─────────────────────────────────────────────────────────────────────────────
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
                # Avoid alert storm for the same IP
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

            arp_table[ip] = mac   # update table

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
            _block_ip(src, "SYN flood", now)
            syn_window[src].clear()   # reset to avoid alert storm

        # Distributed SYN flood detection (works with spoofed/random source IPs)
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

        # Port sweep / Nmap-like scan detection
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
    global DASHBOARD_URL, PACKET_URL, AGENT_NAME, MY_IP

    parser = argparse.ArgumentParser(description="Recon victim detection agent")
    parser.add_argument("--dashboard-url", default=None)
    parser.add_argument("--packet-url", default=None)
    parser.add_argument("--agent-name", default=None)
    parser.add_argument("--my-ip", default=None)
    parser.add_argument("--install-autostart", action="store_true")
    parser.add_argument("--uninstall-autostart", action="store_true")
    parser.add_argument("--ensure-autostart", action="store_true")
    args, _ = parser.parse_known_args()

    if args.dashboard_url:
        DASHBOARD_URL = args.dashboard_url
    if args.packet_url:
        PACKET_URL = args.packet_url
    if args.agent_name:
        AGENT_NAME = args.agent_name
    if args.my_ip:
        MY_IP = args.my_ip

    MY_IP = _detect_local_ip()

    if args.install_autostart and args.uninstall_autostart:
        print("[ERR] choose only one of --install-autostart or --uninstall-autostart")
        sys.exit(2)

    if args.install_autostart:
        try:
            message = install_autostart(DASHBOARD_URL, PACKET_URL, AGENT_NAME, MY_IP)
            print(f"[OK] {message}")
            sys.exit(0)
        except Exception as exc:
            print(f"[ERR] {exc}")
            sys.exit(1)

    if args.uninstall_autostart:
        try:
            message = uninstall_autostart()
            print(f"[OK] {message}")
            sys.exit(0)
        except Exception as exc:
            print(f"[ERR] {exc}")
            sys.exit(1)

    ensure_autostart = args.ensure_autostart or os.environ.get("ENSURE_AUTOSTART", "").lower() in {
        "1", "true", "yes"
    }
    if ensure_autostart:
        try:
            if not _autostart_installed():
                message = install_autostart(DASHBOARD_URL, PACKET_URL, AGENT_NAME, MY_IP)
                print(f"[OK] {message}")
        except Exception as exc:
            print(f"[ERR] Autostart install failed: {exc}")

    print("=" * 60)
    print("  Victim Agent — Network Intrusion Detection")
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
        print("\n[!] Permission denied. Run as Administrator.")
        sys.exit(1)


if __name__ == "__main__":
    main()
