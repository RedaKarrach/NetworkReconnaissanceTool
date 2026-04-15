"""
scanner/discovery.py
--------------------
Host Discovery via ARP broadcast sweep.

How it works:
  1. Craft an ARP "who-has" packet for every IP in the subnet.
  2. Send it as an Ethernet broadcast (ff:ff:ff:ff:ff:ff).
  3. Any live host responds with its MAC → we record it.

Runs in a background thread so Django stays non-blocking.
"""
import threading
import uuid
from datetime import datetime
from scapy.all import ARP, Ether, srp, conf

# Silence Scapy's verbose output by default
conf.verb = 0


def arp_sweep(subnet: str, stop_flag: threading.Event, session_id: str,
              on_host=None, on_packet=None):
    """
    Perform an ARP sweep over `subnet` (e.g. "192.168.56.0/24").

    Parameters
    ----------
    subnet      : CIDR notation string for the network to scan
    stop_flag   : threading.Event — set this to abort mid-scan
    session_id  : used for logging / WebSocket routing
    on_host     : callback(ip, mac) called for every discovered host
    on_packet   : callback(summary_dict) for every packet event
    """

    # --- Build the ARP probe --------------------------------------------------
    # ARP layer: op=1 means "who-has" (request)
    arp = ARP(
        pdst=subnet,      # destination IP range — Scapy expands CIDR automatically
        op=1              # ARP request
    )

    # Ethernet layer: broadcast destination so every host on the segment hears it
    eth = Ether(
        dst="ff:ff:ff:ff:ff:ff"   # Layer-2 broadcast MAC
    )

    packet = eth / arp   # stack layers: Ethernet over ARP
    # --------------------------------------------------------------------------

    hosts = []

    try:
        # srp() = send-and-receive at Layer 2
        # timeout=3  → stop waiting after 3 seconds of silence
        # verbose=0  → suppress Scapy's own console output
        answered, _ = srp(packet, timeout=3, verbose=0)

        for sent, received in answered:
            if stop_flag.is_set():
                break

            ip  = received[ARP].psrc   # sender IP from ARP reply
            mac = received[ARP].hwsrc  # sender MAC from ARP reply

            host_entry = {"ip": ip, "mac": mac}
            hosts.append(host_entry)

            # Notify caller so they can persist to DB + push via WebSocket
            if on_host:
                on_host(ip, mac)

            # Log the raw packet event
            if on_packet:
                on_packet({
                    "summary": f"ARP reply: {ip} is at {mac}",
                    "flags": "ARP-REPLY",
                    "ttl": 0,
                    "src_ip": ip,
                    "dst_ip": "broadcast",
                    "protocol": "ARP",
                    "timestamp": datetime.utcnow().isoformat()
                })

    except PermissionError:
        # Scapy needs raw socket privileges (root / CAP_NET_RAW)
        if on_packet:
            on_packet({
                "summary": "ERROR: root/CAP_NET_RAW required for ARP scan",
                "flags": "ERROR",
                "ttl": 0,
                "src_ip": "",
                "dst_ip": subnet,
                "protocol": "ARP",
                "timestamp": datetime.utcnow().isoformat()
            })
    except Exception as exc:
        if on_packet:
            on_packet({
                "summary": f"ARP sweep error: {exc}",
                "flags": "ERROR",
                "ttl": 0,
                "src_ip": "",
                "dst_ip": subnet,
                "protocol": "ARP",
                "timestamp": datetime.utcnow().isoformat()
            })

    return hosts
