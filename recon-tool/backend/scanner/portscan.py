"""
scanner/portscan.py
-------------------
TCP SYN stealth scan + UDP probe + banner grabbing.

TCP SYN Stealth ("half-open"):
  1. We send SYN.
  2. Target replies SYN-ACK  → port is OPEN.   We immediately RST to avoid full connection.
  3. Target replies RST       → port is CLOSED.
  4. No reply after timeout   → port is FILTERED (firewall drop).

UDP probe:
  1. We send an empty UDP datagram.
  2. Target replies ICMP Port Unreachable → port is CLOSED.
  3. No reply                             → port is OPEN|FILTERED.
  4. Application reply                    → port is OPEN.

Banner grabbing:
  After confirming TCP open we establish a real TCP connection,
  wait briefly for a welcome banner, then close.
"""
import socket
import threading
from datetime import datetime
from scapy.all import (
    IP, TCP, UDP, ICMP,
    sr1, send, conf, RandShort
)

conf.verb = 0   # suppress Scapy output


# ─────────────────────────────────────────────────────────────────────────────
# TCP SYN stealth scan
# ─────────────────────────────────────────────────────────────────────────────

def syn_scan_port(target_ip: str, port: int, timeout: float = 2.0) -> dict:
    """
    Send a single TCP SYN and classify the port.

    Returns dict: { port, status, flags, ttl }
    """
    # Build the SYN packet
    ip_layer  = IP(dst=target_ip)               # destination IP
    tcp_layer = TCP(
        dport=port,           # destination port we're probing
        sport=RandShort(),    # random ephemeral source port
        flags="S"             # SYN flag only
    )
    syn_packet = ip_layer / tcp_layer

    # Send SYN, wait for one reply (sr1 = send-receive-one)
    response = sr1(syn_packet, timeout=timeout, verbose=0)

    result = {
        "port": port,
        "status": "filtered",
        "flags": "",
        "ttl": 0
    }

    if response is None:
        # No reply → filtered by firewall or host is down
        result["status"] = "filtered"

    elif response.haslayer(TCP):
        tcp_resp = response[TCP]
        result["ttl"]   = response[IP].ttl
        result["flags"] = str(tcp_resp.flags)   # e.g. "SA" = SYN-ACK

        if tcp_resp.flags == 0x12:   # SYN-ACK (0x12 = SA flags)
            result["status"] = "open"
            # Immediately RST to tear down half-open connection cleanly
            rst = IP(dst=target_ip) / TCP(
                dport=port,
                sport=tcp_resp.dport,
                flags="R",             # RST flag
                seq=tcp_resp.ack       # acknowledge their seq
            )
            send(rst, verbose=0)

        elif tcp_resp.flags == 0x14:  # RST-ACK (0x14 = RA flags)
            result["status"] = "closed"

    elif response.haslayer(ICMP):
        # ICMP type 3 = destination unreachable (various codes = filtered)
        icmp = response[ICMP]
        if int(icmp.type) == 3 and int(icmp.code) in (1, 2, 3, 9, 10, 13):
            result["status"] = "filtered"

    return result


# ─────────────────────────────────────────────────────────────────────────────
# UDP probe
# ─────────────────────────────────────────────────────────────────────────────

def udp_scan_port(target_ip: str, port: int, timeout: float = 3.0) -> dict:
    """
    Send empty UDP datagram, classify based on response.
    """
    ip_layer  = IP(dst=target_ip)
    udp_layer = UDP(dport=port, sport=RandShort())

    response = sr1(ip_layer / udp_layer, timeout=timeout, verbose=0)

    result = {"port": port, "status": "open|filtered", "flags": "UDP", "ttl": 0}

    if response is None:
        # Silence → open or filtered (can't distinguish without app payload)
        result["status"] = "open|filtered"

    elif response.haslayer(UDP):
        # Got a UDP reply → definitively open
        result["status"] = "open"
        result["ttl"]    = response[IP].ttl

    elif response.haslayer(ICMP):
        icmp = response[ICMP]
        if int(icmp.type) == 3 and int(icmp.code) == 3:
            # Code 3 = Port Unreachable → definitively closed
            result["status"] = "closed"
        else:
            result["status"] = "filtered"
        result["ttl"] = response[IP].ttl

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Banner grabbing
# ─────────────────────────────────────────────────────────────────────────────

def grab_banner(target_ip: str, port: int, timeout: float = 3.0) -> str:
    """
    Open a real TCP connection to an open port and read the welcome banner.
    Many services (FTP, SSH, SMTP, HTTP) send a banner immediately on connect.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target_ip, port))

        # Some services need a prompt; send HTTP request as a generic probe
        if port == 80 or port == 8080:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port == 443:
            # TLS — just try to read, won't get plaintext banner but avoids hang
            sock.send(b"\x16\x03\x01")   # TLS ClientHello first byte
        else:
            # Most services (FTP, SSH, SMTP, POP3…) push banner without prompt
            pass

        banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
        sock.close()
        return banner[:256]   # cap at 256 chars

    except (socket.timeout, ConnectionRefusedError, OSError):
        return ""


# ─────────────────────────────────────────────────────────────────────────────
# Full port scan runner (called from background thread)
# ─────────────────────────────────────────────────────────────────────────────

def run_port_scan(
    target_ip: str,
    ports: list,
    stop_flag: threading.Event,
    session_id: str,
    protocol: str = "tcp",
    on_result=None,
    on_packet=None
):
    """
    Iterate over `ports`, scan each one, call callbacks with results.

    Parameters
    ----------
    target_ip  : host to scan
    ports      : list of int port numbers
    stop_flag  : set() to abort the scan early
    session_id : used for WebSocket routing
    protocol   : "tcp" | "udp"
    on_result  : callback(port_result_dict) → persist to DB + push WS
    on_packet  : callback(packet_summary_dict) → push raw packet to WS
    """
    for port in ports:
        if stop_flag.is_set():
            break

        ts = datetime.utcnow().isoformat()

        if protocol == "tcp":
            result = syn_scan_port(target_ip, port)
            # Grab banner on confirmed open ports
            if result["status"] == "open":
                result["banner"] = grab_banner(target_ip, port)
            else:
                result["banner"] = ""
        else:
            result = udp_scan_port(target_ip, port)
            result["banner"] = ""

        result["protocol"] = protocol
        result["target_ip"] = target_ip

        if on_result:
            on_result(result)

        if on_packet:
            on_packet({
                "summary": (
                    f"{protocol.upper()} port {port}/{target_ip} → "
                    f"{result['status']}"
                    + (f" [{result['banner'][:60]}]" if result.get("banner") else "")
                ),
                "flags": result.get("flags", ""),
                "ttl": result.get("ttl", 0),
                "src_ip": "scanner",
                "dst_ip": target_ip,
                "protocol": protocol.upper(),
                "timestamp": ts
            })
