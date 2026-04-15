"""
scanner/fingerprint.py
----------------------
Passive + active OS fingerprinting using three signals:

1. TTL analysis
   ├── ≤ 64  → Linux / Android / macOS
   ├── ≤ 128 → Windows
   └── > 128 → Cisco IOS / BSD / network device

2. TCP window size
   ├── 65535  → older Windows / BSD
   ├── 8192   → Windows XP / 2003
   ├── 5840   → Linux 2.4.x
   ├── 14600+ → Linux 3.x / 4.x (autotuning)
   └── 65534  → macOS / iOS

3. Xmas scan probe (FIN + PSH + URG flags)
   ├── No reply  → Linux / macOS (RFC compliant: drop if closed? — actually
   │                open ports drop Xmas; closed RST)
   └── RST reply → Windows (non-RFC: responds to Xmas on closed ports too)

Each signal contributes partial confidence → final score is summed and
normalised to [0.0 – 1.0].
"""
import threading
from datetime import datetime
from scapy.all import IP, TCP, sr1, RandShort, conf

conf.verb = 0


# ─────────────────────────────────────────────────────────────────────────────
# Signal 1: TTL
# ─────────────────────────────────────────────────────────────────────────────

def _ttl_guess(ttl: int) -> tuple:
    """Returns (os_label, confidence_contribution)."""
    if ttl == 0:
        return ("unknown", 0.0)
    if ttl <= 64:
        return ("Linux/Android/macOS", 0.40)
    if ttl <= 128:
        return ("Windows", 0.40)
    return ("Cisco/BSD", 0.40)


# ─────────────────────────────────────────────────────────────────────────────
# Signal 2: TCP window size
# ─────────────────────────────────────────────────────────────────────────────

WINDOW_MAP = {
    65535: ("Windows/BSD",          0.30),
    8192:  ("Windows XP/2003",      0.30),
    5840:  ("Linux 2.4.x",          0.30),
    16384: ("Linux 3.x/4.x",        0.25),
    65534: ("macOS/iOS",            0.30),
    4128:  ("Cisco IOS",            0.35),
}

def _window_guess(window: int) -> tuple:
    """Match window size to known OS fingerprint."""
    if window in WINDOW_MAP:
        return WINDOW_MAP[window]
    # Linux autotuning: large windows ≥ 14600
    if window >= 14600:
        return ("Linux (autotuning)", 0.20)
    return ("unknown", 0.0)


# ─────────────────────────────────────────────────────────────────────────────
# Signal 3: Xmas scan probe
# ─────────────────────────────────────────────────────────────────────────────

def _xmas_probe(target_ip: str, port: int = 80) -> tuple:
    """
    Send a TCP packet with FIN+PSH+URG flags set (the "Xmas tree" packet).

    RFC 793 behaviour:
      - Closed port should reply RST.
      - Open port should drop it silently.

    Windows quirk:
      - Sends RST even to open ports, or ignores entirely.

    Returns (os_hint_label, confidence_contribution)
    """
    xmas_pkt = IP(dst=target_ip) / TCP(
        dport=port,
        sport=RandShort(),
        flags="FPU"   # FIN (F) + PSH (P) + URG (U) = "Xmas"
    )

    response = sr1(xmas_pkt, timeout=2, verbose=0)

    if response is None:
        # No reply → Linux/macOS (open port or strict firewall)
        return ("Linux/macOS", 0.30)
    elif response.haslayer(TCP) and response[TCP].flags == 0x14:
        # RST-ACK → closed port on any OS, or Windows on open port
        return ("Windows (RST to Xmas)", 0.30)
    else:
        return ("unknown", 0.0)


# ─────────────────────────────────────────────────────────────────────────────
# Combine signals
# ─────────────────────────────────────────────────────────────────────────────

def fingerprint_os(
    target_ip: str,
    probe_port: int = 80,
    stop_flag: threading.Event = None,
    on_packet=None
) -> dict:
    """
    Run all three fingerprinting probes and return a combined result.

    Returns
    -------
    {
        "ip": target_ip,
        "os_guess": "<label>",
        "confidence": 0.0-1.0,
        "ttl": int,
        "window_size": int,
        "xmas_result": "<label>",
        "details": { ... }
    }
    """
    ts = datetime.utcnow().isoformat()
    result = {
        "ip": target_ip,
        "os_guess": "unknown",
        "confidence": 0.0,
        "ttl": 0,
        "window_size": 0,
        "xmas_result": "unknown",
        "details": {}
    }

    # ── Probe 1: send plain SYN to collect TTL + window size from SYN-ACK ──
    syn = IP(dst=target_ip) / TCP(
        dport=probe_port,
        sport=RandShort(),
        flags="S"    # SYN only
    )
    syn_resp = sr1(syn, timeout=3, verbose=0)

    ttl_guess    = ("unknown", 0.0)
    window_guess = ("unknown", 0.0)

    if syn_resp and syn_resp.haslayer(TCP):
        ttl     = syn_resp[IP].ttl
        window  = syn_resp[TCP].window
        result["ttl"]         = ttl
        result["window_size"] = window
        ttl_guess    = _ttl_guess(ttl)
        window_guess = _window_guess(window)

        # RST the half-open connection
        from scapy.all import send
        rst = IP(dst=target_ip) / TCP(
            dport=probe_port,
            sport=syn_resp[TCP].dport,
            flags="R",
            seq=syn_resp[TCP].ack
        )
        send(rst, verbose=0)

        if on_packet:
            on_packet({
                "summary": (
                    f"OS-FP SYN-ACK from {target_ip}: "
                    f"TTL={ttl} Window={window}"
                ),
                "flags": str(syn_resp[TCP].flags),
                "ttl": ttl,
                "src_ip": target_ip,
                "dst_ip": "scanner",
                "protocol": "TCP",
                "timestamp": ts
            })

    # ── Probe 2: Xmas scan ──────────────────────────────────────────────────
    if stop_flag and stop_flag.is_set():
        return result

    xmas_guess = _xmas_probe(target_ip, probe_port)
    result["xmas_result"] = xmas_guess[0]

    if on_packet:
        on_packet({
            "summary": f"OS-FP Xmas probe → {target_ip}: {xmas_guess[0]}",
            "flags": "FPU",
            "ttl": result["ttl"],
            "src_ip": "scanner",
            "dst_ip": target_ip,
            "protocol": "TCP",
            "timestamp": datetime.utcnow().isoformat()
        })

    # ── Combine signals ─────────────────────────────────────────────────────
    votes = {}  # os_label → total confidence

    for label, conf_val in [ttl_guess, window_guess, xmas_guess]:
        if label != "unknown":
            # Normalise label to broad category for merging
            broad = _broad_label(label)
            votes[broad] = votes.get(broad, 0.0) + conf_val

    if votes:
        best_label = max(votes, key=lambda k: votes[k])
        # Cap at 1.0; scale so 3 matching signals → ~1.0
        total = min(votes[best_label], 1.0)
        result["os_guess"]   = best_label
        result["confidence"] = round(total, 2)

    result["details"] = {
        "ttl_signal":    ttl_guess[0],
        "window_signal": window_guess[0],
        "xmas_signal":   xmas_guess[0]
    }

    return result


def _broad_label(label: str) -> str:
    """Map specific label variants to a canonical OS name."""
    label_lower = label.lower()
    if "windows" in label_lower:
        return "Windows"
    if "linux" in label_lower or "android" in label_lower:
        return "Linux"
    if "macos" in label_lower or "ios" in label_lower:
        return "macOS"
    if "cisco" in label_lower:
        return "Cisco/BSD"
    if "bsd" in label_lower:
        return "Cisco/BSD"
    return label
