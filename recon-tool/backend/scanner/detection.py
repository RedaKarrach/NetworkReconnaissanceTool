"""
scanner/detection.py
--------------------
Passive pattern detection that runs alongside scans.
Fires alerts into MongoDB + WebSocket when suspicious behaviour is spotted.

Patterns detected:
  • ARP anomaly      — same IP, different MAC in short window (possible spoof)
  • Port sweep       — >15 distinct ports probed from same source in 30s
  • SYN flood signal — >200 SYN packets to same dst port in 10s
"""
import threading
from datetime import datetime, timedelta
from collections import defaultdict

from models import Alert


# Per-session state stores (cleared on session end)
_arp_cache   = defaultdict(dict)          # session → { ip: mac }
_port_hits   = defaultdict(lambda: defaultdict(list))  # session → { src_ip: [timestamps] }
_syn_hits    = defaultdict(lambda: defaultdict(list))  # session → { dst_port: [timestamps] }
_lock        = threading.Lock()


def _save_alert(session, type_, src_ip, dst_ip, severity, message):
    """Persist alert to MongoDB and return dict for WebSocket broadcast."""
    a = Alert(
        session   = session,
        type      = type_,
        src_ip    = src_ip,
        dst_ip    = dst_ip,
        severity  = severity,
        message   = message,
        timestamp = datetime.utcnow(),
    )
    a.save()
    return {
        "type":      type_,
        "src_ip":    src_ip,
        "dst_ip":    dst_ip,
        "severity":  severity,
        "message":   message,
        "timestamp": a.timestamp.isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# ARP anomaly detection
# ─────────────────────────────────────────────────────────────────────────────

def check_arp(session, ip: str, mac: str, on_alert=None):
    """
    Call for every ARP reply received.
    Fires 'arp_anomaly' alert if the MAC for a known IP changes.
    """
    sid = str(session.session_id)
    with _lock:
        known_mac = _arp_cache[sid].get(ip)
        if known_mac is None:
            _arp_cache[sid][ip] = mac
            return
        if known_mac != mac:
            alert = _save_alert(
                session, "arp_anomaly",
                src_ip   = mac,
                dst_ip   = ip,
                severity = "high",
                message  = (
                    f"ARP anomaly: IP {ip} was {known_mac}, now {mac}. "
                    "Possible ARP spoofing in progress."
                )
            )
            _arp_cache[sid][ip] = mac   # update to latest
            if on_alert:
                on_alert(alert)


# ─────────────────────────────────────────────────────────────────────────────
# Port sweep detection
# ─────────────────────────────────────────────────────────────────────────────

PORT_SWEEP_THRESHOLD = 15    # distinct ports in 30 seconds
PORT_SWEEP_WINDOW    = 30    # seconds

def check_port_sweep(session, src_ip: str, dst_port: int, on_alert=None):
    """
    Track unique ports probed per source IP.
    Fires 'port_sweep' alert when threshold exceeded.
    """
    sid = str(session.session_id)
    now = datetime.utcnow()
    cutoff = now - timedelta(seconds=PORT_SWEEP_WINDOW)

    with _lock:
        hits = _port_hits[sid][src_ip]
        # Prune old hits outside the window
        hits[:] = [(ts, p) for ts, p in hits if ts > cutoff]
        hits.append((now, dst_port))

        unique_ports = len({p for _, p in hits})
        if unique_ports >= PORT_SWEEP_THRESHOLD:
            alert = _save_alert(
                session, "port_sweep",
                src_ip   = src_ip,
                dst_ip   = "multiple",
                severity = "medium",
                message  = (
                    f"Port sweep detected from {src_ip}: "
                    f"{unique_ports} distinct ports in {PORT_SWEEP_WINDOW}s."
                )
            )
            hits.clear()   # reset to avoid alert storm
            if on_alert:
                on_alert(alert)


# ─────────────────────────────────────────────────────────────────────────────
# SYN flood signal detection
# ─────────────────────────────────────────────────────────────────────────────

SYN_FLOOD_THRESHOLD = 200   # SYNs to same port in 10s
SYN_FLOOD_WINDOW    = 10    # seconds

def check_syn_flood(session, dst_ip: str, dst_port: int, on_alert=None):
    """
    Track SYN packet rate to a single dst_port.
    Fires 'flood_detected' alert when SYN rate is abnormally high.
    """
    sid = str(session.session_id)
    now = datetime.utcnow()
    cutoff = now - timedelta(seconds=SYN_FLOOD_WINDOW)
    key = f"{dst_ip}:{dst_port}"

    with _lock:
        hits = _syn_hits[sid][key]
        hits[:] = [ts for ts in hits if ts > cutoff]
        hits.append(now)

        if len(hits) >= SYN_FLOOD_THRESHOLD:
            alert = _save_alert(
                session, "flood_detected",
                src_ip   = "multiple (spoofed)",
                dst_ip   = dst_ip,
                severity = "critical",
                message  = (
                    f"SYN flood detected targeting {dst_ip}:{dst_port} — "
                    f"{len(hits)} SYNs in {SYN_FLOOD_WINDOW}s."
                )
            )
            hits.clear()
            if on_alert:
                on_alert(alert)


# ─────────────────────────────────────────────────────────────────────────────
# Cleanup
# ─────────────────────────────────────────────────────────────────────────────

def clear_session(session_id: str):
    """Release detection state for a completed session."""
    with _lock:
        _arp_cache.pop(session_id, None)
        _port_hits.pop(session_id, None)
        _syn_hits.pop(session_id, None)
