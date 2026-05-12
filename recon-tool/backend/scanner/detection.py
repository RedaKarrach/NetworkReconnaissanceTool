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
import json
import os
import re
import threading
from datetime import datetime, timedelta
from collections import defaultdict

from mongoengine import Q

from models import Alert, Host, PortResult, HostRiskScore
from audit import audit_log


# Per-session state stores (cleared on session end)
_arp_cache   = defaultdict(dict)          # session → { ip: mac }
_port_hits   = defaultdict(lambda: defaultdict(list))  # session → { src_ip: [timestamps] }
_syn_hits    = defaultdict(lambda: defaultdict(list))  # session → { dst_port: [timestamps] }
_lock        = threading.Lock()

_MITRE_MAPPING_CACHE = None
_MITRE_MAPPING_PATH = os.path.join(os.path.dirname(__file__), "mitre_mapping.json")

RISKY_PORTS = {
    21: "ftp",
    23: "telnet",
    445: "smb",
    3389: "rdp",
    6379: "redis",
    5984: "couchdb",
    27017: "mongodb",
    9200: "elasticsearch",
}

SERVICE_VULN_LABELS = {
    "ftp": "FTP service exposed",
    "telnet": "Telnet service exposed",
    "smb": "SMB service exposed",
    "rdp": "RDP service exposed",
    "redis": "Redis service exposed",
    "couchdb": "CouchDB service exposed",
    "mongodb": "MongoDB service exposed",
    "elasticsearch": "Elasticsearch service exposed",
}

AUTH_ALERT_TYPES = {
    "auth_failed",
    "login_failed",
    "failed_login",
    "authentication_failed",
    "bruteforce_login",
    "ssh_bruteforce",
    "rdp_bruteforce",
}

AUTH_ALERT_KEYWORDS = [
    "failed login",
    "authentication failed",
    "invalid password",
    "brute force",
    "login failure",
    "auth failure",
]


def _load_mitre_mapping():
    global _MITRE_MAPPING_CACHE
    if _MITRE_MAPPING_CACHE is not None:
        return _MITRE_MAPPING_CACHE

    try:
        with open(_MITRE_MAPPING_PATH, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except Exception:
        data = {"version": 1, "mappings": []}

    if not isinstance(data, dict):
        data = {"version": 1, "mappings": []}
    if not isinstance(data.get("mappings"), list):
        data["mappings"] = []

    _MITRE_MAPPING_CACHE = data
    return data


def get_mitre_mapping():
    return _load_mitre_mapping()


def _match_mitre_mapping(text, mapping):
    patterns = mapping.get("patterns") or []
    pattern_type = str(mapping.get("pattern_type", "regex")).lower()

    if pattern_type == "keyword":
        lowered = text.lower()
        for pattern in patterns:
            if str(pattern).lower() in lowered:
                return True
        return False

    for pattern in patterns:
        try:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


def enrich_alert_with_mitre(alert: dict):
    if not isinstance(alert, dict):
        return alert
    if alert.get("mitre_tactic_id") or alert.get("mitre_technique_id"):
        return alert

    text = f"{alert.get('type', '')} {alert.get('message', '')}".strip()
    if not text:
        return alert

    mapping_doc = _load_mitre_mapping()
    for mapping in mapping_doc.get("mappings", []):
        if _match_mitre_mapping(text, mapping):
            enriched = dict(alert)
            enriched.update({
                "mitre_tactic": mapping.get("tactic", ""),
                "mitre_tactic_id": mapping.get("tactic_id", ""),
                "mitre_technique": mapping.get("technique", ""),
                "mitre_technique_id": mapping.get("technique_id", ""),
            })
            return enriched

    return alert


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
    try:
        audit_log(
            "alert_generated",
            {
                "alert_type": type_,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "severity": severity,
                "message": message,
            },
            "success",
            0,
            metadata={"session_id": str(session.session_id)},
        )
    except Exception:
        pass
    return {
        "type":      type_,
        "src_ip":    src_ip,
        "dst_ip":    dst_ip,
        "severity":  severity,
        "message":   message,
        "timestamp": a.timestamp.isoformat(),
    }


def is_auth_alert_payload(alert: dict) -> bool:
    if not isinstance(alert, dict):
        return False
    type_ = str(alert.get("type", "")).lower().strip()
    message = str(alert.get("message", "")).lower()
    if type_ in AUTH_ALERT_TYPES:
        return True
    return any(keyword in message for keyword in AUTH_ALERT_KEYWORDS)


def _risk_level_for_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _summarize_vulns(port_results):
    vulns = []
    seen = set()

    for result in port_results:
        port = int(result.port) if result.port is not None else None
        if port in RISKY_PORTS:
            label = SERVICE_VULN_LABELS.get(RISKY_PORTS[port])
            key = f"port:{port}"
            if label and key not in seen:
                vulns.append(label)
                seen.add(key)

        service = str(result.service or "").lower()
        banner = str(result.banner or "").lower()
        combined = f"{service} {banner}".strip()
        for service_name, label in SERVICE_VULN_LABELS.items():
            if service_name in combined:
                key = f"service:{service_name}"
                if key not in seen:
                    vulns.append(label)
                    seen.add(key)

    return vulns


def calculate_host_risk(ip: str, include_breakdown: bool = False) -> dict:
    ip = str(ip or "").strip()
    if not ip:
        return {"risk_score": 0, "risk_level": "low"}

    hosts = Host.objects(ip=ip)
    port_results = PortResult.objects(host__in=hosts, status="open") if hosts else []

    open_ports = sorted({int(res.port) for res in port_results if res.port is not None})
    risky_ports = [port for port in open_ports if port in RISKY_PORTS]
    risky_port_count = len(risky_ports)

    vulns = _summarize_vulns(port_results)
    vulnerability_count = len(vulns)

    cutoff = datetime.utcnow() - timedelta(hours=24)
    auth_query = Q(type__in=list(AUTH_ALERT_TYPES))
    for keyword in AUTH_ALERT_KEYWORDS:
        auth_query |= Q(message__icontains=keyword)
    ip_query = Q(src_ip=ip) | Q(dst_ip=ip)

    failed_login_count = Alert.objects(ip_query & auth_query & Q(timestamp__gte=cutoff)).count()

    risk_score = min(100, (risky_port_count * 10) + (vulnerability_count * 5) + (failed_login_count * 2))
    risk_level = _risk_level_for_score(risk_score)

    record = HostRiskScore.objects(ip=ip).first()
    if not record:
        record = HostRiskScore(ip=ip)

    record.risky_port_count = risky_port_count
    record.vulnerability_count = vulnerability_count
    record.failed_login_count = failed_login_count
    record.risk_score = int(risk_score)
    record.risk_level = risk_level
    record.last_updated = datetime.utcnow()
    record.save()

    payload = {"risk_score": int(risk_score), "risk_level": risk_level}
    if include_breakdown:
        payload["breakdown"] = {
            "risky_ports": risky_ports,
            "vulns": vulns,
            "failed_logins": failed_login_count,
        }
    return payload


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

PORT_SWEEP_THRESHOLD = 3     # distinct ports in 10 seconds
PORT_SWEEP_WINDOW    = 10    # seconds

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
