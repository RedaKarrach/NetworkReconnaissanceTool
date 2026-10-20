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


def _build_alert(type_, src_ip, dst_ip, severity, message):
    """Build an alert dict for the on_alert callback.

    Persistence, audit logging and de-dupe are the single responsibility of the
    emitter (api.views._emit_alert). The detection engine only *describes* what
    it saw; it never writes to MongoDB. This removes the old double/triple save.
    """
    return {
        "type":      type_,
        "src_ip":    src_ip,
        "dst_ip":    dst_ip,
        "severity":  severity,
        "message":   message,
        "timestamp": datetime.utcnow().isoformat(),
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
            alert = _build_alert(
                "arp_anomaly",
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

PORT_SWEEP_THRESHOLD = int(os.environ.get("IDS_SWEEP_THRESHOLD", "10"))   # distinct ports
PORT_SWEEP_WINDOW    = int(os.environ.get("IDS_SWEEP_WINDOW", "10"))      # seconds

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
            alert = _build_alert(
                "port_sweep",
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

SYN_FLOOD_THRESHOLD = int(os.environ.get("IDS_SYN_THRESHOLD", "200"))   # SYNs to same port
SYN_FLOOD_WINDOW    = int(os.environ.get("IDS_SYN_WINDOW", "10"))       # seconds

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
            alert = _build_alert(
                "flood_detected",
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
# Extended passive detection — windowed stores + many signatures
# ─────────────────────────────────────────────────────────────────────────────

# store -> sid -> key -> [(timestamp, value)]
_windows = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))


def _bump(store, sid, key, value, window):
    now = datetime.utcnow()
    cutoff = now - timedelta(seconds=window)
    bucket = _windows[store][sid][key]
    bucket[:] = [(t, v) for (t, v) in bucket if t > cutoff]
    bucket.append((now, value))
    return bucket


def _reset_window(store, sid, key):
    _windows[store].get(sid, {}).pop(key, None)


# Thresholds (env-tunable); windows in seconds.
GENERIC_WINDOW        = int(os.environ.get("IDS_GENERIC_WINDOW", "10"))
ICMP_FLOOD_THRESHOLD  = int(os.environ.get("IDS_ICMP_FLOOD_THRESHOLD", "100"))
PING_SWEEP_THRESHOLD  = int(os.environ.get("IDS_PING_SWEEP_THRESHOLD", "10"))
UDP_FLOOD_THRESHOLD   = int(os.environ.get("IDS_UDP_FLOOD_THRESHOLD", "200"))
HOST_SWEEP_THRESHOLD  = int(os.environ.get("IDS_HOST_SWEEP_THRESHOLD", "10"))
CONN_RATE_THRESHOLD   = int(os.environ.get("IDS_CONN_RATE_THRESHOLD", "300"))
DNS_QUERY_THRESHOLD   = int(os.environ.get("IDS_DNS_THRESHOLD", "100"))

# Sensitive services → (label, severity) flagged on connection attempts.
SENSITIVE_PORTS = {
    21: ("FTP", "medium"), 23: ("Telnet", "high"), 25: ("SMTP", "low"),
    69: ("TFTP", "medium"), 110: ("POP3", "low"), 135: ("MSRPC", "medium"),
    139: ("NetBIOS", "medium"), 143: ("IMAP", "low"), 161: ("SNMP", "medium"),
    389: ("LDAP", "medium"), 445: ("SMB", "high"), 512: ("rexec", "high"),
    513: ("rlogin", "high"), 514: ("rsh/syslog", "medium"), 1433: ("MSSQL", "medium"),
    1521: ("Oracle", "medium"), 2049: ("NFS", "medium"), 3306: ("MySQL", "medium"),
    3389: ("RDP", "high"), 5432: ("PostgreSQL", "medium"), 5900: ("VNC", "high"),
    6379: ("Redis", "high"), 9200: ("Elasticsearch", "medium"),
    11211: ("Memcached", "medium"), 27017: ("MongoDB", "high"),
}

_TCP_FLAG_ALIASES = {
    "SYN": "S", "ACK": "A", "FIN": "F", "RST": "R", "PSH": "P",
    "URG": "U", "ECE": "E", "CWR": "C", "NS": "N",
}


def _normalize_flags(flags) -> frozenset:
    """Normalize a TCP flags string to a set of single-letter flags."""
    raw = str(flags or "").upper()
    out = set()
    for tok in re.split(r"[\s,\-/|+]+", raw):
        tok = tok.strip()
        if not tok:
            continue
        if tok in _TCP_FLAG_ALIASES:
            out.add(_TCP_FLAG_ALIASES[tok])
        elif len(tok) <= 4 and set(tok) <= set("SAFRPUECN"):
            out.update(tok)          # e.g. "SA", "FPU"
    return frozenset(out)


def _extract_dst_port(pkt, summary):
    for k in ("dst_port", "dport", "dstport"):
        try:
            iv = int(pkt.get(k))
            if 0 < iv <= 65535:
                return iv
        except (TypeError, ValueError):
            pass
    m = re.search(r":(\d{1,5})(?:\D|$)", summary) or re.search(r"port\s+(\d{1,5})", summary, re.IGNORECASE)
    if m:
        iv = int(m.group(1))
        if 0 < iv <= 65535:
            return iv
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# Unified packet engine
# ─────────────────────────────────────────────────────────────────────────────

def process_packet(session, pkt: dict, on_alert=None):
    """Single entry point for passive detection on an observed packet.

    Inspects one observed packet and raises any of a broad set of signatures.
    Per-signature de-dupe/cooldown is handled by the emitter (api._emit_alert),
    so detectors may fire freely. Scan-type alerts use dst_ip="multiple" so the
    cooldown collapses them into one alert per source per window.
    """
    sid = str(session.session_id)
    proto = str(pkt.get("protocol", "")).upper()
    flags_raw = pkt.get("flags", "")
    summary = str(pkt.get("summary", ""))
    src_ip = str(pkt.get("src_ip", "") or "")
    dst_ip = str(pkt.get("dst_ip", "") or "")

    def emit(alert):
        if on_alert:
            on_alert(alert)

    # LAND attack: identical source and destination.
    if src_ip and src_ip == dst_ip:
        emit(_build_alert("land_attack", src_ip=src_ip, dst_ip=dst_ip, severity="high",
                          message=f"LAND attack: packet with identical src and dst {src_ip}"))

    # Generic high packet-rate from one source (any protocol).
    if src_ip:
        with _lock:
            n = len(_bump("conn", sid, src_ip, 1, GENERIC_WINDOW))
            if n >= CONN_RATE_THRESHOLD:
                _reset_window("conn", sid, src_ip)
            else:
                n = 0
        if n:
            emit(_build_alert("connection_flood", src_ip=src_ip, dst_ip="multiple", severity="high",
                              message=f"High packet rate from {src_ip}: {n} packets in {GENERIC_WINDOW}s"))

    if proto == "ARP":
        if "is at" in summary.lower() and src_ip:
            mac_match = re.search(r"is\s+at\s+([0-9a-fA-F:]{11,17})", summary)
            if mac_match:
                check_arp(session, ip=src_ip, mac=mac_match.group(1), on_alert=on_alert)

    elif proto == "TCP":
        fset = _normalize_flags(flags_raw)
        dst_port = _extract_dst_port(pkt, summary)

        # Stealth / malformed-flag scans.
        kind = None
        if len(fset) == 0:
            kind = "NULL"
        elif fset == frozenset({"F"}):
            kind = "FIN"
        elif fset == frozenset({"F", "P", "U"}):
            kind = "XMAS"
        elif "S" in fset and "F" in fset:
            kind = "SYN-FIN"
        elif fset in (frozenset({"F", "U"}), frozenset({"P", "U"}), frozenset({"U"})):
            kind = "unusual-flag"
        if kind and src_ip:
            emit(_build_alert("stealth_scan", src_ip=src_ip, dst_ip="multiple", severity="medium",
                              message=f"{kind} scan flags from {src_ip}"
                                      + (f" (port {dst_port})" if dst_port else "")))

        syn_only = fset == frozenset({"S"})
        if syn_only and dst_port:
            check_syn_flood(session, dst_ip=dst_ip or "unknown", dst_port=dst_port, on_alert=on_alert)
            check_port_sweep(session, src_ip=src_ip or "unknown", dst_port=dst_port, on_alert=on_alert)

        # RST flood.
        if fset == frozenset({"R"}) and (dst_ip or src_ip):
            key = dst_ip or src_ip
            with _lock:
                n = len(_bump("rst", sid, key, 1, GENERIC_WINDOW))
                if n >= CONN_RATE_THRESHOLD:
                    _reset_window("rst", sid, key)
                else:
                    n = 0
            if n:
                emit(_build_alert("rst_flood", src_ip=src_ip or "multiple", dst_ip=dst_ip or "multiple",
                                  severity="medium", message=f"RST flood: {n} RST packets in {GENERIC_WINDOW}s"))

        # Horizontal host sweep (one source, many distinct destinations).
        if src_ip and dst_ip:
            with _lock:
                distinct = len({v for _, v in _bump("hostsweep", sid, src_ip, dst_ip, GENERIC_WINDOW)})
                if distinct >= HOST_SWEEP_THRESHOLD:
                    _reset_window("hostsweep", sid, src_ip)
                else:
                    distinct = 0
            if distinct:
                emit(_build_alert("host_sweep", src_ip=src_ip, dst_ip="multiple", severity="medium",
                                  message=f"Host sweep from {src_ip}: {distinct} distinct hosts in {GENERIC_WINDOW}s"))

        # Connection attempt to a sensitive service (SYN without ACK).
        if dst_port in SENSITIVE_PORTS and src_ip and ("S" in fset and "A" not in fset):
            svc, sev = SENSITIVE_PORTS[dst_port]
            emit(_build_alert("suspicious_port_access", src_ip=src_ip, dst_ip=dst_ip or "unknown",
                              severity=sev, message=f"Connection to sensitive service {svc} (TCP {dst_port}) on {dst_ip or 'host'}"))

    elif proto == "UDP":
        dst_port = _extract_dst_port(pkt, summary)
        if dst_ip:
            key = f"{dst_ip}:{dst_port}"
            with _lock:
                n = len(_bump("udp", sid, key, 1, GENERIC_WINDOW))
                if n >= UDP_FLOOD_THRESHOLD:
                    _reset_window("udp", sid, key)
                else:
                    n = 0
            if n:
                emit(_build_alert("udp_flood", src_ip=src_ip or "multiple", dst_ip=dst_ip, severity="high",
                                  message=f"UDP flood targeting {key}: {n} datagrams in {GENERIC_WINDOW}s"))

        if dst_port == 53 and src_ip:
            with _lock:
                n = len(_bump("dns", sid, src_ip, 1, GENERIC_WINDOW))
                if n >= DNS_QUERY_THRESHOLD:
                    _reset_window("dns", sid, src_ip)
                else:
                    n = 0
            if n:
                emit(_build_alert("dns_anomaly", src_ip=src_ip, dst_ip=dst_ip or "unknown", severity="medium",
                                  message=f"Excessive DNS from {src_ip}: {n} queries in {GENERIC_WINDOW}s (possible tunneling/exfil)"))

        if dst_port in SENSITIVE_PORTS and src_ip:
            svc, sev = SENSITIVE_PORTS[dst_port]
            emit(_build_alert("suspicious_port_access", src_ip=src_ip, dst_ip=dst_ip or "unknown",
                              severity=sev, message=f"Traffic to sensitive service {svc} (UDP {dst_port})"))

    elif proto == "ICMP":
        try:
            icmp_type = int(pkt.get("icmp_type"))
        except (TypeError, ValueError):
            icmp_type = None
        low = summary.lower()

        if "REDIRECT" in str(flags_raw).upper() or icmp_type == 5 or "redirect" in low:
            emit(_build_alert("icmp_redirect", src_ip=src_ip or "unknown", dst_ip=dst_ip or "unknown",
                              severity="high", message=f"ICMP redirect detected from {src_ip} to {dst_ip}"))

        if (icmp_type == 8 or "echo-request" in low or "echo request" in low) and src_ip and dst_ip:
            with _lock:
                distinct = len({v for _, v in _bump("pingsweep", sid, src_ip, dst_ip, GENERIC_WINDOW)})
                if distinct >= PING_SWEEP_THRESHOLD:
                    _reset_window("pingsweep", sid, src_ip)
                else:
                    distinct = 0
            if distinct:
                emit(_build_alert("ping_sweep", src_ip=src_ip, dst_ip="multiple", severity="medium",
                                  message=f"ICMP ping sweep from {src_ip}: {distinct} hosts in {GENERIC_WINDOW}s"))

        if dst_ip:
            with _lock:
                n = len(_bump("icmp", sid, dst_ip, 1, GENERIC_WINDOW))
                if n >= ICMP_FLOOD_THRESHOLD:
                    _reset_window("icmp", sid, dst_ip)
                else:
                    n = 0
            if n:
                emit(_build_alert("icmp_flood", src_ip=src_ip or "multiple", dst_ip=dst_ip, severity="high",
                                  message=f"ICMP flood targeting {dst_ip}: {n} packets in {GENERIC_WINDOW}s"))


# ─────────────────────────────────────────────────────────────────────────────
# Cleanup
# ─────────────────────────────────────────────────────────────────────────────

def clear_session(session_id: str):
    """Release detection state for a completed session."""
    with _lock:
        _arp_cache.pop(session_id, None)
        _port_hits.pop(session_id, None)
        _syn_hits.pop(session_id, None)
        for store in list(_windows.keys()):
            _windows[store].pop(session_id, None)
