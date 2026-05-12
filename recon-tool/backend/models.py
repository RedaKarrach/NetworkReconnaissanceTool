"""
MongoEngine document models for storing all scan/attack data.
Django's built-in auth continues to use SQLite; all recon data goes to MongoDB.
"""
from mongoengine import (
    Document, StringField, IntField, FloatField,
    DateTimeField, ReferenceField, ListField, DictField
)
from datetime import datetime


class ScanSession(Document):
    """Top-level container for a single recon session."""
    session_id  = StringField(required=True, unique=True)
    subnet      = StringField()
    status      = StringField(default="running")   # running | complete | stopped
    timestamp   = DateTimeField(default=datetime.utcnow)

    meta = {"collection": "scan_sessions"}


class Host(Document):
    """A live host discovered during ARP sweep or port scan."""
    session     = ReferenceField(ScanSession, required=True)
    ip          = StringField(required=True)
    mac         = StringField()
    os_guess    = StringField()
    confidence  = FloatField(default=0.0)
    hostname    = StringField()

    meta = {"collection": "hosts"}


class PortResult(Document):
    """Result of a single port probe on a host."""
    host        = ReferenceField(Host, required=True)
    port        = IntField(required=True)
    protocol    = StringField(default="tcp")       # tcp | udp
    status      = StringField(default="filtered")  # open | closed | filtered
    service     = StringField(default="")
    banner      = StringField(default="")
    timestamp   = DateTimeField(default=datetime.utcnow)

    meta = {"collection": "port_results"}


class HostRiskScore(Document):
    """Calculated risk score for a host IP based on observed signals."""
    ip                  = StringField(required=True)
    risky_port_count    = IntField(default=0)
    vulnerability_count = IntField(default=0)
    failed_login_count  = IntField(default=0)
    risk_score          = IntField(default=0)  # 0-100
    risk_level          = StringField(default="low", choices=("critical", "high", "medium", "low"))
    last_updated        = DateTimeField(default=datetime.utcnow)

    meta = {
        "collection": "host_risk_scores",
        "indexes": ["ip", "last_updated"],
    }


class Alert(Document):
    """Security alert triggered by suspicious pattern detection."""
    session     = ReferenceField(ScanSession, required=True)
    type        = StringField()        # arp_anomaly | port_sweep | flood_detected
    src_ip      = StringField()
    dst_ip      = StringField()
    severity    = StringField(default="medium")    # low | medium | high | critical
    message     = StringField()
    timestamp   = DateTimeField(default=datetime.utcnow)

    meta = {
        "collection": "alerts",
        "indexes": [
            "session",
            "timestamp",
            "type",
        ]
    }


class PacketLog(Document):
    """Raw packet summary logged during any scan or attack."""
    session     = ReferenceField(ScanSession, required=True)
    summary     = StringField()
    flags       = StringField()
    ttl         = IntField()
    src_ip      = StringField()
    dst_ip      = StringField()
    protocol    = StringField()
    payload     = StringField(default="")
    timestamp   = DateTimeField(default=datetime.utcnow)

    meta = {
        "collection": "packet_logs",
        "indexes": [
            "session",
            "timestamp",
            "src_ip",
            "dst_ip",
        ]
    }


class AttackLog(Document):
    """Record of a launched attack simulation."""
    session     = ReferenceField(ScanSession)
    attack_type = StringField()   # arp_spoof | syn_flood | icmp_redirect
    target_ip   = StringField()
    params      = StringField()   # JSON string of extra params
    status      = StringField(default="running")   # running | stopped
    packets_sent = IntField(default=0)
    started_at  = DateTimeField(default=datetime.utcnow)
    stopped_at  = DateTimeField()

    meta = {
        "collection": "attack_logs",
        "indexes": ["session", "attack_type", "target_ip", "started_at"],
    }


class AuditLog(Document):
    """Audit trail for scan/attack actions and alert generation."""
    action = StringField(
        required=True,
        choices=(
            "scan_started",
            "scan_completed",
            "fingerprint_run",
            "attack_initiated",
            "alert_generated",
        ),
    )
    action_detail = StringField(default="{}")
    initiated_by = StringField(default="admin")
    initiated_at = DateTimeField(default=datetime.utcnow)
    status = StringField(required=True, choices=("success", "failure"))
    error_message = StringField()
    duration_ms = IntField(default=0)
    metadata = StringField(default="{}")

    meta = {
        "collection": "audit_logs",
        "indexes": ["initiated_at", "action", "status"],
    }


class HostInventory(Document):
    """Inventory snapshot reported by a VM agent (Wazuh-like host data)."""
    agent_id     = StringField(required=True)
    hostname     = StringField()
    os_name      = StringField()
    os_version   = StringField()
    kernel       = StringField()
    arch         = StringField()
    domain       = StringField()
    ips          = ListField(StringField())
    macs         = ListField(StringField())
    interfaces   = ListField(DictField())
    cpu_model    = StringField()
    cpu_cores    = IntField()
    ram_mb       = IntField()
    disk_total_gb = FloatField()
    disk_free_gb  = FloatField()
    uptime_sec   = IntField()
    users        = ListField(StringField())
    packages     = ListField(StringField())
    services     = ListField(StringField())
    open_ports   = ListField(IntField())
    last_seen    = DateTimeField(default=datetime.utcnow)

    meta = {
        "collection": "host_inventory",
        "indexes": ["agent_id", "hostname", "last_seen"],
    }


class AgentRegistry(Document):
    """User-registered agents to visualize on the dashboard."""
    agent_id   = StringField(required=True, unique=True)
    hostname   = StringField()
    ip         = StringField()
    os_name    = StringField()
    notes      = StringField()
    last_seen  = DateTimeField()
    health_status = StringField(default="unknown")  # online | offline | unknown
    health_notified_at = DateTimeField()
    created_at = DateTimeField(default=datetime.utcnow)

    meta = {
        "collection": "agent_registry",
        "indexes": ["agent_id", "hostname", "ip", "created_at", "last_seen", "health_status"],
    }
