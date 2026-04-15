"""
MongoEngine document models for storing all scan/attack data.
Django's built-in auth continues to use SQLite; all recon data goes to MongoDB.
"""
from mongoengine import (
    Document, StringField, IntField, FloatField,
    DateTimeField, ReferenceField, ListField
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
    banner      = StringField(default="")
    timestamp   = DateTimeField(default=datetime.utcnow)

    meta = {"collection": "port_results"}


class Alert(Document):
    """Security alert triggered by suspicious pattern detection."""
    session     = ReferenceField(ScanSession, required=True)
    type        = StringField()        # arp_anomaly | port_sweep | flood_detected
    src_ip      = StringField()
    dst_ip      = StringField()
    severity    = StringField(default="medium")    # low | medium | high | critical
    message     = StringField()
    timestamp   = DateTimeField(default=datetime.utcnow)

    meta = {"collection": "alerts"}


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

    meta = {"collection": "packet_logs"}


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

    meta = {"collection": "attack_logs"}
