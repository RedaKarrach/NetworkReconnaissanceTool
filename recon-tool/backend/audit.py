"""
Audit logging helper for scan/attack actions and alert generation.
"""
import json
from datetime import datetime

from models import AuditLog

ALLOWED_ACTIONS = {
    "scan_started",
    "scan_completed",
    "fingerprint_run",
    "attack_initiated",
    "alert_generated",
}

ALLOWED_STATUS = {"success", "failure"}


def _safe_json(payload):
    if payload is None:
        return "{}"
    if isinstance(payload, str):
        return payload
    try:
        return json.dumps(payload, default=str)
    except TypeError:
        return json.dumps({"value": str(payload)})


def audit_log(action, detail, status, duration_ms, initiated_by=None, error_message=None, metadata=None):
    if action not in ALLOWED_ACTIONS:
        raise ValueError(f"Unsupported audit action: {action}")
    if status not in ALLOWED_STATUS:
        raise ValueError(f"Unsupported audit status: {status}")

    actor = initiated_by or "admin"
    entry = AuditLog(
        action=action,
        action_detail=_safe_json(detail),
        initiated_by=str(actor),
        initiated_at=datetime.utcnow(),
        status=status,
        error_message=str(error_message) if error_message else None,
        duration_ms=int(duration_ms or 0),
        metadata=_safe_json(metadata),
    )
    entry.save()
    return entry
