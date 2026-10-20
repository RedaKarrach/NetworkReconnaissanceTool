"""
backend/ml_bridge.py
--------------------
Bridges the sibling `recon-tool/ml` package into the Django backend.

- Puts the repo root on sys.path so `import ml.engine` resolves (ml/ lives next
  to backend/, not inside it).
- Lazily builds the ML engine singleton with a callback that broadcasts
  ml_alert events over the existing websocket pipeline and persists them.
- Everything is best-effort: if ML_ENABLED is off, the ml package is missing,
  or sklearn/artifacts are absent, feed_packet() is a cheap no-op.
"""
import os
import sys
import threading

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # .../recon-tool
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

_engine = None
_init_attempted = False
_lock = threading.Lock()


def _host_risk(src_ip):
    """Light host-risk lookup (0..100) for triage; no recompute/save."""
    try:
        from models import HostRiskScore
        rec = HostRiskScore.objects(ip=src_ip).first()
        return float(rec.risk_score) if rec else 0.0
    except Exception:
        return 0.0


def _on_ml_alert(alert: dict):
    """Broadcast an ml_alert over the live stream and persist it for history."""
    try:
        from websockets.consumers import broadcast_ml_alert
        broadcast_ml_alert("live", alert)
    except Exception:
        pass
    try:
        from models import Alert, ScanSession
        live = ScanSession.objects(session_id="live").first()
        if not live:
            live = ScanSession(session_id="live", subnet="", status="running")
            live.save()
        Alert(
            session=live,
            type=alert.get("type", "ml_alert"),
            src_ip=alert.get("src_ip", ""),
            dst_ip=alert.get("dst_ip", ""),
            severity=alert.get("severity", "medium"),
            message=alert.get("message", ""),
        ).save()
    except Exception:
        pass


def _get_engine():
    global _engine, _init_attempted
    if _engine is not None or _init_attempted:
        return _engine
    with _lock:
        if _engine is not None or _init_attempted:
            return _engine
        _init_attempted = True
        try:
            from ml.engine import get_engine
            _engine = get_engine(on_ml_alert=_on_ml_alert)
        except Exception as exc:
            print(f"[ml_bridge] ML engine unavailable: {exc}")
            _engine = None
        return _engine


def is_active() -> bool:
    eng = _get_engine()
    return bool(eng and getattr(eng, "active", False))


def feed_packet(pkt: dict):
    """Feed one observed packet to the ML engine (no-op when inactive)."""
    eng = _get_engine()
    if not eng or not getattr(eng, "active", False):
        return
    try:
        eng.feed(pkt, host_risk_lookup=_host_risk)
    except Exception:
        pass
