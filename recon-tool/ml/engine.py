"""
ml/engine.py
------------
Live ML scoring engine.

Loads a supervised classifier (+ scaler) and an IsolationForest from
ml/artifacts/, consumes the live packet stream through a FlowAggregator, and
emits ml_alert events for flows the model flags with high confidence (or that
the anomaly detector marks as novel). Results pass through AlertTriage to get a
priority score.

Everything degrades gracefully:
  - ML_ENABLED=false            → engine is inert (feed() is a no-op)
  - artifacts missing           → no ml_alerts, no crash
  - sklearn/numpy not installed → no ml_alerts, no crash

The engine is framework-agnostic: it takes an `on_ml_alert(dict)` callback so
the Django layer can wire it to broadcast_ml_alert without ml/ importing Django.
"""
import os
import threading
import time

from .features import FEATURE_NAMES, FlowAggregator
from .anomaly import AnomalyDetector
from .triage import AlertTriage

ARTIFACTS_DIR = os.path.join(os.path.dirname(__file__), "artifacts")
CLASSIFIER_PATH = os.path.join(ARTIFACTS_DIR, "classifier.joblib")

BENIGN_LABELS = {"benign", "normal", "0", "0.0"}


def _env_float(name, default):
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return float(default)


def _env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return int(default)


def _severity_for(confidence: float, label: str) -> str:
    if confidence >= 0.9:
        return "critical"
    if confidence >= 0.8:
        return "high"
    if confidence >= 0.65:
        return "medium"
    return "low"


class MLEngine:
    def __init__(self, on_ml_alert=None):
        self.on_ml_alert = on_ml_alert
        self.enabled = os.environ.get("ML_ENABLED", "false").strip().lower() in {"1", "true", "yes"}
        self.confidence_threshold = _env_float("ML_CONFIDENCE_THRESHOLD", 0.7)
        self.score_interval = _env_float("ML_SCORE_INTERVAL", 2.0)
        self.min_packets = _env_int("ML_MIN_PACKETS", 20)
        self.window_seconds = _env_float("ML_WINDOW_SECONDS", 10.0)

        self.model = None
        self.scaler = None
        self.classes_ = None
        self.model_version = "none"
        self.feature_importances_ = None

        self.agg = FlowAggregator(window_seconds=self.window_seconds)
        self.anomaly = AnomalyDetector()
        self.triage = AlertTriage(cooldown_seconds=_env_float("ML_TRIAGE_COOLDOWN", 10.0))

        self._lock = threading.Lock()
        self._last_score = 0.0
        self._loaded = False

        if self.enabled:
            self._load_artifacts()

    # ── artifact loading ────────────────────────────────────────────────
    def _load_artifacts(self):
        if self._loaded:
            return
        self._loaded = True
        try:
            import joblib  # noqa: F401
        except Exception:
            print("[ml.engine] joblib/sklearn not installed — ML scoring disabled")
            return

        if os.path.exists(CLASSIFIER_PATH):
            try:
                import joblib
                bundle = joblib.load(CLASSIFIER_PATH)
                self.model = bundle.get("model")
                self.scaler = bundle.get("scaler")
                self.classes_ = list(getattr(self.model, "classes_", bundle.get("classes", [])))
                self.model_version = bundle.get("model_version", "unknown")
                self.feature_importances_ = getattr(self.model, "feature_importances_", None)
                print(f"[ml.engine] loaded classifier {self.model_version}")
            except Exception as exc:
                print(f"[ml.engine] failed to load classifier: {exc}")
        else:
            print("[ml.engine] no classifier artifact — supervised scoring off")

        self.anomaly = AnomalyDetector.load(scaler=self.scaler)
        if self.anomaly.ready:
            print("[ml.engine] loaded IsolationForest anomaly model")

    @property
    def active(self) -> bool:
        """True when enabled and at least one model is available."""
        return self.enabled and (self.model is not None or self.anomaly.ready)

    # ── live path ───────────────────────────────────────────────────────
    def feed(self, pkt: dict, host_risk_lookup=None):
        """Ingest one observed packet; periodically score ready sources."""
        if not self.active:
            return
        try:
            self.agg.add(pkt)
        except Exception:
            return

        now = time.monotonic()
        if (now - self._last_score) < self.score_interval:
            return
        if not self._lock.acquire(blocking=False):
            return
        try:
            self._last_score = now
            for src_ip in self.agg.ready_sources(min_packets=self.min_packets):
                self._score_source(src_ip, host_risk_lookup)
        finally:
            self._lock.release()

    def _top_features(self, features, k=3):
        if self.feature_importances_ is None:
            return []
        try:
            pairs = list(zip(FEATURE_NAMES, self.feature_importances_))
            pairs.sort(key=lambda p: p[1], reverse=True)
            return [name for name, _ in pairs[:k]]
        except Exception:
            return []

    def _score_source(self, src_ip, host_risk_lookup=None):
        features = self.agg.features_for(src_ip)
        if not features:
            return

        label = None
        confidence = 0.0

        if self.model is not None:
            try:
                import numpy as np
                x = np.asarray(features, dtype=float).reshape(1, -1)
                if self.scaler is not None:
                    x = self.scaler.transform(x)
                if hasattr(self.model, "predict_proba"):
                    proba = self.model.predict_proba(x)[0]
                    idx = int(proba.argmax())
                    confidence = float(proba[idx])
                    label = str(self.classes_[idx]) if self.classes_ else str(idx)
                else:
                    label = str(self.model.predict(x)[0])
                    confidence = 1.0
            except Exception:
                label = None

        emit = None
        if label is not None and str(label).lower() not in BENIGN_LABELS and confidence >= self.confidence_threshold:
            emit = {
                "label": label,
                "confidence": round(confidence, 3),
                "model_version": self.model_version,
            }
        else:
            is_anom, anom_score = self.anomaly.score(features)
            if is_anom:
                emit = {
                    "label": "anomaly",
                    "confidence": round(anom_score, 3),
                    "model_version": "isolation_forest",
                }

        if not emit:
            return

        host_risk = 0.0
        if host_risk_lookup:
            try:
                host_risk = float(host_risk_lookup(src_ip) or 0.0)
            except Exception:
                host_risk = 0.0

        severity = _severity_for(emit["confidence"], emit["label"])
        alert = {
            "type": f"ml_{emit['label']}".lower().replace(" ", "_"),
            "label": emit["label"],
            "confidence": emit["confidence"],
            "model_version": emit["model_version"],
            "src_ip": src_ip,
            "dst_ip": "multiple",
            "severity": severity,
            "message": (
                f"ML flagged {src_ip} as {emit['label']} "
                f"(confidence {emit['confidence']:.0%}, model {emit['model_version']})"
            ),
            "top_features": self._top_features(features),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        enriched = self.triage.update(alert, host_risk=host_risk)
        if enriched.get("is_duplicate"):
            return
        if self.on_ml_alert:
            try:
                self.on_ml_alert(enriched)
            except Exception:
                pass


# Module-level singleton.
_engine = None
_engine_lock = threading.Lock()


def get_engine(on_ml_alert=None):
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = MLEngine(on_ml_alert=on_ml_alert)
        elif on_ml_alert is not None and _engine.on_ml_alert is None:
            _engine.on_ml_alert = on_ml_alert
        return _engine
