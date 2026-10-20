"""
ml/anomaly.py
-------------
Unsupervised novelty detection with IsolationForest (classic ML).

Scores live flow-feature vectors; a score below the configured threshold is
flagged as anomalous (possible novel / zero-day behaviour the supervised model
has not seen). sklearn/joblib are imported lazily so importing this module never
breaks the backend when ML is disabled.
"""
import os

ARTIFACTS_DIR = os.path.join(os.path.dirname(__file__), "artifacts")
IFOREST_PATH = os.path.join(ARTIFACTS_DIR, "isolation_forest.joblib")


class AnomalyDetector:
    def __init__(self, model=None, scaler=None, threshold: float = 0.0):
        self.model = model
        self.scaler = scaler
        # decision_function > 0 is inlier; < threshold is anomalous.
        self.threshold = float(threshold)

    @property
    def ready(self) -> bool:
        return self.model is not None

    @classmethod
    def load(cls, path: str = IFOREST_PATH, scaler=None,
             threshold: float = None):
        try:
            import joblib
        except Exception:
            return cls(None, None)
        if not os.path.exists(path):
            return cls(None, None)
        try:
            bundle = joblib.load(path)
        except Exception:
            return cls(None, None)
        model = bundle.get("model") if isinstance(bundle, dict) else bundle
        sc = scaler if scaler is not None else (bundle.get("scaler") if isinstance(bundle, dict) else None)
        thr = threshold
        if thr is None:
            thr = bundle.get("threshold", 0.0) if isinstance(bundle, dict) else 0.0
        return cls(model, sc, thr)

    def score(self, features):
        """Return (is_anomaly, anomaly_score). Higher score = more anomalous."""
        if not self.ready:
            return (False, 0.0)
        try:
            import numpy as np
            x = np.asarray(features, dtype=float).reshape(1, -1)
            if self.scaler is not None:
                x = self.scaler.transform(x)
            # decision_function: positive = normal, negative = anomaly.
            df = float(self.model.decision_function(x)[0])
            is_anom = df < self.threshold
            # Normalize to a 0..1-ish anomaly score for display.
            anomaly_score = max(0.0, min(1.0, 0.5 - df))
            return (bool(is_anom), anomaly_score)
        except Exception:
            return (False, 0.0)


def train_isolation_forest(X, contamination: float = 0.02, random_state: int = 42):
    """Fit an IsolationForest on benign-leaning feature rows. Returns the model."""
    from sklearn.ensemble import IsolationForest
    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,
    )
    model.fit(X)
    return model
