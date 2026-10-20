"""
ml/triage.py
------------
Alert triage & prioritization.

Deduplicates/clusters incoming alerts and computes a priority score so real
threats surface above lifecycle noise. Pure-Python (no ML libs) so it runs
anywhere the backend runs.

priority = w1*severity + w2*model_confidence + w3*host_risk + w4*frequency
clamped to 0..100, with a small recency boost.
"""
import time
from collections import defaultdict

SEVERITY_WEIGHT = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.5,
    "low": 0.25,
    "info": 0.1,
}

# Scoring weights (sum ~1.0 before scaling to 100).
W_SEVERITY = 40.0
W_CONFIDENCE = 25.0
W_HOST_RISK = 20.0
W_FREQUENCY = 15.0

# A cluster key groups near-duplicate alerts.
def cluster_key(alert: dict) -> str:
    return "|".join([
        str(alert.get("type", "")).lower(),
        str(alert.get("src_ip", "")),
        str(alert.get("dst_ip", "")),
    ])


class AlertTriage:
    """Stateful triage over a stream of alerts.

    - update(alert) returns an enriched dict with {cluster_key, count,
      priority, first_seen, last_seen}.
    - ranked() returns current clusters sorted by priority desc.
    """

    def __init__(self, cooldown_seconds: float = 10.0):
        self.cooldown = float(cooldown_seconds)
        # cluster_key -> aggregate record
        self._clusters = {}

    @staticmethod
    def _severity_score(severity: str) -> float:
        return SEVERITY_WEIGHT.get(str(severity or "").lower(), 0.3)

    def compute_priority(self, severity, confidence, host_risk, frequency):
        sev = self._severity_score(severity)
        conf = max(0.0, min(1.0, float(confidence or 0.0)))
        risk = max(0.0, min(1.0, float(host_risk or 0.0) / 100.0))
        # Frequency saturates: log-ish via capped ratio.
        freq = min(1.0, float(frequency or 1) / 10.0)
        score = (W_SEVERITY * sev + W_CONFIDENCE * conf +
                 W_HOST_RISK * risk + W_FREQUENCY * freq)
        return int(max(0, min(100, round(score))))

    def update(self, alert: dict, host_risk: float = 0.0):
        key = cluster_key(alert)
        now = time.time()
        confidence = float(alert.get("confidence", 0.0) or 0.0)

        rec = self._clusters.get(key)
        if rec is None:
            rec = {
                "cluster_key": key,
                "type": alert.get("type"),
                "src_ip": alert.get("src_ip"),
                "dst_ip": alert.get("dst_ip"),
                "severity": alert.get("severity", "medium"),
                "count": 0,
                "first_seen": now,
                "last_seen": now,
                "max_confidence": confidence,
            }
            self._clusters[key] = rec

        rec["count"] += 1
        rec["last_seen"] = now
        rec["max_confidence"] = max(rec["max_confidence"], confidence)
        # Escalate stored severity to the highest seen.
        if self._severity_score(alert.get("severity")) > self._severity_score(rec["severity"]):
            rec["severity"] = alert.get("severity")

        rec["host_risk"] = host_risk
        rec["priority"] = self.compute_priority(
            rec["severity"], rec["max_confidence"], host_risk, rec["count"]
        )

        is_duplicate = (rec["count"] > 1) and ((now - rec["first_seen"]) < self.cooldown)
        enriched = dict(alert)
        enriched.update({
            "cluster_key": key,
            "count": rec["count"],
            "priority": rec["priority"],
            "is_duplicate": is_duplicate,
        })
        return enriched

    def ranked(self, limit: int = 50):
        items = sorted(self._clusters.values(), key=lambda r: r["priority"], reverse=True)
        return items[:limit]

    def clear(self):
        self._clusters.clear()
