"""
recon-tool ML package
=====================
Classic machine learning for the SOC dashboard (no deep learning):

- features.py  — turn the live packet stream into per-source flow features
- train.py     — train a supervised classifier on CIC-IDS2017 (RandomForest /
                 GradientBoosting / optional XGBoost)
- anomaly.py   — unsupervised IsolationForest for novel-attack detection
- triage.py    — alert deduplication, clustering and priority scoring
- engine.py    — load artifacts, score live flows, emit ml_alert events

The supervised and unsupervised models share one feature schema (FEATURE_NAMES
in features.py) so the same vectors flow from training to live scoring.
"""

__all__ = ["features", "anomaly", "triage", "engine"]
