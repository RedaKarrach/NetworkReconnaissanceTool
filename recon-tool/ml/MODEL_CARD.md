# Model Card — SOC flow classifier + anomaly detector

## Overview

Two classic-ML models support the SOC dashboard:

1. **Supervised classifier** — RandomForest (default; GradientBoosting or
   XGBoost selectable) that labels a network flow as benign or an attack class.
2. **Unsupervised anomaly detector** — IsolationForest that flags novel flows
   the classifier has not seen.

Both consume the same 9-feature vector (`ml/features.py:FEATURE_NAMES`) so the
offline-trained models score the live packet stream unchanged. **No deep
learning is used.**

## Intended use

- Authorized academic lab only: a network recon + SOC/NIDS teaching tool.
- Decision support that surfaces suspicious sources for a human analyst.
- **Not** for production security enforcement or unattended blocking.

## Features

| # | Feature | Meaning |
|---|---------|---------|
| 1 | `packets_per_s` | packet rate over the window |
| 2 | `syn_ratio` | fraction of SYN-only packets (scan/flood signal) |
| 3 | `unique_dst_ports` | distinct destination ports (sweep signal) |
| 4 | `mean_pkt_size` | mean packet size (bytes) |
| 5 | `std_pkt_size` | packet-size variability |
| 6 | `dst_port_entropy` | spread of destination ports |
| 7 | `flow_duration` | window span (seconds) |
| 8 | `total_bytes` | bytes in the window |
| 9 | `total_packets` | packets in the window |

Live features come from `FlowAggregator` (sliding window per source IP).
Training features come from CIC-IDS2017 flow columns via
`cic_row_to_features`.

## Training data

- CIC-IDS2017 (University of New Brunswick). Not committed; see
  `ml/datasets/README.md`.
- Benign + multiple attack families (DoS/DDoS, PortScan, brute force, web, etc.).

## Metrics

Reported by `train.py` on a held-out split and written to
`ml/artifacts/metrics.json`: accuracy, macro precision / recall / F1, per-class
report, confusion matrix, and macro one-vs-rest ROC-AUC. Fill the table below
after training on your machine:

| Metric | Value |
|--------|-------|
| Accuracy | _tbd_ |
| Precision (macro) | _tbd_ |
| Recall (macro) | _tbd_ |
| F1 (macro) | _tbd_ |
| ROC-AUC (macro OVR) | _tbd_ |

## Scoring & thresholds

- A flow is reported as `ml_alert` when the classifier's top-class probability
  is ≥ `ML_CONFIDENCE_THRESHOLD` (default 0.70) and the class is not benign.
- Otherwise, if IsolationForest marks the flow anomalous, it is reported as
  `ml_anomaly`.
- Results are deduplicated and priority-scored by `triage.py`.

## Limitations

- CIC-IDS2017 flow features and the live per-source window features are related
  but not identical; expect domain shift. Treat live scores as advisory.
- The aggregator approximates packet size when the stream lacks a length field.
- Trained on 2017 traffic; it will not know newer attack patterns — that is what
  the IsolationForest partially compensates for.
- Class imbalance in the dataset can bias rare classes despite balanced weights.

## Ethics

- Offensive modules and this model are for an authorized, isolated lab network.
- The model informs a human; it must not drive automated enforcement against
  real hosts. IPS enforcement is a separate, off-by-default, lab-only feature.
