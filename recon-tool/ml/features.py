"""
ml/features.py
--------------
Shared feature schema + a live FlowAggregator.

FEATURE_NAMES is the single source of truth for the feature order. Both the
training pipeline (train.py, from CIC-IDS2017 columns) and live scoring
(engine.py, from the FlowAggregator) produce vectors in exactly this order, so a
model trained offline can score live traffic.

No third-party imports here so the aggregator can run inside the Django backend
without pulling in numpy/pandas.
"""
import math
import time
from collections import defaultdict, deque

# Canonical feature order. Do not reorder without retraining.
FEATURE_NAMES = [
    "packets_per_s",      # packet rate over the window
    "syn_ratio",          # fraction of packets with only the SYN flag
    "unique_dst_ports",   # distinct destination ports contacted
    "mean_pkt_size",      # mean packet size (bytes)
    "std_pkt_size",       # std-dev of packet size (bytes)
    "dst_port_entropy",   # Shannon entropy of destination-port distribution
    "flow_duration",      # seconds between first and last packet in the window
    "total_bytes",        # total bytes observed in the window
    "total_packets",      # total packets observed in the window
]

# Default per-packet size when a packet summary carries no length.
_DEFAULT_PKT_SIZE = 60


def _shannon_entropy(counts):
    total = sum(counts)
    if total <= 0:
        return 0.0
    entropy = 0.0
    for c in counts:
        if c <= 0:
            continue
        p = c / total
        entropy -= p * math.log2(p)
    return entropy


def _is_syn_only(flags: str) -> bool:
    f = str(flags or "").upper().replace("-", " ").split()
    tokens = set(f)
    if tokens == {"S"} or tokens == {"SYN"}:
        return True
    # "S" present but no ACK is treated as a SYN attempt.
    return ("S" in tokens or "SYN" in tokens) and "A" not in tokens and "ACK" not in tokens


def packet_size(pkt: dict) -> int:
    for key in ("length", "size", "bytes", "len"):
        val = pkt.get(key)
        if isinstance(val, (int, float)) and val > 0:
            return int(val)
    summary = str(pkt.get("summary", ""))
    return max(_DEFAULT_PKT_SIZE, len(summary))


class FlowAggregator:
    """Accumulate packets per source IP into a sliding time window and emit
    fixed-order feature vectors.

    Usage (live):
        agg = FlowAggregator(window_seconds=10)
        agg.add(packet_dict)
        vec = agg.features_for(src_ip)          # list[float] in FEATURE_NAMES order
        ready = agg.ready_sources(min_packets=20)
    """

    def __init__(self, window_seconds: float = 10.0, max_sources: int = 4096):
        self.window = float(window_seconds)
        self.max_sources = max_sources
        # src_ip -> deque[(ts, dst_port, size, syn_only)]
        self._flows = defaultdict(deque)

    def _now(self):
        return time.monotonic()

    def _prune(self, src_ip, now=None):
        now = now if now is not None else self._now()
        cutoff = now - self.window
        dq = self._flows[src_ip]
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        if not dq:
            self._flows.pop(src_ip, None)

    def add(self, pkt: dict):
        src_ip = str(pkt.get("src_ip") or pkt.get("src") or "").strip()
        if not src_ip:
            return
        now = self._now()
        try:
            dst_port = int(pkt.get("dst_port") or pkt.get("dport") or 0)
        except (TypeError, ValueError):
            dst_port = 0
        size = packet_size(pkt)
        syn_only = _is_syn_only(pkt.get("flags", ""))
        self._flows[src_ip].append((now, dst_port, size, syn_only))
        self._prune(src_ip, now)

        # Bound memory: drop the least-recently-updated sources.
        if len(self._flows) > self.max_sources:
            oldest = min(self._flows.items(), key=lambda kv: kv[1][-1][0] if kv[1] else 0)
            self._flows.pop(oldest[0], None)

    def features_for(self, src_ip: str):
        self._prune(src_ip)
        dq = self._flows.get(src_ip)
        if not dq:
            return None

        timestamps = [t for t, _, _, _ in dq]
        ports = [p for _, p, _, _ in dq if p]
        sizes = [s for _, _, s, _ in dq]
        syns = sum(1 for _, _, _, syn in dq if syn)
        n = len(dq)

        duration = max(1e-3, (timestamps[-1] - timestamps[0])) if n > 1 else 1e-3
        packets_per_s = n / duration if duration > 0 else float(n)
        syn_ratio = syns / n if n else 0.0
        unique_dst_ports = len(set(ports))
        mean_size = sum(sizes) / n if n else 0.0
        var = sum((s - mean_size) ** 2 for s in sizes) / n if n else 0.0
        std_size = math.sqrt(var)

        port_counts = defaultdict(int)
        for p in ports:
            port_counts[p] += 1
        entropy = _shannon_entropy(list(port_counts.values()))

        total_bytes = sum(sizes)

        return [
            float(packets_per_s),
            float(syn_ratio),
            float(unique_dst_ports),
            float(mean_size),
            float(std_size),
            float(entropy),
            float(duration),
            float(total_bytes),
            float(n),
        ]

    def ready_sources(self, min_packets: int = 20):
        """Sources with at least min_packets in the current window."""
        now = self._now()
        ready = []
        for src_ip in list(self._flows.keys()):
            self._prune(src_ip, now)
            dq = self._flows.get(src_ip)
            if dq and len(dq) >= min_packets:
                ready.append(src_ip)
        return ready

    def clear(self):
        self._flows.clear()


def cic_row_to_features(row: dict):
    """Map one CIC-IDS2017 CSV row (dict of column->value) to FEATURE_NAMES.

    CIC column names vary slightly between mirrors; we try a few aliases and
    fall back to 0.0. Returns a list[float] in FEATURE_NAMES order.
    """
    def g(*names, default=0.0):
        for name in names:
            if name in row and row[name] not in ("", None):
                try:
                    return float(row[name])
                except (TypeError, ValueError):
                    continue
        return default

    duration_us = g("Flow Duration", "flow_duration")
    duration_s = max(1e-3, duration_us / 1_000_000.0)
    total_packets = g("Total Fwd Packets", "Tot Fwd Pkts") + g("Total Backward Packets", "Tot Bwd Pkts")
    total_packets = total_packets or g("Total Packets", default=0.0)
    total_bytes = g("Total Length of Fwd Packets", "TotLen Fwd Pkts") + \
        g("Total Length of Bwd Packets", "TotLen Bwd Pkts")

    syn_count = g("SYN Flag Count", "SYN Flag Cnt")
    syn_ratio = (syn_count / total_packets) if total_packets else 0.0
    mean_size = g("Average Packet Size", "Pkt Size Avg",
                  default=(total_bytes / total_packets if total_packets else 0.0))
    std_size = g("Packet Length Std", "Pkt Len Std")
    packets_per_s = g("Flow Packets/s", "Flow Pkts/s", default=(total_packets / duration_s))

    # CIC rows describe a single flow (one dst port); entropy/unique-ports are
    # not directly available, so we use conservative stand-ins.
    unique_dst_ports = 1.0
    dst_port_entropy = 0.0

    return [
        float(packets_per_s),
        float(min(1.0, max(0.0, syn_ratio))),
        float(unique_dst_ports),
        float(mean_size),
        float(std_size),
        float(dst_port_entropy),
        float(duration_s),
        float(total_bytes),
        float(total_packets),
    ]
