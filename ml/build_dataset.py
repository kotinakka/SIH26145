"""
Phase 4 — Feature dataset builder for ML training.
Extracts passive flow, DNS, and TLS metadata features from ../data/*.pcap.
"""

import os
import sys
import glob
import random
import pandas as pd

# Ensure backend folder is in sys.path so we can import flow, dns_features, tls_features
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.abspath(os.path.join(CURRENT_DIR, "..", "backend"))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from flow import (
    extract_flows,
    attach_source_aggregates,
    attach_destination_aggregates,
    attach_dns_aggregates,
    attach_tls_aggregates,
)

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
OUTPUT_CSV = os.path.join(os.path.dirname(__file__), "traffic_dataset.csv")

LABEL_MAP = {
    "benign": "BENIGN",
    "benign_dns": "BENIGN",
    "benign_download": "BENIGN",
    "benign_tls": "BENIGN",
    "ja3s_control": "BENIGN",
    "irregular_multiconn": "BENIGN",
    "ddos": "DDOS",
    "udp_flood": "DDOS",
    "slowloris": "DDOS",
    "port_scan": "PORT_SCAN",
    "host_sweep": "PORT_SCAN",
    "c2_beacon": "BOTNET_C2",
    "c2_multiconn": "BOTNET_C2",
    "dns_tunnel": "DNS_TUNNEL",
    "dga_dns": "DNS_TUNNEL",
    "encrypted_anomaly": "MALWARE_ENCRYPTED",
    "ja3_demo": "MALWARE_ENCRYPTED",
    "ja3s_demo": "MALWARE_ENCRYPTED",
    "data_exfil": "DATA_EXFIL",
}

FEATURE_COLUMNS = [
    "packet_count",
    "byte_count",
    "duration",
    "packets_per_second",
    "bytes_per_second",
    "syn_count",
    "syn_ratio",
    "mean_interval_seconds",
    "interval_cv",
    "inter_arrival_count",
    "unique_dst_ports",
    "unique_dst_ips",
    "unique_src_ips",
    "total_packets_to_dest",
    "total_bytes_to_dest",
    "total_syn_to_dest",
    "dest_syn_ratio",
    "dest_udp_ratio",
    "dest_src_ip_entropy",
    "pair_bytes_out",
    "pair_bytes_in",
    "out_in_ratio",
    "is_outbound",
    "beacon_conn_count",
    "beacon_span_seconds",
    "beacon_mean_interval",
    "beacon_interval_cv",
    "beacon_bytes_per_conn",
    "dns_query_count",
    "dns_avg_label_length",
    "dns_avg_entropy",
    "dns_avg_digit_ratio",
    "dns_avg_bigram_score",
    "dns_unusual_qtype_ratio",
    "dns_queries_per_second",
    "tls_cipher_count",
    "tls_extension_count",
    "tls_has_sni",
    "tls_server_cipher",
]

BINARY_OR_INT_COLS = {"is_outbound", "tls_has_sni", "tls_server_cipher", "tls_cipher_count", "tls_extension_count"}


def _flow_to_row(f, label, source_pcap):
    row = {}
    for col in FEATURE_COLUMNS:
        val = f.get(col, 0.0)
        if val is None:
            val = 0.0
        elif isinstance(val, bool):
            val = 1.0 if val else 0.0
        row[col] = float(val)
    row["label"] = label
    row["source_pcap"] = source_pcap
    return row


def _augment_sparse_classes(df, min_samples=60):
    random.seed(42)
    extra_rows = []
    counts = df["label"].value_counts().to_dict()

    for label, count in counts.items():
        if count >= min_samples:
            continue
        subset = df[df["label"] == label].to_dict("records")
        needed = min_samples - count
        for i in range(needed):
            base = dict(subset[i % len(subset)])
            for col in FEATURE_COLUMNS:
                if col not in BINARY_OR_INT_COLS and base[col] > 0:
                    jitter = random.uniform(0.88, 1.12)
                    base[col] = round(base[col] * jitter, 4)
            base["source_pcap"] = base["source_pcap"] + "_aug"
            extra_rows.append(base)

    if extra_rows:
        df = pd.concat([df, pd.DataFrame(extra_rows)], ignore_index=True)
    return df


def build():
    rows = []
    for base_name, label in LABEL_MAP.items():
        pcap_path = os.path.join(DATA_DIR, f"{base_name}.pcap")
        if not os.path.exists(pcap_path):
            print(f"Skipping missing file: {pcap_path}")
            continue

        flows = extract_flows(pcap_path)
        flows = attach_source_aggregates(flows)
        flows = attach_destination_aggregates(flows)
        flows = attach_dns_aggregates(flows, pcap_path)
        flows = attach_tls_aggregates(flows, pcap_path)

        for f in flows:
            # For multi-flow captures like data_exfil or ja3s_demo, only label the attack direction
            if label == "DATA_EXFIL" and not f.get("is_outbound", False):
                continue
            if label == "MALWARE_ENCRYPTED" and f.get("tls_cipher_count", 0) == 0:
                continue
            rows.append(_flow_to_row(f, label, f"{base_name}.pcap"))

    df = pd.DataFrame(rows)
    df = _augment_sparse_classes(df, min_samples=60)
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"\nSaved {len(df)} labeled flows to {OUTPUT_CSV}\n")
    print(df["label"].value_counts())


if __name__ == "__main__":
    build()