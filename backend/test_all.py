"""
Automated regression & verification suite for all 19 lab PCAPs.
Tests both the batch pipeline (flow.py + detector.py) and live streaming (streaming.py).
"""

import os
from flow import (
    extract_flows,
    attach_source_aggregates,
    attach_destination_aggregates,
    attach_dns_aggregates,
    attach_tls_aggregates,
)
from detector import detect
from streaming import stream_detect

TEST_CASES = [
    # Benign / Negative Controls (must produce 0 false positives)
    ("benign.pcap", "BENIGN"),
    ("benign_dns.pcap", "BENIGN"),
    ("benign_download.pcap", "BENIGN"),
    ("benign_tls.pcap", "BENIGN"),
    ("irregular_multiconn.pcap", "BENIGN"),
    ("ja3s_control.pcap", "BENIGN"),
    # Attack Captures across all 6 NTRO threat classes
    ("ddos.pcap", "DDOS"),
    ("udp_flood.pcap", "DDOS"),
    ("slowloris.pcap", "DDOS"),
    ("port_scan.pcap", "PORT_SCAN"),
    ("host_sweep.pcap", "PORT_SCAN"),
    ("c2_beacon.pcap", "BOTNET_C2"),
    ("c2_multiconn.pcap", "BOTNET_C2"),
    ("dns_tunnel.pcap", "DNS_TUNNEL"),
    ("dga_dns.pcap", "DNS_TUNNEL"),
    ("encrypted_anomaly.pcap", "MALWARE_ENCRYPTED"),
    ("ja3_demo.pcap", "MALWARE_ENCRYPTED"),
    ("ja3s_demo.pcap", "MALWARE_ENCRYPTED"),
    ("data_exfil.pcap", "DATA_EXFIL"),
]

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")


def run_batch(pcap_path):
    flows = extract_flows(pcap_path)
    flows = attach_source_aggregates(flows)
    flows = attach_destination_aggregates(flows)
    flows = attach_dns_aggregates(flows, pcap_path)
    flows = attach_tls_aggregates(flows, pcap_path)
    verdicts = [detect(f) for f in flows]
    non_benign = [v for v in verdicts if v["threat_class"] != "BENIGN"]
    if non_benign:
        top = max(non_benign, key=lambda v: v["confidence"])
        return top["threat_class"], top["confidence"]
    return "BENIGN", 1.0


def run_stream(pcap_path):
    events = list(stream_detect(pcap_path, speed_factor=0))
    alerts = [e for e in events if e["type"] == "alert"]
    if alerts:
        top = max(alerts, key=lambda a: a["confidence"])
        return top["threat_class"]
    return "BENIGN"


if __name__ == "__main__":
    print(f"{'PCAP File':25s} | {'Expected':18s} | {'Batch':18s} | {'Stream':18s} | {'Result'}")
    print("-" * 96)
    passed = 0
    for filename, expected in TEST_CASES:
        path = os.path.join(DATA_DIR, filename)
        if not os.path.exists(path):
            print(f"{filename:25s} | MISSING FILE (run create_pcap.py, create_tls_pcap.py, create_ja3_demo_pcap.py)")
            continue
        b_cls, b_conf = run_batch(path)
        s_cls = run_stream(path)
        ok = (b_cls == expected) and (s_cls == expected)
        if ok:
            passed += 1
        status = "PASS" if ok else "FAIL"
        print(f"{filename:25s} | {expected:18s} | {b_cls:18s} | {s_cls:18s} | {status} ({b_conf:.2f})")

    print(f"\nSummary: {passed}/{len(TEST_CASES)} test cases passed.")