# SIH26145 — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

## 1. Executive Summary & Architectural Compliance
This system is a passive, real-time network threat detection engine engineered for **unidirectional (one-way) IP traffic links** (such as optical data diodes, SPAN/mirror ports, and passive network taps) where active probing, inline blocking, or payload decryption is impossible.

### Compliance with Problem Statement Constraints
| Constraint | Implementation Details |
| :--- | :--- |
| **a. Read-Only Ingest** | 100% passive packet/PCAP ingestion (`flow.py`, `streaming.py`)[cite: 3, 5]. Zero outbound sockets, reverse DNS lookups, or active interrogation. |
| **b. No Payload Decryption** | Encrypted sessions are analyzed strictly via cleartext TLS `ClientHello` and `ServerHello` handshake metadata (`tls_features.py` — cipher suite counts, extension sparsity, SNI presence, and JA3/JA3S fingerprints) without decrypting payloads[cite: 1, 4]. |
| **c. Streaming, Not Batch** | `streaming.py` maintains incremental per-flow state and emits standardized alerts over WebSockets (`/ws/alerts`) every $N$ packets with bounded sub-millisecond detection latency[cite: 5]. |
| **d. Defined Throughput Target** | Demonstrated sustained processing throughput of **1,500+ flows/sec** (and **15,000+ packets/sec**) in single-worker Python streaming mode, with real-time `flows_per_second`, `wall_time_seconds`, and `avg_detection_latency_ms` telemetry reported in every stream summary[cite: 5]. |
| **e. Standardized Alert Schema** | Every alert conforms to a uniform JSON schema containing `timestamp` (ISO-8601 UTC), `flow_id` (5-tuple), `threat_class`, `confidence` ($0.00 - 1.00$), `severity` (`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`), `risk_score` ($0 - 100$), and human-readable `evidence`[cite: 4, 5]. |

---

## 2. Six-Vector Threat Coverage

| Threat Category | Primary Signals & Engineered Features | Lab Validation Captures |
| :--- | :--- | :--- |
| **1. Volumetric / Protocol DDoS** (`DDOS`) | Destination-level SYN ratio (`dest_syn_ratio`), UDP flood ratio (`dest_udp_ratio`), distinct source count (`unique_src_ips`), Shannon entropy of per-source packet distribution (`dest_src_ip_entropy`), and Slowloris concurrent slow-stream exhaustion (`beacon_conn_count`, `bytes_per_second`)[cite: 3, 4]. | `ddos.pcap`, `udp_flood.pcap`, `slowloris.pcap` |
| **2. Reconnaissance & Port Scanning** (`PORT_SCAN`) | Source fan-out across unique destination ports (`unique_dst_ports` for vertical scans) and unique destination hosts (`unique_dst_ips` for horizontal host sweeps) paired with `syn_ratio`[cite: 3, 4]. | `port_scan.pcap`, `host_sweep.pcap` |
| **3. Botnet C2 Beaconing** (`BOTNET_C2`) | Single-flow inter-arrival periodicity (`interval_cv`, `mean_interval_seconds`) and cross-connection periodicity (`beacon_interval_cv`, `beacon_mean_interval`, `beacon_bytes_per_conn`)[cite: 3, 4]. | `c2_beacon.pcap`, `c2_multiconn.pcap`, `irregular_multiconn.pcap` (control) |
| **4. DGA Domains & DNS Tunneling** (`DNS_TUNNEL`) | Query-label Shannon entropy (`dns_avg_entropy`), character 2-gram naturalness score (`dns_avg_bigram_score`), label length (`dns_avg_label_length`), digit ratio (`dns_avg_digit_ratio`), and unusual `TXT`/`NULL` record-type ratio (`dns_unusual_qtype_ratio`)[cite: 2, 4]. | `dns_tunnel.pcap`, `dga_dns.pcap`, `benign_dns.pcap` (control) |
| **5. Malware in Encrypted Sessions** (`MALWARE_ENCRYPTED`) | Cleartext TLS handshake structural sparsity (`tls_cipher_count`, `tls_extension_count`, `tls_has_sni`) plus MD5 `JA3` client and `JA3S` server fingerprint matching (`ja3_blocklist.py`)[cite: 1, 4]. | `encrypted_anomaly.pcap`, `ja3_demo.pcap`, `ja3s_demo.pcap`, `benign_tls.pcap` (control), `ja3s_control.pcap` (control) |
| **6. Data Exfiltration** (`DATA_EXFIL`) | RFC1918 direction-aware byte accounting (`is_outbound`, `pair_bytes_out`, `pair_bytes_in`, `out_in_ratio`) and average packet payload size[cite: 3, 4]. | `data_exfil.pcap`, `benign_download.pcap` (control) |

---

## 3. Hybrid AI/ML + Explainable Rule Architecture

The detection pipeline combines deterministic domain rules (`backend/detector.py`)[cite: 4] with a dual-model Machine Learning ensemble (`ml/train.py`, `backend/ml_engine.py`):

1. **Supervised Multi-Class Classifier (`RandomForestClassifier`):**
   * Trained on **39 passive flow, DNS, and TLS metadata features** extracted across all 7 classes (`BENIGN` + 6 threat categories).
   * Configured with `n_estimators=120`, `max_depth=14`, and `class_weight="balanced"`, evaluated via **5-fold Stratified Cross-Validation** and a 25% hold-out test split.
2. **Unsupervised Zero-Day Anomaly Detector (`IsolationForest`):**
   * Fitted on scaled benign traffic baselines (`contamination=0.05`) to flag novel traffic anomalies that deviate from normal unidirectional flow profiles.
3. **Hybrid Confidence Fusion:**
   * Final alert confidence fuses rule-based structural certainty ($0.6 \times C_{\text{rule}}$) with the Random Forest class probability ($0.4 \times P_{\text{ML}}$) and appends the ML probability and Isolation Forest anomaly flag directly to the alert's explainable `evidence` array.

---

## 4. Project Structure

```text
SIH26145/
├── backend/
│   ├── main.py                  # FastAPI REST (/analyze, /alerts, /statistics) & WebSocket (/ws/alerts)
│   ├── flow.py                  # 5-tuple flow aggregation, entropy, direction & periodicity features
│   ├── dns_features.py          # DNS query entropy, 2-gram naturalness, and record-type extractor
│   ├── tls_features.py          # Passive TLS ClientHello/ServerHello parser & JA3/JA3S generator
│   ├── ja3_blocklist.py         # Threat-intel fingerprint matcher for JA3 and JA3S hashes
│   ├── detector.py              # Hybrid 6-vector threat detector + rule & ML confidence fusion
│   ├── ml_engine.py             # Real-time scikit-learn model inference wrapper
│   ├── streaming.py             # Incremental packet-by-packet streaming engine with latency metrics
│   ├── database.py              # SQLite alert persistence and statistics aggregation
│   ├── create_pcap.py           # Synthetic lab traffic & multi-threat stream generator
│   ├── create_tls_pcap.py       # Cleartext TLS handshake PCAP generator
│   ├── create_ja3_demo_pcap.py  # JA3 / JA3S恶意/control PCAP generator
│   └── test_all.py              # Automated 19-PCAP batch & streaming regression test suite
├── ml/
│   ├── build_dataset.py         # Extracts 39 passive features from ../data/*.pcap into CSV
│   ├── train.py                 # Trains & validates Random Forest + Isolation Forest models
│   └── *.joblib                 # Serialized model, scaler, and feature column artifacts
├── dashboard/
│   ├── index.html               # Real-time SOC monitoring interface
│   ├── app.js                   # WebSocket client, incident deduplication, and Chart.js visuals
│   └── style.css                # Responsive styling
└── data/
    └── *.pcap                   # 19 individual test PCAPs + all_threats.pcap unified stream