"""
Phase 3 — Rule-based baseline detector.

Deterministic, explainable threat detection based on thresholds
over flow features produced by flow.py. This is NOT machine
learning — it exists to (a) give us an immediately working
detection pipeline, and (b) serve as a baseline that Phase 4's
ML models must outperform to justify their added complexity.

Thresholds below are placeholders based on our synthetic lab
PCAPs (benign.pcap, ddos.pcap, port_scan.pcap) and MUST be
revisited once Phase 2 produces a larger, more varied dataset.

Phase 3b — added evaluate_c2_beacon, evaluate_dns_tunnel,
evaluate_encrypted_anomaly and evaluate_data_exfil to cover the
remaining four of the six official threat categories. These use
ONLY the flow-level features flow.py / streaming.py already
compute (packet/byte counts, duration, rates, ports, SYN ratio)
— no new packet parsing was added. Two consequences of that:

  - evaluate_dns_tunnel can only see traffic VOLUME on port 53,
    not DNS query content (query names, entropy, record types).
    A real DNS-tunneling/DGA detector needs those, which means
    parsing the DNS layer in flow.py — this is a placeholder
    proxy, not the real signal, until that's added.
  - evaluate_encrypted_anomaly and evaluate_data_exfil have no
    way to tell "encrypted" from "large" traffic apart (no TLS/
    payload inspection), so they key off port + volume heuristics
    instead. Treat both as coarse placeholders, same as the
    original DDOS/PORT_SCAN thresholds.

None of these fire on the three existing lab captures (verified
against benign.pcap, ddos.pcap, port_scan.pcap) — they only
affect traffic that actually matches their patterns.

Phase 3e — evaluate_ddos and evaluate_c2_beacon now require real
signals the PS specifically names instead of volume-only proxies:
DDoS requires dest_src_ip_entropy (Shannon entropy of the
per-source packet distribution — see flow.py's _entropy_of_counts)
alongside the existing SYN-ratio/source-count checks, and C2
beaconing requires interval_cv (coefficient of variation of
inter-packet gaps — see flow.py's _interval_stats) alongside the
existing sparse/quiet/long-lived checks. Both are computed in
flow.py's batch path AND streaming.py's incremental path, so
/analyze and /ws/alerts agree.
"""


from ja3_blocklist import lookup_ja3

# JA3 blocklist hit: a known-malicious TLS client fingerprint is stronger
# evidence than the structural heuristic below, so it starts higher.
JA3_MATCH_CONFIDENCE = 0.92


# ---- Threshold constants (tune later against real lab data) ----




DDOS_SYN_RATIO_THRESHOLD = 0.8
DDOS_MIN_SOURCE_IPS = 50
# Shannon entropy (bits) of the per-source packet-count distribution
# toward a destination. High entropy = many sources contributing
# roughly evenly (the spoofed-source/distributed flood shape the PS
# asks for); low/zero entropy = one dominant source. Measured:
# ddos.pcap (200 near-uniform sources) ~7.64 bits; benign/port_scan
# (single source) 0.0 bits. Set well below the observed attack value
# so it doesn't become the binding constraint, but still required.
DDOS_MIN_SRC_ENTROPY = 3.0

PORT_SCAN_MIN_UNIQUE_PORTS = 20

# Ports we don't treat as "unusual" when judging encrypted/exfil
# traffic. Deliberately small and standard-service-only.
COMMON_PORTS = {20, 21, 22, 25, 53, 80, 110, 143, 443, 993, 995}

# C2 beaconing: few packets, spread over a long-lived connection,
# very low sustained throughput — a periodic check-in shape rather
# than a normal request/response or bulk transfer.
BEACON_MAX_PACKETS = 12
BEACON_MIN_DURATION_SECONDS = 20.0
BEACON_MAX_BYTES_PER_SECOND = 5.0
# Coefficient of variation (stddev/mean) of inter-arrival gaps
# between this flow's packets. LOW cv = regular spacing = the
# "repeats at regular intervals" periodicity signal the PS asks
# for; a random/bursty flow has cv much closer to 1.0. Measured on
# c2_beacon.pcap (checkins spaced a consistent 25s apart, with one
# handshake-related outlier gap): cv ~0.41. Set with margin above
# that so a real, slightly-jittery beacon still qualifies.
BEACON_MAX_INTERVAL_CV = 0.5
BEACON_MIN_INTERVALS = 3
# Cross-connection beaconing (new connection per check-in, the common
# real-world shape): >= 4 connections from one source to one
# destination:port, gaps >= 5s apart on average (excludes fast
# polling/loops), tiny payloads, spanning >= 20s, and regular gaps.
BEACON_GROUP_MIN_CONNS = 4
BEACON_GROUP_MIN_MEAN_INTERVAL = 5.0
BEACON_GROUP_MIN_SPAN_SECONDS = 20.0
BEACON_GROUP_MAX_BYTES_PER_CONN = 500

# DNS tunneling / DGA proxy: unusually high packet volume on the
# DNS port for a single flow. See module docstring — this is a
# volume-only proxy, not real DNS content inspection.
# DNS tunneling / DGA: real query-content signal (see
# dns_features.py), replacing the old packet-volume-on-port-53
# proxy. Thresholds set with margin around the measured gap:
# benign avg_entropy ~2.0, avg_label_length ~5
# tunnel avg_entropy ~4.2, avg_label_length ~32
DNS_TUNNEL_MIN_ENTROPY = 3.3
DNS_TUNNEL_MIN_LABEL_LENGTH = 16
DNS_TUNNEL_MIN_QUERY_COUNT = 10
DNS_TUNNEL_MIN_PACKETS = 30
# Encrypted session anomaly: a large, sustained transfer on a
# non-standard port, where we can't otherwise identify the protocol.
ENCRYPTED_ANOMALY_MIN_BYTES = 50_000
ENCRYPTED_ANOMALY_MIN_DURATION_SECONDS = 5.0

# Data exfiltration: a large volume of data moved in a single flow,
# with large individual packets (bulk payload) rather than many
# small control-style packets.
EXFIL_MIN_BYTES = 200_000
EXFIL_MIN_AVG_PACKET_BYTES = 800
# Outbound-to-inbound byte ratio for the host pair (PS: "unusual
# outbound-to-inbound byte ratios"). Normal client traffic pulls
# far more than it pushes (ratio << 1); a bulk upload to an external
# host is heavily one-sided. Lab: data_exfil.pcap ~200+, benign
# download ~0.01.
EXFIL_MIN_OUT_IN_RATIO = 10.0
# Encrypted session anomaly: real TLS ClientHello metadata (see
# tls_features.py), replacing the old port+volume proxy. A
# minimal, non-browser-like handshake (few ciphers, few/no
# extensions) is the structural anomaly signal here — NOT a
# known-malicious-JA3 lookup, since we have no threat-intel feed.
# Thresholds set with margin around measured lab data:
# benign: 15 ciphers, 9 extensions
# anomaly: 2 ciphers, 0 extensions
TLS_ANOMALY_MAX_CIPHERS = 5
TLS_ANOMALY_MAX_EXTENSIONS = 2


HOST_SCAN_MIN_UNIQUE_HOSTS = 15
DGA_MIN_ENTROPY = 3.1
DGA_MAX_BIGRAM_SCORE = 0.38
DGA_MIN_LABEL_LENGTH = 8
SLOWLORIS_MIN_CONNS = 15
SLOWLORIS_MIN_DURATION = 10.0
SLOWLORIS_MAX_BPS = 50.0


def evaluate_ddos(flow):
    dest_syn_ratio = flow.get("dest_syn_ratio", 0)
    dest_udp_ratio = flow.get("dest_udp_ratio", 0)
    unique_src_ips = flow.get("unique_src_ips", 0)
    src_ip_entropy = flow.get("dest_src_ip_entropy", 0)
    total_pkts = flow.get("total_packets_to_dest", 0)

    # Guard: if this source is fanning out across many ports, let evaluate_port_scan classify it
    if flow.get("unique_dst_ports", 0) > PORT_SCAN_MIN_UNIQUE_PORTS:
        return None

    # Branch 1: Spoofed / distributed TCP SYN flood (flow itself must also be SYN-heavy)
    if (
        flow.get("syn_ratio", 0) > 0.5
        and dest_syn_ratio > DDOS_SYN_RATIO_THRESHOLD
        and unique_src_ips > DDOS_MIN_SOURCE_IPS
        and src_ip_entropy >= DDOS_MIN_SRC_ENTROPY
    ):
        syn_excess = (dest_syn_ratio - DDOS_SYN_RATIO_THRESHOLD) / (1 - DDOS_SYN_RATIO_THRESHOLD)
        source_excess = min(unique_src_ips / (DDOS_MIN_SOURCE_IPS * 4), 1.0)
        entropy_excess = min(src_ip_entropy / (DDOS_MIN_SRC_ENTROPY * 2), 1.0)
        confidence = min(0.55 + 0.15 * syn_excess + 0.15 * source_excess + 0.15 * entropy_excess, 0.99)
        evidence = [
            f"{unique_src_ips} distinct source IPs contacted this destination",
            f"destination-level SYN ratio {dest_syn_ratio:.2f}",
            f"source-IP entropy {src_ip_entropy:.2f} bits (distributed/spoofed flood)",
            f"{total_pkts} total packets observed to destination",
        ]
        return confidence, evidence

    # Branch 2: UDP volumetric / reflection-amplification flood
    if (
        flow.get("protocol") == "UDP"
        and dest_udp_ratio > 0.8
        and unique_src_ips > DDOS_MIN_SOURCE_IPS
        and src_ip_entropy >= DDOS_MIN_SRC_ENTROPY
    ):
        source_excess = min(unique_src_ips / (DDOS_MIN_SOURCE_IPS * 4), 1.0)
        entropy_excess = min(src_ip_entropy / (DDOS_MIN_SRC_ENTROPY * 2), 1.0)
        confidence = min(0.60 + 0.20 * source_excess + 0.19 * entropy_excess, 0.99)
        evidence = [
            f"UDP flood: {unique_src_ips} distinct sources sent {total_pkts} UDP packets ({flow.get('total_bytes_to_dest', 0)} bytes)",
            f"destination-level UDP ratio {dest_udp_ratio:.2f}",
            f"source-IP entropy {src_ip_entropy:.2f} bits (distributed UDP flood)",
        ]
        return confidence, evidence

    # Branch 3: Slowloris slow HTTP connection exhaustion
    conns_in_group = flow.get("beacon_conn_count", 0)
    duration = flow.get("duration", 0)
    bps = flow.get("bytes_per_second", 0)
    if (
        flow.get("protocol") == "TCP"
        and conns_in_group >= SLOWLORIS_MIN_CONNS
        and duration >= SLOWLORIS_MIN_DURATION
        and bps <= SLOWLORIS_MAX_BPS
    ):
        conn_factor = min(conns_in_group / (SLOWLORIS_MIN_CONNS * 2), 1.0)
        confidence = min(0.65 + 0.25 * conn_factor, 0.95)
        evidence = [
            f"Slowloris exhaustion pattern: {conns_in_group} concurrent connections held open to {flow.get('dst_ip')}:{flow.get('dst_port')}",
            f"connection held open for {duration:.1f}s at only {bps:.1f} bytes/sec (slow trickle)",
        ]
        return confidence, evidence

    return None


def evaluate_port_scan(flow):
    """
    Detects both vertical port scans (many dst_ports) and horizontal host
    sweeps (many dst_ips) from a single source, per PS requirement e.
    """
    unique_dst_ports = flow.get("unique_dst_ports", 0)
    unique_dst_ips = flow.get("unique_dst_ips", 0)

    # Vertical port scan
    if unique_dst_ports > PORT_SCAN_MIN_UNIQUE_PORTS:
        excess = min(unique_dst_ports / (PORT_SCAN_MIN_UNIQUE_PORTS * 5), 1.0)
        confidence = min(0.6 + 0.35 * excess, 0.99)
        evidence = [
            f"{unique_dst_ports} unique destination ports contacted by this source",
            f"{unique_dst_ips} unique destination hosts contacted",
            f"SYN ratio {flow.get('syn_ratio', 0):.2f} on this flow",
        ]
        return confidence, evidence

    # Horizontal host sweep (reconnaissance across many hosts on the same port)
    if unique_dst_ips >= HOST_SCAN_MIN_UNIQUE_HOSTS and flow.get("packet_count", 0) <= 5:
        excess = min(unique_dst_ips / (HOST_SCAN_MIN_UNIQUE_HOSTS * 3), 1.0)
        confidence = min(0.65 + 0.30 * excess, 0.98)
        evidence = [
            f"horizontal host sweep: {unique_dst_ips} unique destination hosts probed on port {flow.get('dst_port')}",
            f"only {flow.get('packet_count', 0)} packet(s) per flow (SYN ratio {flow.get('syn_ratio', 0):.2f})",
        ]
        return confidence, evidence

    return None


def evaluate_dns_tunnel(flow):
    """
    Detects both DNS Tunneling (long high-entropy labels or unusual TXT/NULL
    record types) and DGA Domains (shorter 8-15 char algorithmically generated
    labels with high entropy and low character bigram naturalness).
    """
    query_count = flow.get("dns_query_count", 0)
    avg_entropy = flow.get("dns_avg_entropy", 0)
    avg_label_length = flow.get("dns_avg_label_length", 0)
    avg_bigram = flow.get("dns_avg_bigram_score", 1.0)
    unusual_qtype_ratio = flow.get("dns_unusual_qtype_ratio", 0.0)

    if query_count < DNS_TUNNEL_MIN_QUERY_COUNT:
        return None

    # Branch 1: DNS Tunneling (dnscat2 / iodine — long subdomain payloads or TXT/NULL records)
    if avg_entropy >= DNS_TUNNEL_MIN_ENTROPY and (
        avg_label_length >= DNS_TUNNEL_MIN_LABEL_LENGTH or unusual_qtype_ratio >= 0.5
    ):
        entropy_excess = min((avg_entropy - DNS_TUNNEL_MIN_ENTROPY) / 1.5, 1.0)
        length_excess = min(avg_label_length / (DNS_TUNNEL_MIN_LABEL_LENGTH * 3), 1.0)
        qtype_bonus = 0.1 * unusual_qtype_ratio
        confidence = min(0.6 + 0.2 * entropy_excess + 0.15 * length_excess + qtype_bonus, 0.99)

        evidence = [
            f"average query-label entropy {avg_entropy:.2f} bits/char (typical benign lookups are ~2.0-3.0)",
            f"average query-label length {avg_label_length:.1f} characters (bigram score {avg_bigram:.2f})",
            f"{query_count} DNS queries observed from this source ({unusual_qtype_ratio*100:.0f}% TXT/NULL/unusual record types)",
        ]
        return confidence, evidence

    # Branch 2: DGA Domains (published PRNG algorithms — 8-15 char unpronounceable labels)
    if (
        avg_label_length >= DGA_MIN_LABEL_LENGTH
        and avg_entropy >= DGA_MIN_ENTROPY
        and avg_bigram <= DGA_MAX_BIGRAM_SCORE
    ):
        bigram_anomaly = 1.0 - (avg_bigram / DGA_MAX_BIGRAM_SCORE)
        entropy_excess = min((avg_entropy - DGA_MIN_ENTROPY) / 1.0, 1.0)
        confidence = min(0.65 + 0.20 * bigram_anomaly + 0.12 * entropy_excess, 0.96)

        evidence = [
            f"DGA domain signature: low 2-gram naturalness score {avg_bigram:.2f} (benign domains score ~0.70+)",
            f"query-label entropy {avg_entropy:.2f} bits/char across {avg_label_length:.1f}-char labels",
            f"{query_count} rapid DGA lookups observed from this source ({flow.get('dns_queries_per_second', 0):.1f}/sec)",
        ]
        return confidence, evidence

    return None


def evaluate_c2_beacon(flow):
    """
    Returns a (confidence, evidence) tuple if this flow looks like
    a sparse, long-lived, low-throughput connection with REGULAR
    inter-arrival spacing, consistent with periodic C2 check-in
    beaconing, else None.

    Requires interval_cv (coefficient of variation of gaps between
    packets — see flow.py's _interval_stats) alongside the original
    sparse/low-throughput/long-duration checks, per the PS's
    "periodicity and inter-arrival analysis ... flows that repeat
    at regular intervals" requirement. Sparse-and-quiet alone isn't
    enough — a long-lived idle connection with irregular, random
    gaps is not the same signal as one checking in on a timer.
    """

    # Branch 1: many short connections checking in on a timer.
    conns = flow.get("beacon_conn_count", 0)
    group_cv = flow.get("beacon_interval_cv")
    group_mean = flow.get("beacon_mean_interval")
    group_span = flow.get("beacon_span_seconds", 0)
    bytes_per_conn = flow.get("beacon_bytes_per_conn", 0)

    if (
        conns >= BEACON_GROUP_MIN_CONNS
        and group_cv is not None
        and group_mean is not None
        and group_mean >= BEACON_GROUP_MIN_MEAN_INTERVAL
        and group_span >= BEACON_GROUP_MIN_SPAN_SECONDS
        and bytes_per_conn <= BEACON_GROUP_MAX_BYTES_PER_CONN
        and group_cv <= BEACON_MAX_INTERVAL_CV
    ):
        regularity = 1 - (group_cv / BEACON_MAX_INTERVAL_CV)
        count_factor = min(conns / (BEACON_GROUP_MIN_CONNS * 3), 1.0)
        confidence = min(0.5 + 0.25 * regularity + 0.2 * count_factor, 0.95)

        evidence = [
            f"{conns} separate connections from {flow.get('src_ip')} to {flow.get('dst_ip')}:{flow.get('dst_port')} over {group_span:.0f}s",
            f"connections start every {group_mean:.1f}s on average (interval variation {group_cv:.2f}, regular check-ins)",
            f"only {bytes_per_conn:.0f} bytes per connection on average (small check-in messages)",
        ]

        return confidence, evidence

    # Branch 2: a single long-lived connection with regular sparse packets.
    packet_count = flow.get("packet_count", 0)
    duration = flow.get("duration", 0)
    bytes_per_second = flow.get("bytes_per_second", 0)
    interval_cv = flow.get("interval_cv")
    inter_arrival_count = flow.get("inter_arrival_count", 0)

    if (
        packet_count > 0
        and duration >= BEACON_MIN_DURATION_SECONDS
        and packet_count <= BEACON_MAX_PACKETS
        and bytes_per_second <= BEACON_MAX_BYTES_PER_SECOND
        and inter_arrival_count >= BEACON_MIN_INTERVALS
        and interval_cv is not None
        and interval_cv <= BEACON_MAX_INTERVAL_CV
    ):
        sparsity = 1 - (packet_count / BEACON_MAX_PACKETS)
        duration_factor = min(duration / (BEACON_MIN_DURATION_SECONDS * 4), 1.0)
        regularity = 1 - (interval_cv / BEACON_MAX_INTERVAL_CV)
        confidence = min(0.5 + 0.15 * sparsity + 0.15 * duration_factor + 0.2 * regularity, 0.95)

        evidence = [
            f"{packet_count} packets over a {duration:.1f}s connection lifetime",
            f"{bytes_per_second:.2f} bytes/sec average throughput",
            f"inter-arrival coefficient of variation {interval_cv:.2f} (regular spacing between check-ins)",
            f"mean gap between packets {flow.get('mean_interval_seconds', 0):.1f}s",
        ]

        return confidence, evidence

    return None





def evaluate_encrypted_anomaly(flow):
    """
    Returns a (confidence, evidence) tuple if this flow's TLS
    ClientHello looks structurally unlike a normal browser/OS TLS
    stack (very few ciphers, very few extensions, often no SNI),
    else None.

    Uses REAL TLS metadata (JA3-style fields) from the cleartext
    ClientHello — no payload decryption. This is a behavioral/
    structural anomaly signal, not a known-malicious-JA3 blacklist
    lookup, since no threat-intel feed is available here.
    """

    cipher_count = flow.get("tls_cipher_count", 0)
    extension_count = flow.get("tls_extension_count", 0)

    if cipher_count == 0:
        return None  # no ClientHello observed in this flow at all

    # JA3 fingerprint match against the known-bad list (ja3_blocklist.csv).
    ja3_hash = flow.get("tls_ja3_hash", "")
    ja3_label = lookup_ja3(ja3_hash)
    if ja3_label:
        evidence = [
            f"JA3 fingerprint {ja3_hash} matches a known-malicious TLS client: {ja3_label}",
            f"ClientHello offered {cipher_count} cipher suites and {extension_count} extensions (metadata only, no decryption)",
            f"SNI: {flow.get('tls_sni') or 'none presented'}",
        ]
        return JA3_MATCH_CONFIDENCE, evidence

    # JA3S (server-side) fingerprint match, e.g. a known C2 framework's listener.
    ja3s_hash = flow.get("tls_ja3s_hash", "")
    ja3s_label = lookup_ja3(ja3s_hash)
    if ja3s_label:
        evidence = [
            f"JA3S server fingerprint {ja3s_hash} matches a known-malicious TLS server: {ja3s_label}",
            f"client offered {cipher_count} cipher suites; server chose cipher 0x{flow.get('tls_server_cipher', 0):04x} (metadata only, no decryption)",
            f"SNI: {flow.get('tls_sni') or 'none presented'}",
        ]
        return JA3_MATCH_CONFIDENCE, evidence

    if cipher_count > TLS_ANOMALY_MAX_CIPHERS or extension_count > TLS_ANOMALY_MAX_EXTENSIONS:
        return None

    cipher_sparsity = 1 - (cipher_count / (TLS_ANOMALY_MAX_CIPHERS + 1))
    ext_sparsity = 1 - (extension_count / (TLS_ANOMALY_MAX_EXTENSIONS + 1))
    confidence = min(0.6 + 0.15 * cipher_sparsity + 0.15 * ext_sparsity, 0.95)

    sni_note = flow.get("tls_sni") or "no SNI presented"

    evidence = [
        f"TLS ClientHello offered only {cipher_count} cipher suite(s), far fewer than typical browser/OS stacks",
        f"{extension_count} TLS extension(s) present, unusually sparse for a standard client",
        f"JA3 fingerprint: {flow.get('tls_ja3_hash', 'n/a')} ({sni_note})",
    ]

    return confidence, evidence


def evaluate_data_exfil(flow):
    """
    Returns a (confidence, evidence) tuple if an INTERNAL host is
    pushing a large, one-sided volume of data to an EXTERNAL host,
    else None.

    Uses real direction-aware byte accounting from flow.py
    (pair_bytes_out / pair_bytes_in / out_in_ratio / is_outbound):
    the PS asks for asymmetric volume and outbound-to-inbound
    ratios, not just "a big flow". A large download (inbound-heavy)
    or an internal-to-internal copy is deliberately NOT flagged.
    """

    if not flow.get("is_outbound", False):
        return None

    bytes_out = flow.get("pair_bytes_out", 0)
    bytes_in = flow.get("pair_bytes_in", 0)
    ratio = flow.get("out_in_ratio", 0)

    byte_count = flow.get("byte_count", 0)
    packet_count = flow.get("packet_count", 0) or 1
    avg_packet_bytes = byte_count / packet_count

    if (
        bytes_out >= EXFIL_MIN_BYTES
        and ratio >= EXFIL_MIN_OUT_IN_RATIO
        and avg_packet_bytes >= EXFIL_MIN_AVG_PACKET_BYTES
    ):
        volume_excess = min(bytes_out / (EXFIL_MIN_BYTES * 4), 1.0)
        ratio_excess = min(ratio / (EXFIL_MIN_OUT_IN_RATIO * 10), 1.0)
        confidence = min(0.5 + 0.25 * volume_excess + 0.2 * ratio_excess, 0.95)

        evidence = [
            f"{bytes_out} bytes sent outbound to an external host vs {bytes_in} bytes returned",
            f"outbound-to-inbound ratio {ratio:.1f}:1 (heavily one-sided upload)",
            f"average packet size {avg_packet_bytes:.0f} bytes (bulk payload, not control traffic)",
        ]

        return confidence, evidence

    return None


def severity_from_confidence(confidence):
    """
    Maps a confidence score to a severity label.
    Thresholds are placeholders — revisit once we have real
    false-positive-rate data from Phase 4 evaluation.
    """

    if confidence >= 0.9:
        return "CRITICAL"
    elif confidence >= 0.75:
        return "HIGH"
    elif confidence >= 0.5:
        return "MEDIUM"
    else:
        return "LOW"


def detect(flow):
    """
    Runs all rules against a single flow dict and returns the
    single best-matching verdict.

    Design decision: a flow gets ONE threat_class, not multiple
    simultaneous alerts. If more than one rule fires, we keep
    the one with the higher confidence. This keeps the alert
    schema simple (section 5) and matches a single-card-per-flow
    dashboard. If you later want multi-label alerts (a flow
    flagged as both DDOS and PORT_SCAN simultaneously), this
    function is the place to change — return a list instead of
    picking a single best match.

    Returns a dict matching the alert schema from section 5,
    minus fields (timestamp, flow_id) that belong to the caller.
    """

    candidates = []

    ddos_result = evaluate_ddos(flow)
    if ddos_result is not None:
        confidence, evidence = ddos_result
        candidates.append(("DDOS", confidence, evidence))

    port_scan_result = evaluate_port_scan(flow)
    if port_scan_result is not None:
        confidence, evidence = port_scan_result
        candidates.append(("PORT_SCAN", confidence, evidence))

    c2_result = evaluate_c2_beacon(flow)
    if c2_result is not None:
        confidence, evidence = c2_result
        candidates.append(("BOTNET_C2", confidence, evidence))

    dns_tunnel_result = evaluate_dns_tunnel(flow)
    if dns_tunnel_result is not None:
        confidence, evidence = dns_tunnel_result
        candidates.append(("DNS_TUNNEL", confidence, evidence))

    encrypted_result = evaluate_encrypted_anomaly(flow)
    if encrypted_result is not None:
        confidence, evidence = encrypted_result
        candidates.append(("MALWARE_ENCRYPTED", confidence, evidence))

    exfil_result = evaluate_data_exfil(flow)
    if exfil_result is not None:
        confidence, evidence = exfil_result
        candidates.append(("DATA_EXFIL", confidence, evidence))

    if not candidates:
        return {
            "threat_class": "BENIGN",
            "confidence": 1.0,
            "severity": "LOW",
            "risk_score": 0,
            "evidence": ["no rule thresholds exceeded"],
        }

    # Pick the highest-confidence match
    candidates.sort(key=lambda c: c[1], reverse=True)
    threat_class, confidence, evidence = candidates[0]
    # Pick the highest-confidence match
    candidates.sort(key=lambda c: c[1], reverse=True)
    threat_class, confidence, evidence = candidates[0]

    # Phase 4 Hybrid ML + Rule Fusion
    from ml_engine import predict_flow_ml
    ml_res = predict_flow_ml(flow)
    if ml_res is not None:
        ml_class, ml_conf, is_anom = ml_res
        if ml_class == threat_class:
            confidence = round(0.6 * confidence + 0.4 * ml_conf, 2)
        evidence = list(evidence) + [
            f"ML Random Forest classifier verdict: {ml_class} ({ml_conf*100:.1f}% probability, IsolationForest anomaly={'YES' if is_anom else 'NO'})"
        ]

    severity = severity_from_confidence(confidence)
    risk_score = round(confidence * 100)

    return {
        "threat_class": threat_class,
        "confidence": round(confidence, 2),
        "severity": severity,
        "risk_score": risk_score,
        "evidence": evidence,
    }


if __name__ == "__main__":
    import sys
    from flow import (
        extract_flows,
        attach_source_aggregates,
        attach_destination_aggregates,
        attach_dns_aggregates,
        attach_tls_aggregates,

    )

    if len(sys.argv) > 1:
        pcap_file = sys.argv[1]
    else:
        pcap_file = "../data/test.pcap"

    results = extract_flows(pcap_file)
    results = attach_source_aggregates(results)
    results = attach_destination_aggregates(results)
    results = attach_dns_aggregates(results, pcap_file)
    results = attach_tls_aggregates(results, pcap_file)


    print(f"Analyzing {len(results)} flows from {pcap_file}\n")

    for flow in results:

        verdict = detect(flow)

        print("========== VERDICT ==========")
        print("Source:", flow["src_ip"], flow["src_port"])
        print("Destination:", flow["dst_ip"], flow["dst_port"])
        print("Threat class:", verdict["threat_class"])
        print("Confidence:", verdict["confidence"])
        print("Severity:", verdict["severity"])
        print("Risk score:", verdict["risk_score"])
        print("Evidence:")
        for e in verdict["evidence"]:
            print("  -", e)
        print()