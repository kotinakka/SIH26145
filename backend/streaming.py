"""
Phase 6c — Incremental / near-real-time detection (Synced with all 6 PS vectors).
"""

import time
from collections import defaultdict
from datetime import datetime, timezone
from scapy.all import rdpcap, IP, TCP, UDP, DNS, Raw

from detector import detect
from dns_features import (
    shannon_entropy,
    digit_ratio,
    bigram_score,
    STANDARD_QTYPES,
    aggregate_dns_by_source,
)
from tls_features import (
    parse_client_hello,
    compute_ja3,
    parse_server_hello,
    compute_ja3s,
)
from flow import (
    _interval_stats,
    _entropy_of_counts,
    _attach_pair_direction_stats,
    _attach_beacon_group_stats,
)


def _new_flow_state():
    return {
        "packet_count": 0,
        "byte_count": 0,
        "syn_count": 0,
        "start_time": None,
        "end_time": None,
        "timestamps": [],
    }


def _flow_features(flow_id, state):
    duration = max(state["end_time"] - state["start_time"], 0.001)
    packet_count = state["packet_count"]
    byte_count = state["byte_count"]
    syn_count = state["syn_count"]
    interval_stats = _interval_stats(state["timestamps"])

    return {
        "src_ip": flow_id[0],
        "dst_ip": flow_id[1],
        "src_port": flow_id[2],
        "dst_port": flow_id[3],
        "protocol": flow_id[4],
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration": duration,
        "packets_per_second": packet_count / duration,
        "bytes_per_second": byte_count / duration,
        "syn_count": syn_count,
        "syn_ratio": syn_count / packet_count if packet_count else 0.0,
        "start_time": state["start_time"],
        **interval_stats,
    }


def _attach_aggregates(flows_features):
    source_ports = defaultdict(set)
    source_ips = defaultdict(set)
    dest_sources = defaultdict(set)
    dest_packets = defaultdict(int)
    dest_bytes = defaultdict(int)
    dest_syns = defaultdict(int)
    dest_udp_packets = defaultdict(int)
    dest_source_packet_counts = defaultdict(lambda: defaultdict(int))

    for f in flows_features.values():
        src_ip = f["src_ip"]
        dst_ip = f["dst_ip"]
        source_ports[src_ip].add(f["dst_port"])
        source_ips[src_ip].add(dst_ip)
        dest_sources[dst_ip].add(src_ip)
        dest_packets[dst_ip] += f["packet_count"]
        dest_bytes[dst_ip] += f["byte_count"]
        dest_syns[dst_ip] += f["syn_count"]
        if f["protocol"] == "UDP":
            dest_udp_packets[dst_ip] += f["packet_count"]
        dest_source_packet_counts[dst_ip][src_ip] += f["packet_count"]

    for f in flows_features.values():
        src_ip = f["src_ip"]
        dst_ip = f["dst_ip"]
        total_to_dest = dest_packets[dst_ip]
        f["unique_dst_ports"] = len(source_ports[src_ip])
        f["unique_dst_ips"] = len(source_ips[src_ip])
        f["unique_src_ips"] = len(dest_sources[dst_ip])
        f["total_packets_to_dest"] = total_to_dest
        f["total_bytes_to_dest"] = dest_bytes[dst_ip]
        f["total_syn_to_dest"] = dest_syns[dst_ip]
        f["dest_syn_ratio"] = dest_syns[dst_ip] / total_to_dest if total_to_dest else 0.0
        f["dest_udp_ratio"] = dest_udp_packets[dst_ip] / total_to_dest if total_to_dest else 0.0
        f["dest_src_ip_entropy"] = _entropy_of_counts(dest_source_packet_counts[dst_ip])

    flow_list = list(flows_features.values())
    _attach_pair_direction_stats(flow_list)
    _attach_beacon_group_stats(flow_list)


def _extract_dns_query(packet, ip):
    if not (packet.haslayer(UDP) and packet.haslayer(DNS)):
        return None
    dns_layer = packet[DNS]
    if dns_layer.qr != 0 or dns_layer.qd is None:
        return None
    qname = dns_layer.qd.qname
    if isinstance(qname, bytes):
        qname = qname.decode(errors="ignore")
    qname = qname.rstrip(".")
    qtype = int(getattr(dns_layer.qd, "qtype", 1))
    label_part = qname.split(".")[0] if "." in qname else qname
    return {
        "src_ip": ip.src,
        "domain": qname,
        "label_length": len(label_part),
        "entropy": shannon_entropy(label_part),
        "digit_ratio": digit_ratio(label_part),
        "bigram_score": bigram_score(label_part),
        "qtype": qtype,
        "is_unusual_qtype": qtype not in STANDARD_QTYPES,
        "timestamp": float(packet.time),
    }


def _extract_tls_hello(packet, flow_id):
    if not packet.haslayer(Raw):
        return None
    payload = bytes(packet[Raw].load)
    parsed = parse_client_hello(payload)
    if parsed is None:
        return None
    ja3_str, ja3_hash = compute_ja3(parsed)
    return flow_id, {
        "tls_cipher_count": len(parsed["cipher_suites"]),
        "tls_extension_count": len(parsed["extensions"]),
        "tls_has_sni": parsed["sni"] is not None,
        "tls_sni": parsed["sni"] or "",
        "tls_ja3": ja3_str,
        "tls_ja3_hash": ja3_hash,
    }


def _extract_tls_server_hello(packet, flow_id):
    if not packet.haslayer(Raw):
        return None
    payload = bytes(packet[Raw].load)
    parsed = parse_server_hello(payload)
    if parsed is None:
        return None
    ja3s_str, ja3s_hash = compute_ja3s(parsed)
    return flow_id, {
        "tls_ja3s": ja3s_str,
        "tls_ja3s_hash": ja3s_hash,
        "tls_server_cipher": parsed["cipher_suite"],
    }


def _apply_dns_tls(flows_features, dns_queries, tls_hellos, tls_server_hellos):
    dns_aggregates = aggregate_dns_by_source(dns_queries) if dns_queries else {}
    for fid, features in flows_features.items():
        is_dns_flow = features["src_port"] == 53 or features["dst_port"] == 53
        if is_dns_flow and features["src_ip"] in dns_aggregates:
            features.update(dns_aggregates[features["src_ip"]])
        else:
            features.setdefault("dns_query_count", 0)
            features.setdefault("dns_avg_label_length", 0)
            features.setdefault("dns_avg_entropy", 0)
            features.setdefault("dns_avg_digit_ratio", 0)
            features.setdefault("dns_avg_bigram_score", 1.0)
            features.setdefault("dns_unusual_qtype_ratio", 0.0)
            features.setdefault("dns_queries_per_second", 0)

        if fid in tls_hellos:
            features.update(tls_hellos[fid])
        else:
            features.setdefault("tls_cipher_count", 0)
            features.setdefault("tls_extension_count", 0)
            features.setdefault("tls_has_sni", False)
            features.setdefault("tls_sni", "")
            features.setdefault("tls_ja3", "")
            features.setdefault("tls_ja3_hash", "")

        reverse_id = (fid[1], fid[0], fid[3], fid[2], fid[4])
        srv_info = tls_server_hellos.get(fid) or tls_server_hellos.get(reverse_id)
        if srv_info:
            features.update(srv_info)
        else:
            features.setdefault("tls_ja3s", "")
            features.setdefault("tls_ja3s_hash", "")
            features.setdefault("tls_server_cipher", 0)


def stream_detect(pcap_file, speed_factor=50.0, recompute_every=10):
    packets = rdpcap(pcap_file)
    if len(packets) == 0:
        return

    flow_state = defaultdict(_new_flow_state)
    already_alerted = set()
    dns_queries = []
    tls_hellos = {}
    tls_server_hellos = {}

    replay_start_wall = time.perf_counter()
    first_packet_time = float(packets[0].time)
    detection_latencies = []
    packets_processed = 0

    def _run_evaluation_pass():
        detect_start = time.perf_counter()
        flows_features = {fid: _flow_features(fid, st) for fid, st in flow_state.items()}
        _attach_aggregates(flows_features)
        _apply_dns_tls(flows_features, dns_queries, tls_hellos, tls_server_hellos)

        emitted = []
        for fid, features in flows_features.items():
            if fid in already_alerted:
                continue
            verdict = detect(features)
            if verdict["threat_class"] != "BENIGN":
                already_alerted.add(fid)
                detection_latencies.append(time.perf_counter() - detect_start)
                emitted.append({
                    "type": "alert",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "flow_id": f"{fid[0]}:{fid[2]}-{fid[1]}:{fid[3]}-{fid[4]}",
                    "src_ip": fid[0],
                    "dst_ip": fid[1],
                    "src_port": fid[2],
                    "dst_port": fid[3],
                    "protocol": fid[4],
                    **verdict,
                })
        return emitted

    for packet in packets:
        if not packet.haslayer(IP):
            continue
        ip = packet[IP]
        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            continue

        pkt_time = float(packet.time)
        if speed_factor > 0:
            target_elapsed = (pkt_time - first_packet_time) / speed_factor
            actual_elapsed = time.perf_counter() - replay_start_wall
            sleep_for = target_elapsed - actual_elapsed
            if sleep_for > 0:
                time.sleep(sleep_for)

        flow_id = (ip.src, ip.dst, src_port, dst_port, protocol)
        state = flow_state[flow_id]
        state["packet_count"] += 1
        state["byte_count"] += len(packet)
        state["timestamps"].append(pkt_time)
        if state["start_time"] is None:
            state["start_time"] = pkt_time
        state["end_time"] = pkt_time

        if packet.haslayer(TCP) and "S" in str(packet[TCP].flags):
            state["syn_count"] += 1

        dns_q = _extract_dns_query(packet, ip)
        if dns_q is not None:
            dns_queries.append(dns_q)

        tls_c = _extract_tls_hello(packet, flow_id)
        if tls_c is not None:
            tls_hellos[tls_c[0]] = tls_c[1]

        tls_s = _extract_tls_server_hello(packet, flow_id)
        if tls_s is not None:
            tls_server_hellos[tls_s[0]] = tls_s[1]

        packets_processed += 1
        if packets_processed % recompute_every == 0:
            elapsed = max(time.perf_counter() - replay_start_wall, 0.001)
            yield {
                "type": "traffic",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "packets": recompute_every,
                "flows_per_second": round(len(flow_state) / elapsed, 1),
                "total_flows": len(flow_state),
            }
            for alert_event in _run_evaluation_pass():
                yield alert_event

    for alert_event in _run_evaluation_pass():
        yield alert_event

    total_wall_time = time.perf_counter() - replay_start_wall
    total_flows = len(flow_state)
    yield {
        "type": "summary",
        "total_packets": packets_processed,
        "total_flows": total_flows,
        "total_alerts": len(already_alerted),
        "wall_time_seconds": round(total_wall_time, 3),
        "flows_per_second": round(total_flows / total_wall_time, 1) if total_wall_time > 0 else 0.0,
        "avg_detection_latency_ms": (
            round(1000.0 * sum(detection_latencies) / len(detection_latencies), 2)
            if detection_latencies else 0.0
        ),
    }