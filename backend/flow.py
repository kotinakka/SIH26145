import math
import ipaddress
from collections import defaultdict
from scapy.all import rdpcap, IP, TCP, UDP
import sys


_INTERNAL_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def _is_internal(ip_str):
    """
    True only for RFC1918 space. Deliberately NOT ipaddress.is_private:
    that also treats the documentation ranges (192.0.2.0/24,
    198.51.100.0/24, 203.0.113.0/24) as private, which are exactly
    the ranges our lab pcaps use to stand in for "external" hosts.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(addr in net for net in _INTERNAL_NETS)


def _attach_pair_direction_stats(flows):
    """
    Outbound/inbound byte accounting per host pair, for data-exfil
    detection (PS: "asymmetric flow-volume anomalies and unusual
    outbound-to-inbound byte ratios").
    """
    bytes_between = defaultdict(int)
    for f in flows:
        bytes_between[(f["src_ip"], f["dst_ip"])] += f["byte_count"]

    for f in flows:
        out_b = bytes_between[(f["src_ip"], f["dst_ip"])]
        in_b = bytes_between.get((f["dst_ip"], f["src_ip"]), 0)
        f["pair_bytes_out"] = out_b
        f["pair_bytes_in"] = in_b
        f["out_in_ratio"] = out_b / max(in_b, 1)
        f["is_outbound"] = _is_internal(f["src_ip"]) and not _is_internal(f["dst_ip"])


def _attach_beacon_group_stats(flows):
    """
    Cross-connection C2 beacon periodicity. Groups flows by
    (src_ip, dst_ip, dst_port, protocol) and measures the regularity
    of the gaps between successive connection START times.
    """
    groups = defaultdict(list)
    for f in flows:
        groups[(f["src_ip"], f["dst_ip"], f["dst_port"], f["protocol"])].append(f)

    for members in groups.values():
        starts = sorted(m["start_time"] for m in members)
        stats = {
            "beacon_conn_count": len(members),
            "beacon_span_seconds": 0.0,
            "beacon_mean_interval": None,
            "beacon_interval_cv": None,
            "beacon_bytes_per_conn": sum(m["byte_count"] for m in members) / len(members),
        }
        if len(starts) >= 3:
            gaps = [b - a for a, b in zip(starts, starts[1:])]
            mean_gap = sum(gaps) / len(gaps)
            stats["beacon_span_seconds"] = starts[-1] - starts[0]
            stats["beacon_mean_interval"] = mean_gap
            if mean_gap > 0:
                var = sum((g - mean_gap) ** 2 for g in gaps) / len(gaps)
                stats["beacon_interval_cv"] = (var ** 0.5) / mean_gap
        for m in members:
            m.update(stats)


def _entropy_of_counts(counts_by_key):
    """
    Shannon entropy (bits) of a distribution given as {key: count}.
    """
    total = sum(counts_by_key.values())
    if total == 0:
        return 0.0

    entropy = 0.0
    for count in counts_by_key.values():
        if count == 0:
            continue
        p = count / total
        entropy -= p * math.log2(p)

    return entropy


def _interval_stats(timestamps):
    """
    Inter-arrival statistics for C2 beacon periodicity.
    """
    if len(timestamps) < 3:
        return {
            "mean_interval_seconds": None,
            "interval_cv": None,
            "inter_arrival_count": 0,
        }

    ordered = sorted(timestamps)
    intervals = [b - a for a, b in zip(ordered, ordered[1:])]

    mean_interval = sum(intervals) / len(intervals)
    if mean_interval == 0:
        return {
            "mean_interval_seconds": 0.0,
            "interval_cv": None,
            "inter_arrival_count": len(intervals),
        }

    variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
    std_interval = variance ** 0.5
    interval_cv = std_interval / mean_interval

    return {
        "mean_interval_seconds": mean_interval,
        "interval_cv": interval_cv,
        "inter_arrival_count": len(intervals),
    }


def extract_flows(pcap_file):
    packets = rdpcap(pcap_file)

    flows = defaultdict(lambda: {
        "packet_count": 0,
        "byte_count": 0,
        "syn_count": 0,
        "start_time": None,
        "end_time": None,
        "timestamps": [],
    })

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

        flow_id = (ip.src, ip.dst, src_port, dst_port, protocol)
        flow = flows[flow_id]

        flow["packet_count"] += 1
        flow["byte_count"] += len(packet)

        current_time = float(packet.time)
        if flow["start_time"] is None:
            flow["start_time"] = current_time
        flow["end_time"] = current_time
        flow["timestamps"].append(current_time)

        if packet.haslayer(TCP):
            if "S" in str(packet[TCP].flags):
                flow["syn_count"] += 1

    results = []
    for flow_id, flow in flows.items():
        duration = max(flow["end_time"] - flow["start_time"], 0.001)
        packets_per_second = flow["packet_count"] / duration
        bytes_per_second = flow["byte_count"] / duration
        syn_ratio = flow["syn_count"] / flow["packet_count"]

        results.append({
            "src_ip": flow_id[0],
            "dst_ip": flow_id[1],
            "src_port": flow_id[2],
            "dst_port": flow_id[3],
            "protocol": flow_id[4],
            "packet_count": flow["packet_count"],
            "byte_count": flow["byte_count"],
            "duration": duration,
            "packets_per_second": packets_per_second,
            "bytes_per_second": bytes_per_second,
            "syn_count": flow["syn_count"],
            "syn_ratio": syn_ratio,
            "start_time": flow["start_time"],
            **_interval_stats(flow["timestamps"]),
        })

    return results


def aggregate_by_source_ip(results):
    source_ports = defaultdict(set)
    source_ips = defaultdict(set)

    for flow in results:
        src_ip = flow["src_ip"]
        source_ports[src_ip].add(flow["dst_port"])
        source_ips[src_ip].add(flow["dst_ip"])

    aggregates = {}
    for src_ip in source_ports:
        aggregates[src_ip] = {
            "unique_dst_ports": len(source_ports[src_ip]),
            "unique_dst_ips": len(source_ips[src_ip]),
        }

    return aggregates


def attach_source_aggregates(results):
    aggregates = aggregate_by_source_ip(results)
    for flow in results:
        src_ip = flow["src_ip"]
        flow["unique_dst_ports"] = aggregates[src_ip]["unique_dst_ports"]
        flow["unique_dst_ips"] = aggregates[src_ip]["unique_dst_ips"]
    return results


def aggregate_by_destination_ip(results):
    dest_sources = defaultdict(set)
    dest_packets = defaultdict(int)
    dest_bytes = defaultdict(int)
    dest_syns = defaultdict(int)
    dest_udp_packets = defaultdict(int)
    dest_source_packet_counts = defaultdict(lambda: defaultdict(int))

    for flow in results:
        dst_ip = flow["dst_ip"]
        dest_sources[dst_ip].add(flow["src_ip"])
        dest_packets[dst_ip] += flow["packet_count"]
        dest_bytes[dst_ip] += flow["byte_count"]
        dest_syns[dst_ip] += flow["syn_count"]
        if flow["protocol"] == "UDP":
            dest_udp_packets[dst_ip] += flow["packet_count"]
        dest_source_packet_counts[dst_ip][flow["src_ip"]] += flow["packet_count"]

    aggregates = {}
    for dst_ip in dest_sources:
        total_packets = dest_packets[dst_ip]
        total_syns = dest_syns[dst_ip]
        total_udp = dest_udp_packets[dst_ip]

        dest_syn_ratio = total_syns / total_packets if total_packets > 0 else 0.0
        dest_udp_ratio = total_udp / total_packets if total_packets > 0 else 0.0

        aggregates[dst_ip] = {
            "unique_src_ips": len(dest_sources[dst_ip]),
            "total_packets_to_dest": total_packets,
            "total_bytes_to_dest": dest_bytes[dst_ip],
            "total_syn_to_dest": total_syns,
            "dest_syn_ratio": dest_syn_ratio,
            "dest_udp_ratio": dest_udp_ratio,
            "dest_src_ip_entropy": _entropy_of_counts(dest_source_packet_counts[dst_ip]),
        }

    return aggregates


def attach_destination_aggregates(results):
    aggregates = aggregate_by_destination_ip(results)
    for flow in results:
        dst_ip = flow["dst_ip"]
        flow["unique_src_ips"] = aggregates[dst_ip]["unique_src_ips"]
        flow["total_packets_to_dest"] = aggregates[dst_ip]["total_packets_to_dest"]
        flow["total_bytes_to_dest"] = aggregates[dst_ip]["total_bytes_to_dest"]
        flow["total_syn_to_dest"] = aggregates[dst_ip]["total_syn_to_dest"]
        flow["dest_syn_ratio"] = aggregates[dst_ip]["dest_syn_ratio"]
        flow["dest_udp_ratio"] = aggregates[dst_ip]["dest_udp_ratio"]
        flow["dest_src_ip_entropy"] = aggregates[dst_ip]["dest_src_ip_entropy"]

    _attach_pair_direction_stats(results)
    _attach_beacon_group_stats(results)
    return results


def attach_dns_aggregates(results, pcap_file):
    from scapy.all import rdpcap
    from dns_features import extract_dns_queries, aggregate_dns_by_source

    packets = rdpcap(pcap_file)
    queries = extract_dns_queries(packets)
    dns_aggregates = aggregate_dns_by_source(queries)

    for flow in results:
        is_dns_flow = flow["src_port"] == 53 or flow["dst_port"] == 53
        if is_dns_flow and flow["src_ip"] in dns_aggregates:
            flow.update(dns_aggregates[flow["src_ip"]])
        else:
            flow.setdefault("dns_query_count", 0)
            flow.setdefault("dns_avg_label_length", 0)
            flow.setdefault("dns_avg_entropy", 0)
            flow.setdefault("dns_avg_digit_ratio", 0)
            flow.setdefault("dns_avg_bigram_score", 1.0)
            flow.setdefault("dns_unusual_qtype_ratio", 0.0)
            flow.setdefault("dns_queries_per_second", 0)

    return results


def attach_tls_aggregates(results, pcap_file):
    from scapy.all import rdpcap
    from tls_features import extract_tls_hellos, extract_tls_server_hellos

    packets = rdpcap(pcap_file)
    hellos = extract_tls_hellos(packets)
    server_hellos = extract_tls_server_hellos(packets)

    for flow in results:
        flow_id = (
            flow["src_ip"], flow["dst_ip"],
            flow["src_port"], flow["dst_port"],
            flow["protocol"],
        )

        if flow_id in hellos:
            flow.update(hellos[flow_id])
        else:
            flow.setdefault("tls_cipher_count", 0)
            flow.setdefault("tls_extension_count", 0)
            flow.setdefault("tls_has_sni", False)
            flow.setdefault("tls_sni", "")
            flow.setdefault("tls_ja3", "")
            flow.setdefault("tls_ja3_hash", "")

        reverse_id = (
            flow["dst_ip"], flow["src_ip"],
            flow["dst_port"], flow["src_port"],
            flow["protocol"],
        )
        server_info = server_hellos.get(flow_id) or server_hellos.get(reverse_id)
        if server_info:
            flow.update(server_info)
        else:
            flow.setdefault("tls_ja3s", "")
            flow.setdefault("tls_ja3s_hash", "")
            flow.setdefault("tls_server_cipher", 0)

    return results


if __name__ == "__main__":
    pcap_file = sys.argv[1] if len(sys.argv) > 1 else "../data/test.pcap"
    results = extract_flows(pcap_file)
    results = attach_source_aggregates(results)
    results = attach_destination_aggregates(results)
    results = attach_dns_aggregates(results, pcap_file)
    results = attach_tls_aggregates(results, pcap_file)
    print("Total flows:", len(results))