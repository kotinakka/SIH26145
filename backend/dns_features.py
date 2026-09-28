"""
Phase 3c+ (DNS) — Real DNS query-content feature extraction.

Computes Shannon entropy, character bigram naturalness (n-gram analysis),
digit ratio, query label length, and unusual DNS record-type ratio
(TXT/NULL/ANY queries used by dnscat2/iodine).
"""

import math
from collections import defaultdict
from scapy.all import IP, UDP, DNS

# Top English/domain character bigrams for n-gram naturalness scoring
COMMON_BIGRAMS = {
    "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
    "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar",
    "st", "to", "nt", "ng", "se", "ha", "as", "ou", "io", "le",
    "ve", "co", "me", "de", "hi", "ri", "ro", "ic", "ne", "ea",
    "ra", "ce", "li", "ch", "ll", "be", "ma", "si", "om", "ur",
    "ca", "el", "ta", "la", "ns", "di", "fo", "ho", "pe", "ec",
    "pr", "no", "ct", "us", "ac", "ot", "il", "tr", "ly", "nc",
    "et", "ut", "ss", "so", "rs", "un", "lo", "wa", "ge", "ie",
    "wh", "ee", "wi", "em", "ad", "ol", "rt", "po", "we", "na",
    "ul", "ni", "ts", "mo", "ow", "pa", "im", "mi", "ai", "sh",
    "go", "oo", "gl", "ex", "am", "mp", "pl", "cl", "ud", "fl",
    "up", "da", "cr", "os", "ft", "gi", "hu", "ub", "pi", "cd", "dn",
}

# Standard lookup record types: A (1), AAAA (28), CNAME (5), PTR (12)
# Tunneling tools (dnscat2, iodine) heavily abuse TXT (16), NULL (10), MX (15), SRV (33), ANY (255)
STANDARD_QTYPES = {1, 5, 12, 28}


def shannon_entropy(s):
    if not s:
        return 0.0
    freq = defaultdict(int)
    for ch in s:
        freq[ch] += 1
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def digit_ratio(s):
    if not s:
        return 0.0
    return sum(ch.isdigit() for ch in s) / len(s)


def bigram_score(s):
    """
    Fraction of adjacent character pairs (2-grams) that appear in common
    domain/English bigrams. Normal domain labels score high (~0.60-0.95);
    DGA and random base32/hex labels score low (~0.05-0.30).
    """
    s = s.lower()
    if len(s) < 2:
        return 1.0
    pairs = [s[i : i + 2] for i in range(len(s) - 1)]
    hits = sum(1 for p in pairs if p in COMMON_BIGRAMS)
    return hits / len(pairs)


def extract_dns_queries(packets):
    queries = []

    for packet in packets:
        if not packet.haslayer(IP) or not packet.haslayer(UDP) or not packet.haslayer(DNS):
            continue

        dns_layer = packet[DNS]
        if dns_layer.qr != 0 or dns_layer.qd is None:
            continue

        qname = dns_layer.qd.qname
        if isinstance(qname, bytes):
            qname = qname.decode(errors="ignore")
        qname = qname.rstrip(".")

        qtype = int(getattr(dns_layer.qd, "qtype", 1))
        label_part = qname.split(".")[0] if "." in qname else qname

        queries.append({
            "src_ip": packet[IP].src,
            "domain": qname,
            "label_length": len(label_part),
            "entropy": shannon_entropy(label_part),
            "digit_ratio": digit_ratio(label_part),
            "bigram_score": bigram_score(label_part),
            "qtype": qtype,
            "is_unusual_qtype": qtype not in STANDARD_QTYPES,
            "timestamp": float(packet.time),
        })

    return queries


def aggregate_dns_by_source(queries):
    by_source = defaultdict(list)
    for q in queries:
        by_source[q["src_ip"]].append(q)

    aggregates = {}

    for src_ip, qlist in by_source.items():
        n = len(qlist)
        avg_label_length = sum(q["label_length"] for q in qlist) / n
        avg_entropy = sum(q["entropy"] for q in qlist) / n
        avg_digit_ratio = sum(q["digit_ratio"] for q in qlist) / n
        avg_bigram_score = sum(q["bigram_score"] for q in qlist) / n
        unusual_qtype_ratio = sum(1 for q in qlist if q["is_unusual_qtype"]) / n

        timestamps = sorted(q["timestamp"] for q in qlist)
        duration = max(timestamps[-1] - timestamps[0], 0.001)
        queries_per_second = n / duration

        aggregates[src_ip] = {
            "dns_query_count": n,
            "dns_avg_label_length": avg_label_length,
            "dns_avg_entropy": avg_entropy,
            "dns_avg_digit_ratio": avg_digit_ratio,
            "dns_avg_bigram_score": avg_bigram_score,
            "dns_unusual_qtype_ratio": unusual_qtype_ratio,
            "dns_queries_per_second": queries_per_second,
        }

    return aggregates