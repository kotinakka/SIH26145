"""
Phase 3d (TLS) — Real TLS ClientHello metadata extraction (JA3).

Detects malware-in-encrypted-sessions using ONLY the cleartext
ClientHello handshake — no decryption of any kind. The ClientHello
is sent before encryption is established, so reading it is fully
compliant with the passive, read-only, no-decryption constraint.

Honesty note: without a real threat-intel feed of known-malicious
JA3 hashes, we cannot say "this JA3 is a known malware family."
What this DOES give us is a legitimate anomaly signal: real
browsers/OS TLS stacks offer many ciphers and extensions in
predictable patterns; minimal/custom TLS clients (common in
malware toolkits) often offer very few of both, and frequently
skip SNI. That structural shape — not a blacklist lookup — is
what evaluate_encrypted_anomaly() in detector.py will use.
"""

import struct
import hashlib
from scapy.all import IP, TCP, Raw


GREASE_VALUES = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
}


def parse_client_hello(data):
    """
    Parses raw bytes starting at a TLS record header. Returns a
    dict of extracted metadata, or None if this doesn't look like
    a TLS ClientHello.
    """

    if len(data) < 9:
        return None

    content_type, record_version, record_length = struct.unpack(">BHH", data[:5])
    if content_type != 0x16:  # not a Handshake record
        return None

    handshake_type = data[5]
    if handshake_type != 0x01:  # not a ClientHello
        return None

    handshake_length = int.from_bytes(data[6:9], "big")
    body = data[9:9 + handshake_length]

    if len(body) < 34:
        return None

    offset = 0
    client_version = struct.unpack(">H", body[offset:offset + 2])[0]
    offset += 2
    offset += 32  # random

    session_id_len = body[offset]
    offset += 1 + session_id_len

    if offset + 2 > len(body):
        return None
    cipher_suites_len = struct.unpack(">H", body[offset:offset + 2])[0]
    offset += 2
    cipher_bytes = body[offset:offset + cipher_suites_len]
    cipher_suites = [
        struct.unpack(">H", cipher_bytes[i:i + 2])[0]
        for i in range(0, len(cipher_bytes) - 1, 2)
    ]
    offset += cipher_suites_len

    if offset >= len(body):
        return None
    compression_len = body[offset]
    offset += 1 + compression_len

    extensions = []
    sni = None
    supported_groups = []
    ec_point_formats = []

    if offset + 2 <= len(body):
        ext_total_len = struct.unpack(">H", body[offset:offset + 2])[0]
        offset += 2
        ext_end = min(offset + ext_total_len, len(body))

        while offset + 4 <= ext_end:
            ext_type, ext_len = struct.unpack(">HH", body[offset:offset + 4])
            offset += 4
            ext_data = body[offset:offset + ext_len]
            offset += ext_len

            extensions.append(ext_type)

            if ext_type == 0x0000 and len(ext_data) >= 5:  # server_name
                name_len = struct.unpack(">H", ext_data[3:5])[0]
                sni = ext_data[5:5 + name_len].decode(errors="ignore")

            elif ext_type == 0x000a and len(ext_data) >= 2:  # supported_groups
                groups_len = struct.unpack(">H", ext_data[0:2])[0]
                group_bytes = ext_data[2:2 + groups_len]
                supported_groups = [
                    struct.unpack(">H", group_bytes[i:i + 2])[0]
                    for i in range(0, len(group_bytes) - 1, 2)
                ]

            elif ext_type == 0x000b and len(ext_data) >= 1:  # ec_point_formats
                fmt_len = ext_data[0]
                ec_point_formats = list(ext_data[1:1 + fmt_len])

    return {
        "client_version": client_version,
        "cipher_suites": cipher_suites,
        "extensions": extensions,
        "sni": sni,
        "supported_groups": supported_groups,
        "ec_point_formats": ec_point_formats,
    }


def compute_ja3(parsed):
    """
    Computes the standard JA3 string and its MD5 hash. GREASE
    values are stripped per the JA3 spec (browsers insert them
    randomly; they carry no real fingerprinting signal).
    """

    def strip_grease(values):
        return [v for v in values if v not in GREASE_VALUES]

    version = parsed["client_version"]
    ciphers = strip_grease(parsed["cipher_suites"])
    exts = strip_grease(parsed["extensions"])
    groups = strip_grease(parsed["supported_groups"])
    formats = parsed["ec_point_formats"]

    ja3_str = "{},{},{},{},{}".format(
        version,
        "-".join(str(c) for c in ciphers),
        "-".join(str(e) for e in exts),
        "-".join(str(g) for g in groups),
        "-".join(str(f) for f in formats),
    )

    return ja3_str, hashlib.md5(ja3_str.encode()).hexdigest()


def extract_tls_hellos(packets):
    """
    Scans packets for TCP payloads that look like a TLS ClientHello.
    Returns a dict keyed by the exact same 5-tuple flow.py uses
    (src_ip, dst_ip, src_port, dst_port, "TCP"), so results can be
    matched directly onto flow.py's flow records.
    """

    hellos = {}

    for packet in packets:
        if not (packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw)):
            continue

        payload = bytes(packet[Raw].load)
        parsed = parse_client_hello(payload)
        if parsed is None:
            continue

        ja3_str, ja3_hash = compute_ja3(parsed)

        flow_id = (
            packet[IP].src, packet[IP].dst,
            packet[TCP].sport, packet[TCP].dport,
            "TCP",
        )

        hellos[flow_id] = {
            "tls_cipher_count": len(parsed["cipher_suites"]),
            "tls_extension_count": len(parsed["extensions"]),
            "tls_has_sni": parsed["sni"] is not None,
            "tls_sni": parsed["sni"] or "",
            "tls_ja3": ja3_str,
            "tls_ja3_hash": ja3_hash,
        }

    return hellos


def parse_server_hello(data):
    """
    Parses raw bytes starting at a TLS record header. Returns the
    negotiated version, chosen cipher suite and extension list, or None
    if this isn't a TLS ServerHello. The ServerHello is sent in
    cleartext before encryption starts, so reading it needs no decryption.
    """

    if len(data) < 9 or data[0] != 0x16 or data[5] != 0x02:
        return None

    handshake_length = int.from_bytes(data[6:9], "big")
    body = data[9:9 + handshake_length]
    if len(body) < 38:
        return None

    version = struct.unpack(">H", body[0:2])[0]
    offset = 2 + 32  # version + random
    offset += 1 + body[offset]  # session id

    if offset + 3 > len(body):
        return None
    cipher_suite = struct.unpack(">H", body[offset:offset + 2])[0]
    offset += 2
    offset += 1  # compression method

    extensions = []
    if offset + 2 <= len(body):
        ext_total_len = struct.unpack(">H", body[offset:offset + 2])[0]
        offset += 2
        ext_end = min(offset + ext_total_len, len(body))
        while offset + 4 <= ext_end:
            ext_type, ext_len = struct.unpack(">HH", body[offset:offset + 4])
            offset += 4 + ext_len
            extensions.append(ext_type)

    return {
        "server_version": version,
        "cipher_suite": cipher_suite,
        "extensions": extensions,
    }


def compute_ja3s(parsed):
    """
    JA3S: MD5 of "version,cipher,extensions" from the ServerHello. The
    same server answers differently to different clients, so JA3S
    fingerprints the server side (e.g. a C2 framework's TLS listener).
    """

    ja3s_str = "{},{},{}".format(
        parsed["server_version"],
        parsed["cipher_suite"],
        "-".join(str(e) for e in parsed["extensions"]),
    )
    return ja3s_str, hashlib.md5(ja3s_str.encode()).hexdigest()


def extract_tls_server_hellos(packets):
    """
    Scans packets for TLS ServerHellos. Returns a dict keyed by the
    5-tuple of the SERVER-to-CLIENT direction (that's the direction the
    ServerHello travels), so callers match it to the client flow by
    reversing the tuple.
    """

    server_hellos = {}

    for packet in packets:
        if not (packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw)):
            continue

        parsed = parse_server_hello(bytes(packet[Raw].load))
        if parsed is None:
            continue

        ja3s_str, ja3s_hash = compute_ja3s(parsed)

        flow_id = (
            packet[IP].src, packet[IP].dst,
            packet[TCP].sport, packet[TCP].dport,
            "TCP",
        )

        server_hellos[flow_id] = {
            "tls_ja3s": ja3s_str,
            "tls_ja3s_hash": ja3s_hash,
            "tls_server_cipher": parsed["cipher_suite"],
        }

    return server_hellos


if __name__ == "__main__":

    import sys
    from scapy.all import rdpcap

    pcap_file = sys.argv[1] if len(sys.argv) > 1 else "../data/benign_tls.pcap"

    packets = rdpcap(pcap_file)
    hellos = extract_tls_hellos(packets)

    print(f"TLS ClientHellos found: {len(hellos)}\n")

    for flow_id, info in hellos.items():
        print("========== TLS CLIENTHELLO ==========")
        print("Flow:", flow_id)
        print("Cipher count:", info["tls_cipher_count"])
        print("Extension count:", info["tls_extension_count"])
        print("Has SNI:", info["tls_has_sni"], "->", info["tls_sni"] or "(none)")
        print("JA3 hash:", info["tls_ja3_hash"])
        print()