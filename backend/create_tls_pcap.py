"""
Generates two labeled TLS session PCAPs for lab testing:

benign_tls.pcap: a TCP connection carrying a realistic,
    browser-like ClientHello — many modern cipher suites, many
    extensions (ALPN, supported_versions, key_share-style groups),
    SNI present.

encrypted_anomaly.pcap: a TCP connection carrying a minimal,
    malware-toolkit-style ClientHello — very few (old) cipher
    suites, no extensions, no SNI. This is the actual PS-named
    signal (TLS metadata shape), replacing the old port+volume
    heuristic.
"""

import struct
import time
from scapy.all import IP, TCP, Raw, wrpcap


def build_client_hello(client_version, cipher_suites, extensions, sni=None):
    random_bytes = b"\x00" * 32
    session_id = b""

    cipher_bytes = b"".join(struct.pack(">H", c) for c in cipher_suites)
    compression_methods = b"\x00"

    ext_list = list(extensions)
    if sni:
        hostname = sni.encode()
        server_name_entry = struct.pack(">BH", 0, len(hostname)) + hostname
        sni_ext_data = struct.pack(">H", len(server_name_entry)) + server_name_entry
        ext_list.append((0x0000, sni_ext_data))

    ext_bytes = b""
    for ext_type, ext_data in ext_list:
        ext_bytes += struct.pack(">HH", ext_type, len(ext_data)) + ext_data

    body = (
        struct.pack(">H", client_version)
        + random_bytes
        + struct.pack(">B", len(session_id)) + session_id
        + struct.pack(">H", len(cipher_bytes)) + cipher_bytes
        + struct.pack(">B", len(compression_methods)) + compression_methods
        + struct.pack(">H", len(ext_bytes)) + ext_bytes
    )

    handshake = struct.pack(">B", 0x01) + struct.pack(">I", len(body))[1:] + body
    record = struct.pack(">BHH", 0x16, 0x0301, len(handshake)) + handshake

    return record


def _tls_session(src_ip, dst_ip, sport, dport, hello_bytes, base_time):
    """Wraps a ClientHello payload in a minimal but realistic TCP
    session shape: SYN, ACK, then the ClientHello as data."""

    packets = []
    t = base_time

    pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="S")
    pkt.time = t
    packets.append(pkt)

    t += 0.02
    pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="A")
    pkt.time = t
    packets.append(pkt)

    t += 0.01
    pkt = (
        IP(src=src_ip, dst=dst_ip)
        / TCP(sport=sport, dport=dport, flags="PA")
        / Raw(load=hello_bytes)
    )
    pkt.time = t
    packets.append(pkt)

    return packets


def create_benign_tls():
    ciphers = [
        0x1301, 0x1302, 0x1303,
        0xc02b, 0xc02f, 0xc02c, 0xc030,
        0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
    ]
    extensions = [
        (0x0017, b""),
        (0xff01, b"\x00"),
        (0x000a, struct.pack(">H", 8) + struct.pack(">HHHH", 0x001d, 0x0017, 0x0018, 0x0019)),
        (0x000b, struct.pack(">B", 1) + b"\x00"),
        (0x0023, b""),
        (0x0010, struct.pack(">H", 14) + struct.pack(">H", 12) + b"\x02h2\x08http/1.1"),
        (0x002b, struct.pack(">B", 2) + struct.pack(">H", 0x0304)),
        (0x000d, struct.pack(">H", 4) + struct.pack(">HH", 0x0403, 0x0804)),
    ]
    hello = build_client_hello(0x0303, ciphers, extensions, sni="www.example.com")
    return _tls_session("192.168.1.90", "203.0.113.40", 54000, 443, hello, time.time())


def create_encrypted_anomaly():
    ciphers = [0x002f, 0x0035]  # only 2 old ciphers
    extensions = []  # no extensions at all
    hello = build_client_hello(0x0301, ciphers, extensions, sni=None)
    return _tls_session("192.168.1.70", "203.0.113.20", 52000, 8443, hello, time.time())


benign_tls = create_benign_tls()
encrypted_anomaly = create_encrypted_anomaly()

wrpcap("../data/benign_tls.pcap", benign_tls)
wrpcap("../data/encrypted_anomaly.pcap", encrypted_anomaly)

print("Created:")
print("  benign_tls.pcap         ->", len(benign_tls), "packets")
print("  encrypted_anomaly.pcap  ->", len(encrypted_anomaly), "packets")