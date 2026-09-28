"""
Generates the JA3 / JA3S demonstration captures:

ja3_demo.pcap      client JA3 is on the blocklist (handshake otherwise normal)
ja3s_demo.pcap     client JA3 is NOT listed, but the SERVER's JA3S is
ja3s_control.pcap  same client, different (unlisted) server -> must stay clean

Both hashes are deterministic, so the LAB-DEMO lines in ja3_blocklist.csv
stay valid. No real malware fingerprints are used.
"""

import struct
import time
from scapy.all import IP, TCP, Raw, wrpcap
from tls_features import (
    parse_client_hello, compute_ja3, parse_server_hello, compute_ja3s,
)


def build_client_hello(client_version, cipher_suites, extensions, sni=None):
    cipher_bytes = b"".join(struct.pack(">H", c) for c in cipher_suites)
    ext_list = list(extensions)
    if sni:
        host = sni.encode()
        entry = struct.pack(">BH", 0, len(host)) + host
        ext_list.append((0x0000, struct.pack(">H", len(entry)) + entry))
    ext_bytes = b"".join(struct.pack(">HH", t, len(d)) + d for t, d in ext_list)
    body = (
        struct.pack(">H", client_version) + b"\x00" * 32 + b"\x00"
        + struct.pack(">H", len(cipher_bytes)) + cipher_bytes
        + b"\x01\x00" + struct.pack(">H", len(ext_bytes)) + ext_bytes
    )
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return struct.pack(">BHH", 0x16, 0x0301, len(hs)) + hs


def build_server_hello(version, cipher, extensions):
    ext_bytes = b"".join(struct.pack(">HH", t, len(d)) + d for t, d in extensions)
    body = (
        struct.pack(">H", version) + b"\x00" * 32 + b"\x00"
        + struct.pack(">H", cipher) + b"\x00"
        + struct.pack(">H", len(ext_bytes)) + ext_bytes
    )
    hs = b"\x02" + struct.pack(">I", len(body))[1:] + body
    return struct.pack(">BHH", 0x16, 0x0303, len(hs)) + hs


def session(client, server, sport, dport, client_hello, server_hello=None):
    """SYN, SYN-ACK, ACK, ClientHello, then (optionally) ServerHello."""
    steps = [
        (client, server, sport, dport, "S", None),
        (server, client, dport, sport, "SA", None),
        (client, server, sport, dport, "A", None),
        (client, server, sport, dport, "PA", client_hello),
    ]
    if server_hello:
        steps.append((server, client, dport, sport, "PA", server_hello))

    t = time.time()
    packets = []
    for src, dst, sp, dp, flags, payload in steps:
        t += 0.01
        p = IP(src=src, dst=dst) / TCP(sport=sp, dport=dp, flags=flags)
        if payload:
            p = p / Raw(load=payload)
        p.time = t
        packets.append(p)
    return packets


EXTS = [
    (0x0017, b""), (0xff01, b"\x00"),
    (0x000a, struct.pack(">H", 4) + struct.pack(">HH", 0x001d, 0x0017)),
    (0x000b, b"\x01\x00"), (0x0023, b""),
    (0x002b, b"\x02" + struct.pack(">H", 0x0303)),
    (0x000d, struct.pack(">H", 4) + struct.pack(">HH", 0x0403, 0x0804)),
]
CIPHERS_A = [0x1301, 0x1302, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x0035]
CIPHERS_B = CIPHERS_A + [0x009d]   # different list -> different JA3

# 1) client-side JA3 listed
hello_a = build_client_hello(0x0303, CIPHERS_A, EXTS, sni="updates.example.net")
wrpcap("../data/ja3_demo.pcap",
       session("192.168.1.95", "203.0.113.60", 56000, 443, hello_a))
print("ja3_demo.pcap     JA3  =", compute_ja3(parse_client_hello(hello_a))[1])

# 2) server-side JA3S listed, client is unlisted
hello_b = build_client_hello(0x0303, CIPHERS_B, EXTS, sni="cdn.example.net")
srv_bad = build_server_hello(0x0303, 0xc02f, [(0xff01, b"\x00"), (0x000b, b"\x01\x00"), (0x0023, b"")])
wrpcap("../data/ja3s_demo.pcap",
       session("192.168.1.96", "203.0.113.61", 57000, 443, hello_b, srv_bad))
print("ja3s_demo.pcap    JA3  =", compute_ja3(parse_client_hello(hello_b))[1])
print("ja3s_demo.pcap    JA3S =", compute_ja3s(parse_server_hello(srv_bad))[1])

# 3) control: same client, ordinary server
srv_ok = build_server_hello(0x0303, 0x1301, [(0x002b, b"\x03\x04"), (0x0033, b"\x00\x00")])
wrpcap("../data/ja3s_control.pcap",
       session("192.168.1.97", "203.0.113.62", 58000, 443, hello_b, srv_ok))
print("ja3s_control.pcap JA3S =", compute_ja3s(parse_server_hello(srv_ok))[1])
