import time
import random
import string
from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap


def create_benign():
    packets = []
    base_time = time.time()
    for flow_index in range(10):
        sport = 5000 + flow_index
        dport = 80
        t = base_time + (flow_index * 2.0)

        pkt = IP(src="192.168.1.10", dst="10.0.0.5") / TCP(sport=sport, dport=dport, flags="S")
        pkt.time = t
        packets.append(pkt)

        t += 0.05
        pkt = IP(src="192.168.1.10", dst="10.0.0.5") / TCP(sport=sport, dport=dport, flags="A")
        pkt.time = t
        packets.append(pkt)

        for _ in range(5):
            t += 0.2
            pkt = (
                IP(src="192.168.1.10", dst="10.0.0.5")
                / TCP(sport=sport, dport=dport, flags="PA")
                / Raw(load=b"X" * 100)
            )
            pkt.time = t
            packets.append(pkt)

        t += 0.1
        pkt = IP(src="192.168.1.10", dst="10.0.0.5") / TCP(sport=sport, dport=dport, flags="FA")
        pkt.time = t
        packets.append(pkt)
    return packets


def create_ddos():
    packets = []
    for i in range(1000):
        packet = (
            IP(src=f"192.168.1.{(i % 200) + 1}", dst="10.0.0.5")
            / TCP(sport=4000 + (i % 100), dport=80, flags="S")
        )
        packets.append(packet)
    return packets


def create_port_scan():
    packets = []
    for port in range(1, 101):
        packet = (
            IP(src="192.168.1.20", dst="10.0.0.5")
            / TCP(sport=6000, dport=port, flags="S")
        )
        packets.append(packet)
    return packets


def create_c2_beacon():
    packets = []
    base_time = time.time()
    sport = 51000
    dport = 4444
    t = base_time

    pkt = IP(src="192.168.1.50", dst="203.0.113.9") / TCP(sport=sport, dport=dport, flags="S")
    pkt.time = t
    packets.append(pkt)

    t += 0.05
    pkt = IP(src="192.168.1.50", dst="203.0.113.9") / TCP(sport=sport, dport=dport, flags="A")
    pkt.time = t
    packets.append(pkt)

    for _ in range(6):
        t += 25.0
        pkt = (
            IP(src="192.168.1.50", dst="203.0.113.9")
            / TCP(sport=sport, dport=dport, flags="PA")
            / Raw(load=b"hb")
        )
        pkt.time = t
        packets.append(pkt)
    return packets


def create_benign_dns():
    domains = [
        "google.com",
        "example.org",
        "mail.google.com",
        "cdn.cloudflare.net",
        "api.github.com",
        "update.microsoft.com",
    ]
    packets = []
    t = time.time()
    for i, domain in enumerate(domains):
        pkt = (
            IP(src="192.168.1.10", dst="8.8.8.8")
            / UDP(sport=33000 + i, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=domain))
        )
        pkt.time = t
        packets.append(pkt)
        t += 3.0
    return packets


def create_dns_tunnel():
    packets = []
    t = time.time()
    for i in range(40):
        label = "".join(random.choices(string.ascii_lowercase + string.digits, k=32))
        pkt = (
            IP(src="192.168.1.60", dst="8.8.8.8")
            / UDP(sport=40000 + i, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=f"{label}.tunnel.example.com", qtype=16))
        )
        pkt.time = t
        packets.append(pkt)
        t += 0.1
    return packets


def create_data_exfil():
    packets = []
    t = time.time()
    sport = 53500
    dport = 443

    pkt = IP(src="192.168.1.80", dst="203.0.113.30") / TCP(sport=sport, dport=dport, flags="S")
    pkt.time = t
    packets.append(pkt)

    for i in range(250):
        t += 0.02
        pkt = (
            IP(src="192.168.1.80", dst="203.0.113.30")
            / TCP(sport=sport, dport=dport, flags="PA")
            / Raw(load=b"D" * 1200)
        )
        pkt.time = t
        packets.append(pkt)

        if i % 10 == 9:
            ack = IP(src="203.0.113.30", dst="192.168.1.80") / TCP(sport=dport, dport=sport, flags="A")
            ack.time = t + 0.001
            packets.append(ack)
    return packets


def create_benign_download():
    packets = []
    t = time.time()
    sport = 55000
    dport = 443

    pkt = IP(src="192.168.1.90", dst="203.0.113.50") / TCP(sport=sport, dport=dport, flags="S")
    pkt.time = t
    packets.append(pkt)

    for i in range(250):
        t += 0.02
        pkt = (
            IP(src="203.0.113.50", dst="192.168.1.90")
            / TCP(sport=dport, dport=sport, flags="PA")
            / Raw(load=b"R" * 1200)
        )
        pkt.time = t
        packets.append(pkt)

        if i % 10 == 9:
            ack = IP(src="192.168.1.90", dst="203.0.113.50") / TCP(sport=sport, dport=dport, flags="A")
            ack.time = t + 0.001
            packets.append(ack)
    return packets


def _checkin_connections(src, dst, dport, start_offsets, base_time, sport0):
    packets = []
    for i, off in enumerate(start_offsets):
        sport = sport0 + i
        t = base_time + off
        for flags, payload in (
            ("S", None),
            ("A", None),
            ("PA", b"chk-in:" + bytes([65 + i % 26]) * 12),
            ("FA", None),
        ):
            pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
            if payload:
                pkt = pkt / Raw(load=payload)
            pkt.time = t
            packets.append(pkt)
            t += 0.05
    return packets


def create_c2_multiconn():
    offsets = [i * 30.0 + j for i, j in enumerate([0.0, 0.8, -0.6, 0.4, -0.9, 0.7, -0.3, 0.5])]
    return _checkin_connections("192.168.1.55", "203.0.113.9", 8080, offsets, time.time(), 47000)


def create_irregular_multiconn():
    gaps = [0, 4, 75, 12, 96, 20, 8, 61]
    offsets, t = [], 0.0
    for g in gaps:
        t += g
        offsets.append(t)
    return _checkin_connections("192.168.1.56", "203.0.113.10", 8080, offsets, time.time(), 48000)


def create_udp_flood():
    """Simulates hping3 --udp --flood --rand-source amplification/volumetric flood."""
    packets = []
    base_time = time.time()
    for i in range(600):
        pkt = (
            IP(src=f"192.168.1.{(i % 150) + 1}", dst="10.0.0.5")
            / UDP(sport=53, dport=80)
            / Raw(load=b"U" * 512)
        )
        pkt.time = base_time + (i * 0.002)
        packets.append(pkt)
    return packets


def create_slowloris():
    """Simulates Slowloris slow HTTP connection exhaustion (25 parallel slow streams)."""
    packets = []
    base_time = time.time()
    for conn_idx in range(25):
        sport = 42000 + conn_idx
        t = base_time + (conn_idx * 0.05)
        for flags, payload, dt in [
            ("S", None, 0.0),
            ("PA", b"GET / HTTP/1.1\r\n", 0.1),
            ("PA", b"X-a: b\r\n", 8.0),
            ("PA", b"X-c: d\r\n", 8.0),
        ]:
            t += dt
            pkt = IP(src="192.168.1.45", dst="10.0.0.5") / TCP(sport=sport, dport=80, flags=flags)
            if payload:
                pkt = pkt / Raw(load=payload)
            pkt.time = t
            packets.append(pkt)
    return packets


def create_dga_dns():
    """Simulates a seeded LCG PRNG DGA (Ramnit/Cryptolocker style) querying 12-15 char domains."""
    packets = []
    base_time = time.time()
    val = 0x1337BEEF
    tlds = ["com", "net", "org", "biz"]
    for i in range(25):
        length = 12 + (i % 4)
        chars = []
        for _ in range(length):
            val = (1103515245 * val + 12345) & 0x7FFFFFFF
            chars.append(chr(ord("a") + (val % 26)))
        dga_domain = f"{''.join(chars)}.{tlds[i % len(tlds)]}"
        pkt = (
            IP(src="192.168.1.65", dst="8.8.8.8")
            / UDP(sport=45000 + i, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=dga_domain, qtype=1))
        )
        pkt.time = base_time + (i * 0.25)
        packets.append(pkt)
    return packets


def create_host_sweep():
    """Simulates horizontal reconnaissance scanning port 22 across 35 internal hosts."""
    packets = []
    base_time = time.time()
    for host_idx in range(1, 36):
        pkt = (
            IP(src="192.168.1.25", dst=f"10.0.0.{host_idx}")
            / TCP(sport=6100 + host_idx, dport=22, flags="S")
        )
        pkt.time = base_time + (host_idx * 0.02)
        packets.append(pkt)
    return packets


benign = create_benign()
ddos = create_ddos()
port_scan = create_port_scan()
c2_beacon = create_c2_beacon()
dns_tunnel = create_dns_tunnel()
data_exfil = create_data_exfil()
benign_dns = create_benign_dns()
benign_download = create_benign_download()
c2_multiconn = create_c2_multiconn()
irregular_multiconn = create_irregular_multiconn()
udp_flood = create_udp_flood()
slowloris = create_slowloris()
dga_dns = create_dga_dns()
host_sweep = create_host_sweep()

wrpcap("../data/benign.pcap", benign)
wrpcap("../data/ddos.pcap", ddos)
wrpcap("../data/port_scan.pcap", port_scan)
wrpcap("../data/c2_beacon.pcap", c2_beacon)
wrpcap("../data/dns_tunnel.pcap", dns_tunnel)
wrpcap("../data/data_exfil.pcap", data_exfil)
wrpcap("../data/benign_dns.pcap", benign_dns)
wrpcap("../data/benign_download.pcap", benign_download)
wrpcap("../data/c2_multiconn.pcap", c2_multiconn)
wrpcap("../data/irregular_multiconn.pcap", irregular_multiconn)
wrpcap("../data/udp_flood.pcap", udp_flood)
wrpcap("../data/slowloris.pcap", slowloris)
wrpcap("../data/dga_dns.pcap", dga_dns)
wrpcap("../data/host_sweep.pcap", host_sweep)

print("Created:")
print("  benign.pcap             ->", len(benign), "packets")
print("  ddos.pcap               ->", len(ddos), "packets")
print("  udp_flood.pcap          ->", len(udp_flood), "packets")
print("  slowloris.pcap          ->", len(slowloris), "packets")
print("  port_scan.pcap          ->", len(port_scan), "packets")
print("  host_sweep.pcap         ->", len(host_sweep), "packets")
print("  c2_beacon.pcap          ->", len(c2_beacon), "packets")
print("  c2_multiconn.pcap       ->", len(c2_multiconn), "packets")
print("  irregular_multiconn.pcap->", len(irregular_multiconn), "packets")
print("  dns_tunnel.pcap         ->", len(dns_tunnel), "packets")
print("  dga_dns.pcap            ->", len(dga_dns), "packets")
print("  data_exfil.pcap         ->", len(data_exfil), "packets")
print("  benign_dns.pcap         ->", len(benign_dns), "packets")
print("  benign_download.pcap    ->", len(benign_download), "packets")
# Combine all 6 threat categories into one multi-vector capture for live demo
from create_tls_pcap import create_encrypted_anomaly as create_tls_anom

all_threats = (
    benign
    + ddos
    + port_scan
    + c2_multiconn
    + dns_tunnel
    + create_tls_anom()
    + data_exfil
)
# Sort packets chronologically so stream_detect replays them smoothly
all_threats.sort(key=lambda pkt: float(pkt.time))
wrpcap("../data/all_threats.pcap", all_threats)
print("  all_threats.pcap        ->", len(all_threats), "packets (ALL 6 THREATS)")