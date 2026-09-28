from scapy.all import rdpcap

pcap_file = "../data/test.pcap"

packets = rdpcap(pcap_file)

print("Total packets:", len(packets))

for packet in packets[:10]:
    print(packet.summary())