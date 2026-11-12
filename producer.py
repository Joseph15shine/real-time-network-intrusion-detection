
from kafka import KafkaProducer
from scapy.all import sniff, IP, TCP, UDP
import json
from datetime import datetime

producer = KafkaProducer(
    bootstrap_servers="localhost:9092",
    value_serializer=lambda value: json.dumps(value).encode("utf-8")
)

INTERFACE = r"\Device\NPF_{9C36B33C-CD7F-4499-92C4-723F385A756A}"

def process_packet(packet):
    if IP not in packet:
        return

    protocol = "OTHER"
    destination_port = 0

    if TCP in packet:
        protocol = "TCP"
        destination_port = packet[TCP].dport
    elif UDP in packet:
        protocol = "UDP"
        destination_port = packet[UDP].dport

    event = {
        "timestamp": datetime.now().isoformat(),
        "source_ip": packet[IP].src,
        "destination_ip": packet[IP].dst,
        "protocol": protocol,
        "destination_port": destination_port,
        "packet_size": len(packet),
        "event_type": "REAL_NETWORK_TRAFFIC"
    }

    producer.send("network-traffic", event)
    producer.flush()
    print("Captured and sent:", event)

print("REAL NETWORK PACKET CAPTURE STARTED")
print("Listening on your Wi-Fi adapter...")

try:
    sniff(iface=INTERFACE, filter="ip", prn=process_packet, store=False)

except KeyboardInterrupt:
    print("Packet capture stopped")

finally:
    producer.close()
