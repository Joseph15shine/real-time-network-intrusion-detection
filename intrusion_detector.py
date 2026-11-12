
from kafka import KafkaConsumer
import json
from collections import defaultdict, deque
import time

consumer = KafkaConsumer(
    "network-traffic",
    bootstrap_servers="localhost:9092",
    auto_offset_reset="latest",
    value_deserializer=lambda x: json.loads(x.decode("utf-8"))
)

print("INTRUSION DETECTION SYSTEM STARTED")
print("Monitoring network traffic...")

# Track traffic from each source IP
traffic_count = defaultdict(deque)
# Track destination ports for each source IP
port_history = defaultdict(set)

# Detection thresholds
TRAFFIC_THRESHOLD = 10
PACKET_SIZE_THRESHOLD = 5000
TIME_WINDOW = 10

for message in consumer:
    event = message.value

    source_ip = event.get("source_ip", "Unknown")
    packet_size = event.get("packet_size", 0)
    current_time = time.time()
    destination_port = event.get("destination_port", 0)

    print("\nTraffic:", event)

    # Track events within the time window
    traffic_count[source_ip].append(current_time)
    port_history[source_ip].add(destination_port)

    while traffic_count[source_ip] and current_time - traffic_count[source_ip][0] > TIME_WINDOW:
        traffic_count[source_ip].popleft()

    # Rule 1: High traffic volume
    if len(traffic_count[source_ip]) > TRAFFIC_THRESHOLD:
        print("🚨 ALERT: Possible DDoS-like traffic from", source_ip)

    # Rule 2: Unusually large packet
    if packet_size > PACKET_SIZE_THRESHOLD:
        print("🚨 ALERT: Unusually large packet from", source_ip)
    # Rule 3: Port scanning detection
    if len(port_history[source_ip]) > 5:
        print("🚨 ALERT: Possible Port Scanning from", source_ip)
