
import streamlit as st
from kafka import KafkaConsumer
import json
import pandas as pd
import time
from collections import defaultdict, deque
from datetime import datetime

st.set_page_config(
    page_title="Network Intrusion Detection",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Real-Time Network Intrusion Detection System")
st.caption("Powered by Apache Kafka and Python")

# Connect to Kafka
@st.cache_resource
def get_consumer():
    return KafkaConsumer(
        "network-traffic",
        bootstrap_servers="localhost:9092",
        auto_offset_reset="latest",
        group_id="dashboard-group",
        value_deserializer=lambda x: json.loads(x.decode("utf-8"))
    )

consumer = get_consumer()

if "events" not in st.session_state:
    st.session_state.events = []

if "traffic_history" not in st.session_state:
    st.session_state.traffic_history = defaultdict(deque)

if "port_history" not in st.session_state:
    st.session_state.port_history = defaultdict(set)

st.subheader("Live Network Monitoring")

refresh = st.button("🔄 Refresh Dashboard")

if refresh:
    records = consumer.poll(timeout_ms=1000)

    for messages in records.values():
        for message in messages:
            event = message.value
            source_ip = event.get("source_ip", "Unknown")
            packet_size = event.get("packet_size", 0)
            destination_port = event.get("destination_port", 0)
            current_time = time.time()

            st.session_state.events.append(event)

            history = st.session_state.traffic_history[source_ip]
            history.append(current_time)

            while history and current_time - history[0] > 10:
                history.popleft()

            st.session_state.port_history[source_ip].add(
                destination_port
            )

# Calculate alerts
events = st.session_state.events

large_packets = sum(
    1 for event in events
    if event.get("packet_size", 0) > 5000
)

ddos_alerts = sum(
    1 for history in st.session_state.traffic_history.values()
    if len(history) > 10
)

port_scan_alerts = sum(
    1 for ports in st.session_state.port_history.values()
    if len(ports) > 5
)

# Metrics
col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Traffic Events", len(events))
col2.metric("Large Packet Events", large_packets)
col3.metric("DDoS-like Sources", ddos_alerts)
col4.metric("Port Scanning Sources", port_scan_alerts)

st.divider()

# Traffic table
st.subheader("Network Traffic Events")

if events:
    df = pd.DataFrame(events)
    st.dataframe(df.tail(20), use_container_width=True)

    st.subheader("Traffic by Destination Port")
    if "destination_port" in df.columns:
        port_data = df["destination_port"].value_counts()
        st.bar_chart(port_data)

    st.subheader("Security Alerts")

    if large_packets:
        st.warning(f"Large packet events detected: {large_packets}")

    if ddos_alerts:
        st.error(f"Possible DDoS-like activity from {ddos_alerts} source(s)")

    if port_scan_alerts:
        st.error(f"Possible port scanning from {port_scan_alerts} source(s)")

else:
    st.info("Waiting for network traffic... Click Refresh Dashboard to fetch events.")

st.caption("Test environment: Simulated network traffic")


# Improved Alert History
st.divider()
st.subheader("🚨 Security Alert History")

alert_history = []

# 1. Large packet alerts - one entry per source IP
large_packet_sources = {
    event.get("source_ip", "Unknown")
    for event in events
    if event.get("packet_size", 0) > 5000
}

for source_ip in large_packet_sources:
    alert_history.append({
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Source IP": source_ip,
        "Alert Type": "Unusually Large Packet",
        "Severity": "HIGH"
    })

# 2. DDoS-like traffic alerts
for source_ip, history in st.session_state.traffic_history.items():
    if len(history) > 10:
        alert_history.append({
            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Source IP": source_ip,
            "Alert Type": "Possible DDoS-like Activity",
            "Severity": "CRITICAL"
        })

# 3. Port scanning alerts
for source_ip, ports in st.session_state.port_history.items():
    if len(ports) > 5:
        alert_history.append({
            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Source IP": source_ip,
            "Alert Type": "Possible Port Scanning",
            "Severity": "HIGH"
        })

if alert_history:
    alert_df = pd.DataFrame(alert_history)
    st.dataframe(alert_df, use_container_width=True)
else:
    st.success("No security alerts detected.")
