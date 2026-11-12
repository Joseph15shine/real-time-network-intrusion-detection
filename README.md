# Real-Time Network Intrusion Detection System

A real-time network monitoring and intrusion detection prototype using Apache Kafka, Python, Scapy, and Streamlit.

## Project Overview

This project captures network traffic using Scapy and streams network events through Apache Kafka. Python-based detection logic monitors traffic patterns and identifies suspicious activities. A Streamlit dashboard displays network events and security alerts.

## Features

- Real-time network traffic capture using Scapy
- Event streaming using Apache Kafka
- Large packet detection
- DDoS-like high traffic detection
- Port scanning detection
- Interactive Streamlit monitoring dashboard
- Traffic visualization and security alert history

## Technologies Used

- Python
- Apache Kafka
- Scapy
- Streamlit
- Pandas
- VS Code

## Project Structure

- `producer.py` – Captures and sends network traffic events to Kafka.
- `consumer.py` – Receives network events from Kafka.
- `intrusion_detector.py` – Detects suspicious traffic patterns.
- `dashboard.py` – Displays network events and security alerts.
- `.gitignore` – Excludes unnecessary files.

## How to Run

1. Install Python and Apache Kafka.
2. Install the required Python packages:

   `pip install kafka-python scapy streamlit pandas`

3. Start the Kafka broker and create the `network-traffic` topic.
4. Run the traffic producer:

   `python producer.py`

5. Run the intrusion detection system:

   `python intrusion_detector.py`

6. Start the dashboard:

   `python -m streamlit run dashboard.py`

## Note

This project is a prototype tested with captured network traffic and simulated traffic events. Detection rules are heuristic-based and intended for educational demonstration, not production-grade security.

## Author

Joseph Shine
