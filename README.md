# 🌐 Network Traffic Analyzer & Intrusion Detection System (IDS)

A Python-based networking and cybersecurity project that captures and analyzes network traffic to identify potentially suspicious activity using **Scapy**.

## 📌 Overview

This project explores network packet analysis and basic intrusion detection. It includes detection logic for selected traffic patterns and records traffic data and security alerts in CSV files for further analysis.

## ✨ Features

- 📡 Network packet capture and analysis
- 🚨 Port scan pattern detection
- 📈 Traffic spike detection
- 🔁 Repeated connection detection
- 🔐 Monitoring of selected suspicious ports
- 📝 IDS alert logging
- 📊 CSV-based traffic analysis and reporting
- 🧪 Test scripts for checking detection logic

## 🛠️ Technologies Used

- **Python**
- **Scapy** — packet capture and inspection
- **Pandas** — data analysis
- **Matplotlib** — data visualization

## 📂 Project Structure

```text
network-traffic-analyzer-ids/
├── packet_capture.py
├── traffic_analysis.py
├── requirements.txt
├── test_ids_alert_logging.py
├── test_port_scan.py
├── test_port_scan_updated.py
├── test_repeated_connections.py
├── test_suspicious_ports.py
├── test_traffic_spike.py
├── README.md
├── LICENSE
└── .gitignore
```

## ⚙️ Installation

**1. Clone the repository**

```bash
git clone https://github.com/shriya-khanai/network-traffic-analyzer-ids.git
cd network-traffic-analyzer-ids
```

**2. Install the dependencies**

```bash
python -m pip install -r requirements.txt
```

**3. Run the analyzer**

```bash
python packet_capture.py
```

Depending on your Windows configuration and capture interface, packet capture may require administrator privileges and a compatible Npcap installation.

## 🧪 Testing

The repository includes separate test scripts for the detection features.

Run an individual test with:

```bash
python test_port_scan_updated.py
```

Other test scripts cover traffic spikes, repeated connections, suspicious ports, and IDS alert logging.

Use simulated test traffic to test detection logic safely. A passing simulated test does not by itself prove detection accuracy on real network traffic.

## 🔒 Responsible Use

Use packet capture only on networks and devices you own or have explicit permission to monitor. Detection alerts indicate potentially suspicious patterns; they do not automatically confirm malicious activity.

## 🎯 Learning Goals

- Understand network packet structure and traffic flows
- Practise Python-based network analysis
- Explore basic intrusion detection techniques
- Learn CSV logging and automated testing
- Build practical foundations in networking and cybersecurity

## 👩‍💻 Author

**Shriya Khanai**

Electronics & Communication Engineering student interested in computer networking, network security, and network engineering.

---

⭐ *This project is part of my hands-on learning journey in computer networking and cybersecurity.*

