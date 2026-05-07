# NetWatch — Network Traffic Analyzer

A live network traffic analyzer with a Python/Scapy backend and a real-time browser dashboard.

![Dashboard](https://img.shields.io/badge/dashboard-live-3fb950) ![Python](https://img.shields.io/badge/python-3.10%2B-58a6ff) ![License](https://img.shields.io/badge/license-proprietary-red)

## Features

- **Live packet capture** via Scapy — TCP, UDP, ICMP, and other IP traffic
- **Real-time dashboard** streamed over WebSockets (Flask-SocketIO)
- **Protocol distribution** pie chart, auto-updating as traffic arrives
- **Top source IPs** ranked by packet count with volume bars
- **Anomaly detection** with two built-in detectors:
  - **Port scan** — flags a source IP that contacts ≥ 15 unique destination ports within 60 seconds
  - **High volume** — flags a source IP that sends ≥ 100 packets within 10 seconds
- **Filterable packet table** — filter by protocol, IP address, or anomalies-only
- **Traffic simulator** (`gen_traffic.py`) to exercise both anomaly detectors without real attack traffic

## Requirements

- Python 3.10+
- **Windows:** [Npcap](https://npcap.com) must be installed for raw packet capture
- **Linux/macOS:** `libpcap` (usually pre-installed)
- Administrator / root privileges to capture packets

## Installation

```bash
git clone https://github.com/samueldgs1/traffic-analyzer.git
cd traffic-analyzer
pip install -r requirements.txt
```

## Usage

Run as Administrator (required for raw packet capture):

```bash
python app.py
```

Then open **http://127.0.0.1:5000** in your browser and click **Start**.

### Controls

| Button | Action |
|--------|--------|
| Start | Begin live packet capture |
| Stop | Pause capture |
| Reset | Clear all stats, anomaly state, and packet history |
| Clear table | Remove rows from the packet table (keeps stats) |
| Clear alerts | Dismiss anomaly alerts |

### Filters

- **Protocol** — show only TCP / UDP / ICMP / OTHER
- **IP** — filter rows where source or destination IP contains the typed string
- **Anomalies only** — hide non-flagged packets

## Anomaly Detection

Thresholds are defined at the top of `app.py` and can be adjusted:

```python
PORT_SCAN_THRESHOLD = 15   # unique dst ports
PORT_SCAN_WINDOW    = 60   # seconds
HIGH_VOLUME_THRESHOLD = 100  # packets
HIGH_VOLUME_WINDOW    = 10   # seconds
```

Flagged packets are highlighted in red in the table. Hover the flag icon to see the reason.

## Traffic Simulator

`gen_traffic.py` injects crafted packets to trigger both anomaly detectors without real attack traffic. Run it while the dashboard is capturing:

```bash
python gen_traffic.py
```

It uses two distinct fake source IPs (`10.99.1.1` for the port scanner, `10.99.2.1` for the flooder) and sends to `192.0.2.1` (RFC 5737 documentation range — goes nowhere).

## REST API

| Endpoint | Description |
|----------|-------------|
| `GET /` | Dashboard HTML |
| `GET /api/stats` | JSON snapshot of total packets, protocol counts, anomaly count, and top 10 source IPs |

## Project Structure

```
traffic-analyzer/
├── app.py              # Flask + Flask-SocketIO backend, Scapy capture, anomaly detection
├── gen_traffic.py      # Anomaly traffic simulator
├── requirements.txt
└── templates/
    └── index.html      # Dashboard (Chart.js + Socket.IO, no build step)
```

## License

MIT
