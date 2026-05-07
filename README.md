# NetWatch — Network Traffic Analyzer

A live network traffic analyzer with a Python/Scapy backend and a real-time browser dashboard.

![Dashboard](https://img.shields.io/badge/dashboard-live-3fb950) ![Python](https://img.shields.io/badge/python-3.10%2B-58a6ff) ![License](https://img.shields.io/badge/license-proprietary-red)

## Features

- **Live packet capture** via Scapy — TCP, UDP, ICMP, and other IP traffic
- **Real-time dashboard** streamed over WebSockets (Flask-SocketIO)
- **Protocol distribution** pie chart, auto-updating as traffic arrives
- **Top source IPs and destination IPs** ranked by packet count with volume bars
- **Anomaly detection** with two built-in detectors:
  - **Port scan** — flags a source IP that contacts >= 15 unique destination ports within 60 seconds
  - **High volume** — flags a source IP that sends >= 100 packets within 10 seconds
- **DNS resolution** — hostnames resolved asynchronously and shown alongside IPs throughout the dashboard
- **Geographic IP mapping** — world map (Leaflet + CartoDB dark tiles) with a marker per unique public IP, geolocated via ip-api.com
- **Bandwidth graph** — stacked area chart showing per-protocol byte throughput updated every second, with up to 2 minutes of history
- **Connection tracking** — live flow table (src:port -> dst:port/proto) with packet/byte counts, sortable by any column
- **Custom alert rules** — build rules on any packet field (IP, port, protocol, size) with ==, !=, >, <, or contains operators; matching packets are flagged and logged in a rule alert history panel
- **CSV and PCAP export** — download the last 1000 captured packets as a CSV spreadsheet or a Wireshark-compatible PCAP file
- **Filterable packet table** — filter by protocol, IP address, anomalies-only, or rule-alerts-only
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

### Dashboard Tabs

| Tab | What it shows |
|-----|---------------|
| **Dashboard** | Stat cards, protocol pie chart, top IPs, anomaly alerts, packet table |
| **Bandwidth** | Stacked area chart of per-protocol throughput (bytes/sec), updated every second |
| **Connections** | Live flow table sortable by any column; filter by IP, protocol, or active-only |
| **Geo Map** | World map with a dot per unique public IP, coloured by traffic volume |
| **Alert Rules** | Rule builder form, active rule list, and rule alert history |
| **Export** | Download session data as CSV or PCAP |

### Controls

| Button | Action |
|--------|--------|
| Start | Begin live packet capture |
| Stop | Pause capture |
| Reset | Clear all stats, anomaly state, connection tracking, and packet history |
| Clear table | Remove rows from the packet table (keeps stats) |
| Clear alerts | Dismiss anomaly alerts |

### Filters

- **Protocol** — show only TCP / UDP / ICMP / OTHER
- **IP** — filter rows where source or destination IP contains the typed string
- **Anomalies only** — hide non-flagged packets
- **Rules only** — show only packets that matched a custom alert rule

## Anomaly Detection

Thresholds are defined at the top of `app.py` and can be adjusted:

```python
PORT_SCAN_THRESHOLD   = 15   # unique dst ports
PORT_SCAN_WINDOW      = 60   # seconds
HIGH_VOLUME_THRESHOLD = 100  # packets
HIGH_VOLUME_WINDOW    = 10   # seconds
```

Flagged packets are highlighted in red in the table. Hover the flag icon to see the reason.

## Custom Alert Rules

Rules are created in the **Alert Rules** tab. Each rule specifies:

- **Name** — a label shown in the alert log
- **Field** — `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, or `size`
- **Operator** — `==`, `!=`, `>`, `<`, or `contains`
- **Value** — the value to compare against

Example: flag every packet larger than 1500 bytes by setting field=`size`, operator=`>`, value=`1500`.

## Export

From the **Export** tab:

- **CSV** — downloads `capture_<timestamp>.csv` with one row per packet (last 1000)
- **PCAP** — downloads `capture_<timestamp>.pcap` compatible with Wireshark and tcpdump (last 1000)

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
| `GET /api/bandwidth` | Array of per-second bandwidth snapshots (up to 120 entries) |
| `GET /api/connections` | Active and recent flows sorted by byte volume |
| `GET /api/geo` | Cached geolocation data keyed by IP address |
| `GET /api/export/csv` | Download packet history as CSV |
| `GET /api/export/pcap` | Download packet history as PCAP |

## Project Structure

```
traffic-analyzer/
├── app.py              # Flask + Flask-SocketIO backend, Scapy capture, anomaly detection, all new features
├── gen_traffic.py      # Anomaly traffic simulator
├── requirements.txt
└── templates/
    └── index.html      # 6-tab dashboard (Chart.js + Leaflet + Socket.IO, no build step)
```

## License

Copyright (c) 2026 samueldgs1. All rights reserved.
