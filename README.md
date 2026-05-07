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
- **IP Labels** — assign a custom name to any IP address; the label appears as a purple tag next to that IP everywhere in the dashboard (packet table, top IPs, geo map popups)
- **CSV and PCAP export** — download the last 1,000 captured packets as a CSV spreadsheet or a Wireshark-compatible PCAP file
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
| **Dashboard** | Stat cards, protocol pie chart, top IPs, anomaly alerts, IP labels, packet table |
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
- **IP / Host** — filter rows where source or destination IP or hostname contains the typed string
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

## IP Labels

In the **Dashboard** tab, the IP Labels panel sits between the anomaly alerts and the packet table. Enter any IP address and a friendly name, then press Enter or click **+ Set Label**.

Examples:
- `192.168.1.1` → `Router`
- `192.168.1.217` → `My MacBook`
- `162.159.135.234` → `Cloudflare`

Labels are stored server-side and broadcast to all connected browser tabs. They appear as purple tags next to the IP everywhere: the packet table, top source/destination IP lists, and geo map popups.

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

## How I Built This

I built NetWatch from scratch as a personal project to learn network programming and real-time web dashboards. Here's how it came together:

**Starting with packet capture**
I started by getting raw packet capture working with Scapy's `AsyncSniffer`, which lets me start and stop capture on demand without blocking the server. I wrapped it in Flask with Flask-SocketIO so captured packets stream directly to the browser over WebSockets in real time. The first version just showed a table of packets — timestamp, protocol, source/destination IP and port, and size.

**Adding anomaly detection**
Once the basic capture was working I added two anomaly detectors: a port scanner detector that flags any source IP hitting 15 or more unique destination ports within 60 seconds, and a high-volume detector that flags any IP sending 100+ packets in 10 seconds. I built a traffic simulator (`gen_traffic.py`) using Scapy to inject crafted packets with fake source IPs so I could test both detectors without needing real attack traffic.

**Building the dashboard**
I chose a dark GitHub-style theme using pure CSS variables. The frontend uses Chart.js for the protocol distribution doughnut chart and no other framework — just vanilla JS with a dirty-flag render loop running at 15fps so the page stays smooth even under heavy traffic without thrashing the DOM on every packet.

**Expanding with six new features**
After the core was solid I added six features in one go:
- **DNS resolution** using Python's `socket.gethostbyaddr()` in a `ThreadPoolExecutor` so lookups don't block the capture thread
- **Geographic IP mapping** using ip-api.com's free API (rate-limited to 45 req/min) rendered on a Leaflet world map with CartoDB dark tiles — no API key needed
- **Bandwidth graph** with a background thread that samples per-protocol byte counts every second and emits them via SocketIO, displayed as a stacked area chart
- **Connection tracking** that builds a flow table keyed by `src:port-dst:port/proto` and tracks packet counts, byte totals, and last-seen timestamps
- **Custom alert rules** evaluated against every packet using a simple field/operator/value engine
- **CSV and PCAP export** via two REST endpoints using Python's `csv` module and Scapy's `wrpcap`

**Fixing the geo map bug**
After shipping the geo feature I noticed the map was always blank. The bug was subtle: `request_geo()` was pre-setting `geo_cache[ip] = None` to mark an IP as pending, but then `geo_worker` was checking `if ip in geo_cache` which returned `True` for the pending marker, so it skipped the actual API call entirely. Fixed it by changing the check to `bool(geo_cache.get(ip))` — only `True` when real geo data exists, not when the value is `None`.

**Adding IP Labels**
The last feature I added was the ability to name any IP address. Labels are stored server-side in a dict, broadcast to all connected clients via SocketIO, and rendered as purple tags next to the IP in the packet table, top IPs list, and geo map popups.

## Project Structure

```
traffic-analyzer/
├── app.py              # Flask + Flask-SocketIO backend, Scapy capture, anomaly detection, all features
├── gen_traffic.py      # Anomaly traffic simulator
├── requirements.txt
└── templates/
    └── index.html      # 6-tab dashboard (Chart.js + Leaflet + Socket.IO, no build step)
```

## License

Copyright (c) 2026 samueldgs1. All rights reserved.
