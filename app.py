import threading
from collections import defaultdict
from datetime import datetime

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit as sock_emit

app = Flask(__name__)
app.config["SECRET_KEY"] = "netwatch-traffic-analyzer"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ---------------------------------------------------------------------------
# Capture state
# ---------------------------------------------------------------------------
sniffer = None
sniffer_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------
stats_lock = threading.Lock()
total_packets = 0
protocol_counts = defaultdict(int)
anomaly_event_count = 0
ip_packet_counts = defaultdict(int)

# ---------------------------------------------------------------------------
# Anomaly detection state
# ---------------------------------------------------------------------------
anomaly_lock = threading.Lock()
ip_port_history = defaultdict(list)   # src_ip -> [(ts, dst_port)]
ip_packet_times = defaultdict(list)   # src_ip -> [ts]

PORT_SCAN_THRESHOLD = 15   # unique dst ports
PORT_SCAN_WINDOW    = 60   # seconds
HIGH_VOLUME_THRESHOLD = 100  # packets
HIGH_VOLUME_WINDOW    = 10   # seconds


def check_anomalies(src_ip: str, dst_port: int, now_ts: float) -> list[str]:
    found = []
    with anomaly_lock:
        # Port-scan detection
        hist = ip_port_history[src_ip]
        hist.append((now_ts, dst_port))
        ip_port_history[src_ip] = [
            (t, p) for t, p in hist if now_ts - t <= PORT_SCAN_WINDOW
        ]
        unique_ports = {p for _, p in ip_port_history[src_ip]}
        if len(unique_ports) >= PORT_SCAN_THRESHOLD:
            found.append(
                f"Port scan: {len(unique_ports)} unique ports in {PORT_SCAN_WINDOW}s"
            )

        # High-volume detection
        times = ip_packet_times[src_ip]
        times.append(now_ts)
        ip_packet_times[src_ip] = [t for t in times if now_ts - t <= HIGH_VOLUME_WINDOW]
        count = len(ip_packet_times[src_ip])
        if count >= HIGH_VOLUME_THRESHOLD:
            found.append(f"High volume: {count} packets in {HIGH_VOLUME_WINDOW}s")

    return found


def process_packet(pkt):
    global total_packets, anomaly_event_count
    try:
        from scapy.all import IP, TCP, UDP, ICMP

        if not pkt.haslayer(IP):
            return

        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        size = len(pkt)
        now = datetime.now()
        ts_str = now.strftime("%H:%M:%S.%f")[:-3]
        now_ts = now.timestamp()

        src_port = dst_port = None
        proto = "OTHER"

        if pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            proto = "TCP"
        elif pkt.haslayer(UDP):
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            proto = "UDP"
        elif pkt.haslayer(ICMP):
            proto = "ICMP"

        with stats_lock:
            total_packets += 1
            protocol_counts[proto] += 1
            ip_packet_counts[src_ip] += 1

        anomalies = (
            check_anomalies(src_ip, dst_port, now_ts) if dst_port is not None else []
        )

        if anomalies:
            with stats_lock:
                anomaly_event_count += 1
            socketio.emit(
                "anomaly",
                {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "timestamp": ts_str,
                    "reasons": anomalies,
                },
            )

        socketio.emit(
            "packet",
            {
                "timestamp": ts_str,
                "protocol": proto,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "size": size,
                "anomalies": anomalies,
            },
        )
    except Exception:
        pass  # skip malformed / unrecognized packets


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def get_stats():
    with stats_lock:
        top_ips = sorted(
            ip_packet_counts.items(), key=lambda x: x[1], reverse=True
        )[:10]
        return jsonify(
            {
                "total_packets": total_packets,
                "protocols": dict(protocol_counts),
                "anomaly_count": anomaly_event_count,
                "top_ips": [{"ip": ip, "count": c} for ip, c in top_ips],
            }
        )


# ---------------------------------------------------------------------------
# Socket events
# ---------------------------------------------------------------------------

@socketio.on("connect")
def on_connect():
    with sniffer_lock:
        running = sniffer is not None and sniffer.running
    sock_emit("status", {
        "capturing": running,
        "message": "Capture running" if running else "Ready — click Start",
    })


@socketio.on("start_capture")
def on_start(data=None):
    global sniffer
    err = None
    with sniffer_lock:
        if sniffer is not None and sniffer.running:
            return
        try:
            from scapy.all import AsyncSniffer, conf as scapy_conf
            scapy_conf.verb = 0
            kwargs = {"prn": process_packet, "store": False, "filter": "ip"}
            if data and data.get("iface"):
                kwargs["iface"] = data["iface"]
            sniffer = AsyncSniffer(**kwargs)
            sniffer.start()
        except Exception as e:
            err = str(e)

    if err:
        sock_emit("status", {"capturing": False, "message": f"Error: {err}"})
    else:
        sock_emit("status", {"capturing": True, "message": "Capture started"})


@socketio.on("stop_capture")
def on_stop():
    global sniffer
    with sniffer_lock:
        if sniffer and sniffer.running:
            sniffer.stop()
    sock_emit("status", {"capturing": False, "message": "Capture stopped"})


@socketio.on("reset_stats")
def on_reset():
    global total_packets, anomaly_event_count
    with stats_lock:
        total_packets = 0
        anomaly_event_count = 0
        protocol_counts.clear()
        ip_packet_counts.clear()
    with anomaly_lock:
        ip_port_history.clear()
        ip_packet_times.clear()
    sock_emit("stats_reset", {})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("\n  NetWatch — Network Traffic Analyzer")
    print("  =====================================")
    print("  IMPORTANT: Run this script as Administrator for packet capture.")
    print("  Windows users: Npcap must be installed (https://npcap.com).")
    print("\n  Dashboard -> http://127.0.0.1:5000\n")
    socketio.run(
        app,
        host="0.0.0.0",
        port=5000,
        debug=False,
        use_reloader=False,
        allow_unsafe_werkzeug=True,
    )
