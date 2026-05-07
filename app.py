import io
import csv
import ipaddress
import socket as _socket
import threading
import time
import uuid
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    import requests as _requests
    _GEO_ENABLED = True
except ImportError:
    _GEO_ENABLED = False

from flask import Flask, render_template, jsonify, send_file
from flask_socketio import SocketIO, emit as sock_emit

app = Flask(__name__)
app.config["SECRET_KEY"] = "netwatch-traffic-analyzer"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ---------------------------------------------------------------------------
# Capture
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
bw_current = defaultdict(int)   # proto -> bytes in current second

# ---------------------------------------------------------------------------
# Anomaly detection
# ---------------------------------------------------------------------------
anomaly_lock = threading.Lock()
ip_port_history = defaultdict(list)
ip_packet_times = defaultdict(list)

PORT_SCAN_THRESHOLD   = 15
PORT_SCAN_WINDOW      = 60
HIGH_VOLUME_THRESHOLD = 100
HIGH_VOLUME_WINDOW    = 10

# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------
dns_cache   = {}
dns_pending = set()
dns_lock    = threading.Lock()
dns_exec    = ThreadPoolExecutor(max_workers=4, thread_name_prefix="dns")

# ---------------------------------------------------------------------------
# GeoIP  (ip-api.com, free, 45 req/min)
# ---------------------------------------------------------------------------
geo_cache = {}
geo_lock  = threading.Lock()
geo_queue = None   # initialized after app starts (needs socketio)

# ---------------------------------------------------------------------------
# Bandwidth history
# ---------------------------------------------------------------------------
bw_history = deque(maxlen=120)

# ---------------------------------------------------------------------------
# Connection tracking
# ---------------------------------------------------------------------------
conn_lock   = threading.Lock()
connections = {}
CONN_TIMEOUT = 300   # prune flows silent for 5 min

# ---------------------------------------------------------------------------
# Packet buffer for export
# ---------------------------------------------------------------------------
pkt_buf_lock = threading.Lock()
pkt_buffer   = deque(maxlen=1000)   # {data: dict, raw: bytes}

# ---------------------------------------------------------------------------
# Custom alert rules
# ---------------------------------------------------------------------------
rules_lock   = threading.Lock()
alert_rules  = []
rule_alerts  = deque(maxlen=500)


# ─── helpers ────────────────────────────────────────────────────────────────

def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


# ─── DNS ────────────────────────────────────────────────────────────────────

def schedule_dns(ip: str):
    with dns_lock:
        if ip in dns_cache or ip in dns_pending:
            return
        dns_pending.add(ip)

    def _resolve():
        try:
            host = _socket.gethostbyaddr(ip)[0]
        except Exception:
            host = ip
        with dns_lock:
            dns_pending.discard(ip)
            dns_cache[ip] = host
        if host != ip:
            socketio.emit('dns', {'ip': ip, 'hostname': host})

    dns_exec.submit(_resolve)


# ─── GeoIP worker ────────────────────────────────────────────────────────────

def geo_worker(q):
    while True:
        ip = q.get()
        if ip is None:
            break
        with geo_lock:
            already = ip in geo_cache
        if not already and _GEO_ENABLED:
            try:
                r = _requests.get(
                    f'http://ip-api.com/json/{ip}',
                    params={'fields': 'status,country,countryCode,lat,lon,isp'},
                    timeout=4,
                )
                d = r.json()
                if d.get('status') == 'success':
                    result = {k: d[k] for k in ('country', 'countryCode', 'lat', 'lon', 'isp')}
                    with geo_lock:
                        geo_cache[ip] = result
                    socketio.emit('geo', {'ip': ip, **result})
                else:
                    with geo_lock:
                        geo_cache[ip] = None
            except Exception:
                with geo_lock:
                    geo_cache[ip] = None
            time.sleep(1.4)   # ≈ 43 req/min, safely under the 45 limit
        q.task_done()


def request_geo(ip: str):
    if is_private(ip):
        return
    with geo_lock:
        if ip in geo_cache:
            return
        geo_cache[ip] = None   # mark pending
    if geo_queue is not None:
        geo_queue.put(ip)


# ─── Bandwidth ticker ─────────────────────────────────────────────────────────

def bandwidth_ticker():
    while True:
        time.sleep(1)
        with stats_lock:
            snap = {
                'TCP':   bw_current.pop('TCP',   0),
                'UDP':   bw_current.pop('UDP',   0),
                'ICMP':  bw_current.pop('ICMP',  0),
                'OTHER': bw_current.pop('OTHER', 0),
            }
        snap['total'] = sum(snap.values())
        snap['ts']    = datetime.now().strftime('%H:%M:%S')
        bw_history.append(snap)
        socketio.emit('bandwidth', snap)

        # Prune stale connections
        cutoff = time.time() - CONN_TIMEOUT
        with conn_lock:
            stale = [k for k, v in connections.items() if v['last'] < cutoff]
            for k in stale:
                del connections[k]


# ─── Connection tracker ───────────────────────────────────────────────────────

def track_connection(src_ip, src_port, dst_ip, dst_port, proto, size, now_ts):
    sp = src_port or 0
    dp = dst_port or 0
    key = f"{src_ip}:{sp}-{dst_ip}:{dp}/{proto}"
    with conn_lock:
        if key not in connections:
            connections[key] = {
                'key': key, 'src_ip': src_ip, 'src_port': sp,
                'dst_ip': dst_ip, 'dst_port': dp, 'proto': proto,
                'start': now_ts, 'last': now_ts, 'bytes': size, 'packets': 1,
            }
        else:
            c = connections[key]
            c['last']    = now_ts
            c['bytes']  += size
            c['packets'] += 1
        conn = dict(connections[key])
    socketio.emit('conn_update', conn)


# ─── Alert rules ─────────────────────────────────────────────────────────────

def eval_rules(pkt_data: dict) -> list[str]:
    hits = []
    with rules_lock:
        rules = list(alert_rules)
    for rule in rules:
        fv = pkt_data.get(rule['field'])
        if fv is None:
            continue
        op, rv = rule['operator'], rule['value']
        try:
            if   op == '=='       and str(fv) == str(rv):              hits.append(rule['name'])
            elif op == '!='       and str(fv) != str(rv):              hits.append(rule['name'])
            elif op == '>'        and float(fv) > float(rv):           hits.append(rule['name'])
            elif op == '<'        and float(fv) < float(rv):           hits.append(rule['name'])
            elif op == 'contains' and str(rv).lower() in str(fv).lower(): hits.append(rule['name'])
        except Exception:
            pass
    return hits


# ─── Anomaly detection ────────────────────────────────────────────────────────

def check_anomalies(src_ip: str, dst_port: int, now_ts: float) -> list[str]:
    found = []
    with anomaly_lock:
        hist = ip_port_history[src_ip]
        hist.append((now_ts, dst_port))
        ip_port_history[src_ip] = [(t, p) for t, p in hist if now_ts - t <= PORT_SCAN_WINDOW]
        if len({p for _, p in ip_port_history[src_ip]}) >= PORT_SCAN_THRESHOLD:
            found.append(f"Port scan: {len({p for _, p in ip_port_history[src_ip]})} ports/{PORT_SCAN_WINDOW}s")
        times = ip_packet_times[src_ip]
        times.append(now_ts)
        ip_packet_times[src_ip] = [t for t in times if now_ts - t <= HIGH_VOLUME_WINDOW]
        if len(ip_packet_times[src_ip]) >= HIGH_VOLUME_THRESHOLD:
            found.append(f"High volume: {len(ip_packet_times[src_ip])} pkts/{HIGH_VOLUME_WINDOW}s")
    return found


# ─── Packet processor ─────────────────────────────────────────────────────────

def process_packet(pkt):
    global total_packets, anomaly_event_count
    try:
        from scapy.all import IP, TCP, UDP, ICMP
        if not pkt.haslayer(IP):
            return
        ip_layer = pkt[IP]
        src_ip, dst_ip = ip_layer.src, ip_layer.dst
        size = len(pkt)
        now    = datetime.now()
        ts_str = now.strftime('%H:%M:%S.%f')[:-3]
        now_ts = now.timestamp()

        src_port = dst_port = None
        proto = 'OTHER'
        if pkt.haslayer(TCP):
            src_port, dst_port, proto = pkt[TCP].sport, pkt[TCP].dport, 'TCP'
        elif pkt.haslayer(UDP):
            src_port, dst_port, proto = pkt[UDP].sport, pkt[UDP].dport, 'UDP'
        elif pkt.haslayer(ICMP):
            proto = 'ICMP'

        with stats_lock:
            total_packets += 1
            protocol_counts[proto] += 1
            ip_packet_counts[src_ip] += 1
            bw_current[proto] += size

        anomalies  = check_anomalies(src_ip, dst_port, now_ts) if dst_port is not None else []
        if anomalies:
            with stats_lock:
                anomaly_event_count += 1

        pkt_data = {
            'timestamp': ts_str, 'protocol': proto,
            'src_ip': src_ip, 'src_port': src_port,
            'dst_ip': dst_ip, 'dst_port': dst_port,
            'size': size, 'anomalies': anomalies,
        }

        rule_hits = eval_rules(pkt_data)
        pkt_data['rule_alerts'] = rule_hits
        if rule_hits:
            alert = {'ts': ts_str, 'rules': rule_hits, 'src_ip': src_ip,
                     'dst_ip': dst_ip, 'proto': proto, 'size': size}
            rule_alerts.appendleft(alert)
            socketio.emit('rule_alert', alert)

        with pkt_buf_lock:
            try:
                pkt_buffer.append({'data': pkt_data, 'raw': bytes(pkt)})
            except Exception:
                pkt_buffer.append({'data': pkt_data, 'raw': None})

        socketio.emit('packet', pkt_data)
        if anomalies:
            socketio.emit('anomaly', {'src_ip': src_ip, 'dst_ip': dst_ip,
                                      'timestamp': ts_str, 'reasons': anomalies})

        track_connection(src_ip, src_port, dst_ip, dst_port, proto, size, now_ts)
        schedule_dns(src_ip);  schedule_dns(dst_ip)
        request_geo(src_ip);   request_geo(dst_ip)

    except Exception:
        pass


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/stats')
def get_stats():
    with stats_lock:
        top = sorted(ip_packet_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        return jsonify({
            'total_packets': total_packets,
            'protocols':     dict(protocol_counts),
            'anomaly_count': anomaly_event_count,
            'top_ips':       [{'ip': ip, 'count': c} for ip, c in top],
        })


@app.route('/api/bandwidth')
def get_bandwidth():
    return jsonify(list(bw_history))


@app.route('/api/connections')
def get_connections():
    now = time.time()
    with conn_lock:
        rows = sorted(
            [c for c in connections.values() if now - c['last'] < CONN_TIMEOUT],
            key=lambda c: c['bytes'], reverse=True
        )[:200]
    return jsonify(rows)


@app.route('/api/geo')
def get_geo():
    with geo_lock:
        return jsonify({ip: g for ip, g in geo_cache.items() if g})


@app.route('/api/export/csv')
def export_csv():
    with pkt_buf_lock:
        rows = [e['data'] for e in pkt_buffer]
    buf = io.StringIO()
    fields = ['timestamp', 'protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'size', 'anomalies', 'rule_alerts']
    w = csv.DictWriter(buf, fieldnames=fields, extrasaction='ignore')
    w.writeheader()
    for row in rows:
        r = dict(row)
        r['anomalies']   = ' | '.join(r.get('anomalies', []))
        r['rule_alerts'] = ' | '.join(r.get('rule_alerts', []))
        w.writerow(r)
    buf.seek(0)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    return send_file(io.BytesIO(buf.getvalue().encode()), as_attachment=True,
                     download_name=f'capture_{ts}.csv', mimetype='text/csv')


@app.route('/api/export/pcap')
def export_pcap():
    from scapy.all import wrpcap, IP as SIP
    with pkt_buf_lock:
        snapshot = list(pkt_buffer)
    pkts = []
    for e in snapshot:
        raw = e.get('raw')
        if raw:
            try:   pkts.append(SIP(raw))
            except Exception: pass
    buf = io.BytesIO()
    wrpcap(buf, pkts)
    buf.seek(0)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    return send_file(buf, as_attachment=True, download_name=f'capture_{ts}.pcap',
                     mimetype='application/vnd.tcpdump.pcap')


# ─── Socket events ────────────────────────────────────────────────────────────

@socketio.on('connect')
def on_connect():
    with sniffer_lock:
        running = sniffer is not None and sniffer.running
    sock_emit('status', {'capturing': running,
                         'message': 'Capture running' if running else 'Ready — click Start'})
    with geo_lock:
        geo_snap = {ip: g for ip, g in geo_cache.items() if g}
    if geo_snap:
        sock_emit('geo_bulk', geo_snap)
    with dns_lock:
        dns_snap = {ip: h for ip, h in dns_cache.items() if h and h != ip}
    if dns_snap:
        sock_emit('dns_bulk', dns_snap)
    sock_emit('bandwidth_history', list(bw_history))
    with conn_lock:
        conn_snap = list(connections.values())
    sock_emit('conn_bulk', conn_snap)
    with rules_lock:
        sock_emit('rules_state', list(alert_rules))
    sock_emit('rule_history', list(rule_alerts))


@socketio.on('start_capture')
def on_start(data=None):
    global sniffer
    err = None
    with sniffer_lock:
        if sniffer is not None and sniffer.running:
            return
        try:
            from scapy.all import AsyncSniffer, conf as sc
            sc.verb = 0
            kwargs = {'prn': process_packet, 'store': False, 'filter': 'ip'}
            if data and data.get('iface'):
                kwargs['iface'] = data['iface']
            sniffer = AsyncSniffer(**kwargs)
            sniffer.start()
        except Exception as e:
            err = str(e)
    sock_emit('status', {'capturing': err is None,
                         'message': 'Capture started' if err is None else f'Error: {err}'})


@socketio.on('stop_capture')
def on_stop():
    global sniffer
    with sniffer_lock:
        if sniffer and sniffer.running:
            sniffer.stop()
    sock_emit('status', {'capturing': False, 'message': 'Capture stopped'})


@socketio.on('reset_stats')
def on_reset():
    global total_packets, anomaly_event_count
    with stats_lock:
        total_packets = anomaly_event_count = 0
        protocol_counts.clear(); ip_packet_counts.clear(); bw_current.clear()
    with anomaly_lock:
        ip_port_history.clear(); ip_packet_times.clear()
    with conn_lock:
        connections.clear()
    with geo_lock:
        geo_cache.clear()
    with dns_lock:
        dns_cache.clear(); dns_pending.clear()
    with pkt_buf_lock:
        pkt_buffer.clear()
    bw_history.clear()
    rule_alerts.clear()
    sock_emit('stats_reset', {})


@socketio.on('add_rule')
def on_add_rule(data):
    rule = {'id': str(uuid.uuid4())[:8], 'name': data.get('name', 'Rule'),
            'field': data.get('field', 'src_ip'), 'operator': data.get('operator', '=='),
            'value': data.get('value', '')}
    with rules_lock:
        alert_rules.append(rule)
        rules = list(alert_rules)
    sock_emit('rules_state', rules)


@socketio.on('remove_rule')
def on_remove_rule(data):
    with rules_lock:
        alert_rules[:] = [r for r in alert_rules if r['id'] != data.get('id')]
        rules = list(alert_rules)
    sock_emit('rules_state', rules)


# ─── Startup ──────────────────────────────────────────────────────────────────

def _start_background_threads():
    global geo_queue
    import queue
    geo_queue = queue.Queue()
    t_geo = threading.Thread(target=geo_worker, args=(geo_queue,), daemon=True, name="geo")
    t_bw  = threading.Thread(target=bandwidth_ticker, daemon=True, name="bw")
    t_geo.start()
    t_bw.start()


if __name__ == '__main__':
    _start_background_threads()
    print("\n  NetWatch — Network Traffic Analyzer")
    print("  =====================================")
    print("  IMPORTANT: Run this script as Administrator for packet capture.")
    print("  Windows users: Npcap must be installed (https://npcap.com).")
    print("\n  Dashboard -> http://127.0.0.1:5000\n")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False,
                 use_reloader=False, allow_unsafe_werkzeug=True)
