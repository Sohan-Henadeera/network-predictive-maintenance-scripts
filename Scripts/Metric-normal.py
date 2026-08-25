import subprocess
import re
import csv
import time
import os
from datetime import datetime, timezone

DEVICE_NAME = "Pi_1"               # change per device: Pi_1, Pi_2, Pi_3, etc.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_FILE = os.path.join(SCRIPT_DIR, "..", "Data", "normal.csv")
INTERVAL_SECONDS = 10
INTERFACE = "eth0"                  # change to wlan0 if this Pi is on WiFi

PING_TARGETS = {
    "Router": "192.168.1.1",
    "Pi_2": "192.168.1.102",
    "Pi_3": "192.168.1.103",
}

_prev_net = None
_prev_net_time = None

def init_csv():
    try:
        with open(CSV_FILE, "x", newline="") as f:
            csv.writer(f).writerow(["scan_id","timestamp","device_id","device_type","metric_name","metric_value","unit","collection_method","collector_id","is_injected_anomaly","notes"])
    except FileExistsError:
        pass

def add_row(rows, scan_id, ts, device_id, device_type, metric_name, value, unit, method, notes=""):
    rows.append([scan_id, ts, device_id, device_type, metric_name, value, unit, method, DEVICE_NAME, 0, notes])
    print(f"  [{scan_id}] {device_id:12s} | {metric_name:24s} = {value} {unit}")

def collect_ping(rows, scan_id, ts, device_id, ip):
    try:
        result = subprocess.run(["ping", "-c", "4", "-W", "2", ip], capture_output=True, text=True)
        output = result.stdout
        loss_match = re.search(r"(\d+)% packet loss", output)
        packet_loss = float(loss_match.group(1)) if loss_match else 100.0
        rtt_match = re.search(r"= [\d.]+/([\d.]+)/", output)
        avg_latency = float(rtt_match.group(1)) if rtt_match else None
        reachable = 0 if packet_loss == 100.0 else 1
        add_row(rows, scan_id, ts, device_id, "peer_device", "latency_ms", avg_latency if avg_latency is not None else "", "ms", "ping")
        add_row(rows, scan_id, ts, device_id, "peer_device", "packet_loss_pct", packet_loss, "%", "ping")
        add_row(rows, scan_id, ts, device_id, "peer_device", "reachability", reachable, "bool", "ping")
    except Exception as e:
        print(f"  ping failed for {device_id}: {e}")

def collect_self_metrics(rows, scan_id, ts):
    try:
        import psutil
        add_row(rows, scan_id, ts, DEVICE_NAME, "self", "cpu_pct", psutil.cpu_percent(interval=1), "%", "psutil")
        add_row(rows, scan_id, ts, DEVICE_NAME, "self", "disk_usage_pct", psutil.disk_usage("/").percent, "%", "psutil")
    except Exception as e:
        print(f"  psutil failed: {e}")
    try:
        with open("/proc/uptime") as f:
            uptime_seconds = float(f.readline().split()[0])
        add_row(rows, scan_id, ts, DEVICE_NAME, "self", "uptime_seconds", round(uptime_seconds, 1), "s", "/proc/uptime")
    except Exception as e:
        print(f"  uptime failed: {e}")
    try:
        result = subprocess.run(["vcgencmd", "measure_temp"], capture_output=True, text=True)
        temp_match = re.search(r"temp=([\d.]+)", result.stdout)
        if temp_match:
            add_row(rows, scan_id, ts, DEVICE_NAME, "self", "temperature_c", float(temp_match.group(1)), "C", "vcgencmd")
    except Exception as e:
        print(f"  vcgencmd failed: {e}")

def collect_throughput_and_errors(rows, scan_id, ts):
    global _prev_net, _prev_net_time
    try:
        with open("/proc/net/dev") as f:
            lines = f.readlines()
        stats = None
        for line in lines:
            if line.strip().startswith(INTERFACE + ":"):
                parts = line.split(":")[1].split()
                stats = {
                    "rx_bytes": int(parts[0]), "rx_packets": int(parts[1]), "rx_errs": int(parts[2]), "rx_drop": int(parts[3]),
                    "tx_bytes": int(parts[8]), "tx_packets": int(parts[9]), "tx_errs": int(parts[10]), "tx_drop": int(parts[11]),
                }
                break
        if stats is None:
            print(f"  interface {INTERFACE} not found in /proc/net/dev")
            return
        now = time.time()
        if _prev_net is not None:
            elapsed = max(now - _prev_net_time, 1e-6)
            byte_delta = (stats["rx_bytes"] + stats["tx_bytes"]) - (_prev_net["rx_bytes"] + _prev_net["tx_bytes"])
            throughput_bps = round(byte_delta / elapsed, 1)
            packet_delta = (stats["rx_packets"] + stats["tx_packets"]) - (_prev_net["rx_packets"] + _prev_net["tx_packets"])
            error_delta = (stats["rx_errs"] + stats["tx_errs"] + stats["rx_drop"] + stats["tx_drop"]) - \
                          (_prev_net["rx_errs"] + _prev_net["tx_errs"] + _prev_net["rx_drop"] + _prev_net["tx_drop"])
            error_rate_pct = round((error_delta / packet_delta) * 100, 3) if packet_delta > 0 else 0.0
            add_row(rows, scan_id, ts, DEVICE_NAME, "self", "throughput_bytes_per_sec", throughput_bps, "B/s", "/proc/net/dev")
            add_row(rows, scan_id, ts, DEVICE_NAME, "self", "packet_error_rate_pct", error_rate_pct, "%", "/proc/net/dev")
        else:
            print("  first cycle - establishing baseline for throughput/error rate")
        _prev_net = stats
        _prev_net_time = now
    except Exception as e:
        print(f"  throughput/error read failed: {e}")

def collect_device_count(rows, scan_id, ts):
    try:
        result = subprocess.run(["arp-scan", "--localnet"], capture_output=True, text=True, timeout=30)
        macs_seen = set(re.findall(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", result.stdout))
        add_row(rows, scan_id, ts, "LAN", "network", "connected_device_count", len(macs_seen), "count", "arp-scan")
    except Exception as e:
        print(f"  arp-scan failed (needs install + sudo): {e}")

def flush(rows):
    with open(CSV_FILE, "a", newline="") as f:
        csv.writer(f).writerows(rows)

if __name__ == "__main__":
    init_csv()
    scan_id = 0
    print(f"[{DEVICE_NAME}] NORMAL collection every {INTERVAL_SECONDS}s. Ctrl+C to stop.")
    while True:
        scan_id += 1
        ts = datetime.now(timezone.utc).isoformat()
        print(f"\n===== {DEVICE_NAME} | Scan #{scan_id} | {ts} =====")
        rows = []
        for device_id, ip in PING_TARGETS.items():
            collect_ping(rows, scan_id, ts, device_id, ip)
        collect_self_metrics(rows, scan_id, ts)
        collect_throughput_and_errors(rows, scan_id, ts)
        collect_device_count(rows, scan_id, ts)
        flush(rows)
        time.sleep(INTERVAL_SECONDS)