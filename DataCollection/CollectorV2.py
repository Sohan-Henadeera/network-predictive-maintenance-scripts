import subprocess
import re
import time
import os
import glob
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from hashlib import sha1

from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

DEVICE_NAME = "Client1"             # change per device
DEVICE_TYPE = "Raspberry Pi"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INTERVAL_SECONDS = 10
INTERFACE = "eth0"
TIMEZONE = "Australia/Canberra"     # change to local time as necessary

PING_TARGETS = ["192.168.0.4"]

# --- InfluxDB connection settings ---
INFLUX_URL = "http://192.168.0.4:8086"
INFLUX_TOKEN = "REPLACE_WITH_TOKEN"
INFLUX_ORG = "Capstone Group 25"
INFLUX_BUCKET = "Client1"
PUSH_EVERY_N_SCANS = 3

# --- Power estimate model (Pi 4B, from Raspberry Pi's published figures) ---
EST_IDLE_W = 2.7
EST_FULL_LOAD_W = 6.4

influx_client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
write_api = influx_client.write_api(write_options=SYNCHRONOUS)

_prev_net = None
_prev_net_time = None
_last_cpu_pct = None
_points_buffer = []

def add_row(rows, scan_id, ts, device_id, metric_name, value, unit, method, notes=""):
    rows.append([scan_id, ts, device_id, DEVICE_NAME, DEVICE_TYPE, metric_name, value, unit, method, notes])
    print(f"  [{scan_id}] {device_id:12s} | {metric_name:24s} = {value} {unit}")

    try:
        numeric_value = float(value)
    except (TypeError, ValueError):
        return

    point = (
        Point("network_metrics")
        .tag("device_id", device_id)
        .tag("device_name", DEVICE_NAME)
        .tag("device_type", DEVICE_TYPE)
        .tag("metric_name", metric_name)
        .tag("unit", unit)
        .tag("method", method)
        .field("value", numeric_value)
        .time(ts)
    )
    _points_buffer.append(point)


def collect_ping(rows, scan_id, ts, device_id, ip):
    try:
        result = subprocess.run(["ping", "-c", "4", "-W", "2", ip], capture_output=True, text=True)
        output = result.stdout
        loss_match = re.search(r"(\d+)% packet loss", output)
        packet_loss = float(loss_match.group(1)) if loss_match else 100.0
        rtt_match = re.search(r"= [\d.]+/([\d.]+)/", output)
        avg_latency = float(rtt_match.group(1)) if rtt_match else None
        reachable = 0 if packet_loss == 100.0 else 1
        add_row(rows, scan_id, ts, device_id, "latency_ms",
                avg_latency if avg_latency is not None else "", "ms", "ping")
        add_row(rows, scan_id, ts, device_id, "packet_loss_pct", packet_loss, "%", "ping")
        add_row(rows, scan_id, ts, device_id, "reachability", reachable, "bool", "ping")
    except Exception as e:
        print(f"  ping failed for {device_id}: {e}")


def collect_self_metrics(rows, scan_id, ts):
    global _last_cpu_pct
    try:
        import psutil
        _last_cpu_pct = psutil.cpu_percent(interval=1)
        add_row(rows, scan_id, ts, DEVICE_NAME, "cpu_pct", _last_cpu_pct, "%", "psutil")
        add_row(rows, scan_id, ts, DEVICE_NAME, "disk_usage_pct", psutil.disk_usage("/").percent, "%", "psutil")
    except Exception as e:
        print(f"  psutil failed: {e}")
    try:
        with open("/proc/uptime") as f:
            uptime_seconds = float(f.readline().split()[0])
        add_row(rows, scan_id, ts, DEVICE_NAME, "uptime_seconds", round(uptime_seconds, 1), "s", "/proc/uptime")
    except Exception as e:
        print(f"  uptime failed: {e}")
    try:
        result = subprocess.run(["vcgencmd", "measure_temp"], capture_output=True, text=True)
        temp_match = re.search(r"temp=([\d.]+)", result.stdout)
        if temp_match:
            add_row(rows, scan_id, ts, DEVICE_NAME, "temperature_c", float(temp_match.group(1)), "C", "vcgencmd")
    except Exception as e:
        print(f"  vcgencmd failed: {e}")


def _vc(*args):
    return subprocess.run(["vcgencmd", *args], capture_output=True, text=True, timeout=5).stdout.strip()


def _read(path):
    with open(path) as f:
        return f.read().strip()


def collect_power_metrics(rows, scan_id, ts):
    # CPU voltage
    try:
        m = re.search(r"volt=([\d.]+)V", _vc("measure_volts", "core"))
        if m:
            add_row(rows, scan_id, ts, DEVICE_NAME, "cpu_voltage_v", float(m.group(1)), "V", "vcgencmd")
    except Exception as e:
        print(f"  cpu voltage failed: {e}")

    # power supply low voltage, throttled, speed capped
    try:
        t = int(_vc("get_throttled").split("=")[1], 16)
        add_row(rows, scan_id, ts, DEVICE_NAME, "power_supply_low_voltage", int(bool(t & 0x1)), "bool", "vcgencmd")
        add_row(rows, scan_id, ts, DEVICE_NAME, "cpu_throttled", int(bool(t & 0x4)), "bool", "vcgencmd")
        add_row(rows, scan_id, ts, DEVICE_NAME, "cpu_speed_capped", int(bool(t & 0x2)), "bool", "vcgencmd")
    except Exception as e:
        print(f"  get_throttled failed: {e}")

    # CPU clock speed
    try:
        m = re.search(r"=(\d+)", _vc("measure_clock", "arm"))
        if m:
            add_row(rows, scan_id, ts, DEVICE_NAME, "cpu_clock_mhz", round(int(m.group(1)) / 1e6, 1), "MHz", "vcgencmd")
    except Exception as e:
        print(f"  cpu clock failed: {e}")

    # fan level
    try:
        for d in glob.glob("/sys/class/thermal/cooling_device*"):
            if "fan" in _read(os.path.join(d, "type")).lower():
                level = int(_read(os.path.join(d, "cur_state")))
                add_row(rows, scan_id, ts, DEVICE_NAME, "fan_speed_level", level, "level", "thermal")
                break
    except Exception:
        pass

    # estimated power draw
    if _last_cpu_pct is not None:
        est_w = EST_IDLE_W + (EST_FULL_LOAD_W - EST_IDLE_W) * (_last_cpu_pct / 100.0)
        add_row(rows, scan_id, ts, DEVICE_NAME, "est_power_draw_w", round(est_w, 2), "W", "model",
                "estimate from cpu_pct, not measured")


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
            add_row(rows, scan_id, ts, DEVICE_NAME, "throughput_bytes_per_sec", throughput_bps, "B/s", "/proc/net/dev")
            add_row(rows, scan_id, ts, DEVICE_NAME, "packet_error_rate_pct", error_rate_pct, "%", "/proc/net/dev")
        else:
            print("  first cycle - establishing baseline for throughput/error rate")
        _prev_net = stats
        _prev_net_time = now
    except Exception as e:
        print(f"  throughput/error read failed: {e}")

def flush_influx():
    """Push everything accumulated in _points_buffer since the last push, then clear it."""
    global _points_buffer
    if not _points_buffer:
        return
    try:
        write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=_points_buffer)
        print(f"  [influx] pushed {len(_points_buffer)} points to bucket '{INFLUX_BUCKET}'")
        _points_buffer = []
    except Exception as e:
        # leave the buffer intact on failure, retry on the next push instead of losing points
        print(f"  [influx] push failed, will retry next cycle with buffer still intact: {e}")


if __name__ == "__main__":
    scan_count = 0
    push_seconds = INTERVAL_SECONDS * PUSH_EVERY_N_SCANS
    print(f"[{DEVICE_NAME}] scanning every {INTERVAL_SECONDS}s, pushing to InfluxDB every {push_seconds}s. Ctrl+C to stop.")
    while True:
        ts = datetime.now(tz=ZoneInfo(TIMEZONE)).isoformat()
        scan_id = sha1((ts + DEVICE_NAME).encode()).hexdigest() # scan id is a hash
        print(f"\n===== {DEVICE_NAME} | Scan #{scan_id} | {ts} =====")
        rows = []
        for ip in PING_TARGETS:
            collect_ping(rows, scan_id, ts, DEVICE_NAME, ip)
        collect_self_metrics(rows, scan_id, ts)
        collect_power_metrics(rows, scan_id, ts)
        collect_throughput_and_errors(rows, scan_id, ts)
        scan_count += 1

        if scan_count % PUSH_EVERY_N_SCANS == 0:
            flush_influx()

        time.sleep(INTERVAL_SECONDS)