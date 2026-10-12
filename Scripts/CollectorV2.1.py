import subprocess
import re
import time
import os
from datetime import datetime
from zoneinfo import ZoneInfo
from hashlib import sha1

from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

DEVICE_NAME = "Client1"             # change per device
DEVICE_TYPE = "Raspberry Pi"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
INTERVAL_SECONDS = 10
INTERFACE = "eth0"
TIMEZONE = "Australia/Canberra"

PING_TARGETS = ["192.168.0.4"]

# --- InfluxDB connection settings ---
INFLUX_URL = "http://192.168.0.4:8086"
INFLUX_TOKEN = "REPLACE_WITH_TOKEN"
INFLUX_ORG = "Capstone Group 25"
INFLUX_BUCKET = "Client1"
PUSH_EVERY_N_SCANS = 3

# --- Power estimate model
EST_IDLE_W = 2.7
EST_FULL_LOAD_W = 6.4

influx_client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
write_api = influx_client.write_api(write_options=SYNCHRONOUS)

_prev_net = None
_prev_net_time = None
_prev_cpu = None
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


def _vc(*args):
    """Run vcgencmd and return stdout. Raises with stderr included if it produced nothing,
    so a permissions/PATH problem is logged instead of silently skipping the metric."""
    r = subprocess.run(["vcgencmd", *args], capture_output=True, text=True, timeout=5)
    out = r.stdout.strip()
    if not out:
        raise RuntimeError(f"vcgencmd {' '.join(args)} returned nothing (rc={r.returncode}, stderr={r.stderr.strip()!r})")
    return out


def _read(path):
    with open(path) as f:
        return f.read().strip()


def _read_cpu_times():
    """Aggregate CPU ticks from the first line of /proc/stat -> (idle, total)."""
    with open("/proc/stat") as f:
        fields = f.readline().split()
    vals = [int(x) for x in fields[1:9]]
    idle = vals[3] + vals[4]
    return idle, sum(vals)


def prime_cpu():
    """Take a baseline /proc/stat reading so the first scan has a real delta."""
    global _prev_cpu
    try:
        _prev_cpu = _read_cpu_times()
    except Exception as e:
        print(f"  cpu baseline failed: {e}")


def startup_check():
    """One-off sanity check so missing vcgencmd access shows up immediately, not as gaps in Grafana."""
    try:
        _vc("version")
        print("  [check] vcgencmd OK")
    except FileNotFoundError:
        print("  [check] vcgencmd NOT FOUND - voltage/throttle metrics will be skipped, "
              "temp and clock will fall back to sysfs")
    except Exception as e:
        print(f"  [check] vcgencmd not usable ({e}). Usually fixed with: sudo usermod -aG video $USER, then re-login")


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


def collect_cpu_pct(rows, scan_id, ts):
    """CPU utilisation averaged over the whole time since the previous scan (not a 1s snapshot).
    Returns the value so the power estimate uses THIS scan's reading, never a stale one."""
    global _prev_cpu
    try:
        cur = _read_cpu_times()
        if _prev_cpu is None:
            _prev_cpu = cur
            print("  cpu_pct: no baseline yet, will report next scan")
            return None
        d_idle = cur[0] - _prev_cpu[0]
        d_total = cur[1] - _prev_cpu[1]
        _prev_cpu = cur
        if d_total <= 0:
            print("  cpu_pct: no ticks elapsed, skipping")
            return None
        cpu_pct = round(max(0.0, min(100.0, (1 - d_idle / d_total) * 100)), 1)
        add_row(rows, scan_id, ts, DEVICE_NAME, "cpu_pct", cpu_pct, "%", "/proc/stat")
        return cpu_pct
    except Exception as e:
        print(f"  cpu_pct failed: {e}")
        return None


def collect_self_metrics(rows, scan_id, ts):
    try:
        import psutil
        add_row(rows, scan_id, ts, DEVICE_NAME, "disk_usage_pct", psutil.disk_usage("/").percent, "%", "psutil")
    except Exception as e:
        print(f"  disk usage failed: {e}")

    try:
        uptime_seconds = float(_read("/proc/uptime").split()[0])
        add_row(rows, scan_id, ts, DEVICE_NAME, "uptime_seconds", round(uptime_seconds, 1), "s", "/proc/uptime")
    except Exception as e:
        print(f"  uptime failed: {e}")

    # CPU temperature: vcgencmd
    temp = None
    try:
        m = re.search(r"temp=([\d.]+)", _vc("measure_temp"))
        if m:
            temp, method = float(m.group(1)), "vcgencmd"
    except Exception as e:
        print(f"  temp via vcgencmd failed: {e}")
    if temp is None:
        try:
            temp, method = round(int(_read("/sys/class/thermal/thermal_zone0/temp")) / 1000, 1), "sysfs"
        except Exception as e:
            print(f"  temp via sysfs failed: {e}")
    if temp is not None:
        add_row(rows, scan_id, ts, DEVICE_NAME, "temperature_c", temp, "C", method)


def collect_power_metrics(rows, scan_id, ts, cpu_pct):
    # CPU core voltage
    try:
        out = _vc("measure_volts", "core")
        m = re.search(r"volt=([\d.]+)V", out)
        if m:
            add_row(rows, scan_id, ts, DEVICE_NAME, "cpu_voltage_v", float(m.group(1)), "V", "vcgencmd")
        else:
            print(f"  cpu voltage: unexpected output {out!r}")
    except Exception as e:
        print(f"  cpu voltage failed: {e}")

    try:
        out = _vc("get_throttled")
        m = re.search(r"throttled=(0x[0-9a-fA-F]+)", out)
        if not m:
            raise ValueError(f"unexpected output {out!r}")
        t = int(m.group(1), 16)
        add_row(rows, scan_id, ts, DEVICE_NAME, "power_supply_low_voltage", int(bool(t & 0x1)), "bool", "vcgencmd")
        add_row(rows, scan_id, ts, DEVICE_NAME, "cpu_speed_capped", int(bool(t & 0x2)), "bool", "vcgencmd")
        add_row(rows, scan_id, ts, DEVICE_NAME, "cpu_throttled", int(bool(t & 0x4)), "bool", "vcgencmd")
    except Exception as e:
        print(f"  get_throttled failed: {e}")

    mhz = None
    try:
        out = _vc("measure_clock", "arm")
        m = re.search(r"=\s*(\d+)", out)
        if m and int(m.group(1)) > 0:
            mhz, method = round(int(m.group(1)) / 1e6, 1), "vcgencmd"
        else:
            print(f"  cpu clock via vcgencmd: unusable output {out!r}")
    except Exception as e:
        print(f"  cpu clock via vcgencmd failed: {e}")
    if mhz is None:
        try:
            khz = int(_read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq"))
            mhz, method = round(khz / 1000, 1), "sysfs"
        except Exception as e:
            print(f"  cpu clock via sysfs failed: {e}")
    if mhz is not None:
        add_row(rows, scan_id, ts, DEVICE_NAME, "cpu_clock_mhz", mhz, "MHz", method)

    # estimated power draw, only from this scan's cpu_pct
    if cpu_pct is not None:
        est_w = EST_IDLE_W + (EST_FULL_LOAD_W - EST_IDLE_W) * (cpu_pct / 100.0)
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
        print(f"  [influx] push failed, will retry next cycle with buffer still intact: {e}")


if __name__ == "__main__":
    scan_count = 0
    push_seconds = INTERVAL_SECONDS * PUSH_EVERY_N_SCANS
    print(f"[{DEVICE_NAME}] scanning every {INTERVAL_SECONDS}s, pushing to InfluxDB every {push_seconds}s. Ctrl+C to stop.")
    startup_check()
    prime_cpu()
    time.sleep(1)
    while True:
        ts = datetime.now(tz=ZoneInfo(TIMEZONE)).isoformat()
        scan_id = sha1((ts + DEVICE_NAME).encode()).hexdigest()
        print(f"\n===== {DEVICE_NAME} | Scan #{scan_id} | {ts} =====")
        rows = []
        cpu_pct = collect_cpu_pct(rows, scan_id, ts)
        for ip in PING_TARGETS:
            collect_ping(rows, scan_id, ts, DEVICE_NAME, ip)
        collect_self_metrics(rows, scan_id, ts)
        collect_power_metrics(rows, scan_id, ts, cpu_pct)
        collect_throughput_and_errors(rows, scan_id, ts)
        scan_count += 1

        if scan_count % PUSH_EVERY_N_SCANS == 0:
            flush_influx()

        time.sleep(INTERVAL_SECONDS)