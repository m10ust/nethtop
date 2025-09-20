#!/usr/bin/env python3
"""NetHtop++: network hunt console with ghost response playbooks."""

# NETWORK ARMY KNIFE
# The only network monitoring tool that incorporates htop like connections monitoring with kill # function, trace, ghost sockets inspector and counter-measures baked in, all interfaces easy 
# monitoring, tcpdump to pcap file and extensive logging capabilities. Why switch between lsof
# tcpdump, nettop, netstat, ps, nettrace, iftop etc. when you can have it all in one terminal?

import argparse
import contextlib
import curses
import errno
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
import warnings
from collections import defaultdict, deque
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Deque, Dict, Iterable, List, Optional, Sequence, Tuple

import psutil

warnings.filterwarnings("ignore", category=DeprecationWarning, module="psutil")

try:  # optional enrichment helper
    from ipwhois import IPWhois
except Exception:  # pragma: no cover - optional
    IPWhois = None

PROCESS_CACHE_TTL = 5.0
REFRESH_MIN_INTERVAL = 0.2
HISTORY_LENGTH = 120
GRAPH_CHARS = " .:-=+*#%@"
GHOST_CHECK_INTERVAL = 15.0
LAUNCHD_SCAN_INTERVAL = 60.0
LOOPBACK_BURST_THRESHOLD = 30.0
LOOPBACK_PORT_FANOUT = 15
EVENT_LOG_LIMIT = 500
STREAM_ENV_VAR = "NETHTOP_STREAM_TARGET"
ALERT_EXPORT_DIR = Path.cwd() / "exports"
CAPTURE_DIR = Path.cwd() / "captures"
PLUGIN_DIR_NAME = "hunters"
ALERT_COOLDOWN = 30.0
SNAPSHOT_DIR = Path.cwd() / "snapshots"
PF_TABLE_NAME = "nethtop_ghost_block"
CAPTURE_DURATION = 60
BANNER_LINES = [
    " /$$   /$$ /$$$$$$$$ /$$$$$$$$ /$$      /$$  /$$$$$$  /$$$$$$$  /$$   /$$        /$$$$$$  /$$$$$$$  /$$      /$$ /$$     /$$       /$$   /$$ /$$   /$$ /$$$$$$ /$$$$$$$$ /$$$$$$$$",
    "| $$$ | $$| $$_____/|__  $$__/| $$  /$ | $$ /$$__  $$| $$__  $$| $$  /$$/       /$$__  $$| $$__  $$| $$$    /$$$|  $$   /$$/      | $$  /$$/| $$$ | $$|_  $$_/| $$_____/| $$_____",
    "| $$$$| $$| $$         | $$   | $$ /$$$| $$| $$  \ $$| $$  \ $$| $$ /$$/       | $$  \ $$| $$  \ $$| $$$$  /$$$$ \  $$ /$$/       | $$ /$$/ | $$$$| $$  | $$  | $$      | $$      ",
    "| $$ $$ $$| $$$$$      | $$   | $$/$$ $$ $$| $$  | $$| $$$$$$$/| $$$$$/        | $$$$$$$$| $$$$$$$/| $$ $$/$$ $$  \  $$$$/        | $$$$$/  | $$ $$ $$  | $$  | $$$$$   | $$$$$   ",
    "| $$  $$$$| $$__/      | $$   | $$$$_  $$$$| $$  | $$| $$__  $$| $$  $$        | $$__  $$| $$__  $$| $$  $$$| $$   \  $$/         | $$  $$  | $$  $$$$  | $$  | $$__/   | $$__/   ",
    "| $$\  $$$| $$         | $$   | $$$/ \  $$$| $$  | $$| $$  \ $$| $$\  $$       | $$  | $$| $$  \ $$| $$\  $ | $$    | $$          | $$\  $$ | $$\  $$$  | $$  | $$      | $$      ",
    "| $$ \  $$| $$$$$$$$   | $$   | $$/   \  $$|  $$$$$$/| $$  | $$| $$ \  $$      | $$  | $$| $$  | $$| $$ \/  | $$    | $$          | $$ \  $$| $$ \  $$ /$$$$$$| $$      | $$$$$$$$",
    "|__/  \__/|________/   |__/   |__/     \__/ \______/ |__/  |__/|__/  \__/      |__/  |__/|__/  |__/|__/     |__/    |__/          |__/  \__/|__/  \__/|______/|__/      |________/",
    "",
    "",
    "",
]


@dataclass
class ConnectionRow:
    protocol: str
    laddr: str
    raddr: str
    remote_ip: Optional[str]
    status: str
    pid: Optional[int]
    proc_name: str
    cmdline: str
    laddr_tuple: Optional[Tuple[str, int]]
    raddr_tuple: Optional[Tuple[str, int]]


@dataclass
class AlertRecord:
    timestamp: float
    category: str
    severity: str
    summary: str
    details: Dict[str, Any]

    def as_dict(self) -> Dict[str, Any]:
        data = dict(self.details)
        ts_iso = datetime.fromtimestamp(self.timestamp, timezone.utc).isoformat().replace("+00:00", "Z")
        data.update(
            {
                "timestamp": self.timestamp,
                "ts_iso": ts_iso,
                "category": self.category,
                "severity": self.severity,
                "summary": self.summary,
            }
        )
        return data

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), sort_keys=True)


class AlertStreamer:
    def __init__(self) -> None:
        self._target = os.getenv(STREAM_ENV_VAR)
        self._lock = threading.Lock()
        self._sock: Optional[ssl.SSLSocket] = None
        self._context = ssl.create_default_context()

    def send(self, alert: AlertRecord) -> None:
        if not self._target:
            return
        payload = alert.to_json().encode("utf-8") + b"\n"
        with self._lock:
            try:
                self._ensure_socket()
                if not self._sock:
                    return
                self._sock.write(payload)
            except Exception:
                self._close_socket()

    def _ensure_socket(self) -> None:
        if self._sock:
            return
        if not self._target or ":" not in self._target:
            return
        host, port = self._target.split(":", 1)
        try:
            port_int = int(port)
        except ValueError:
            return
        try:
            raw = socket.create_connection((host, port_int), timeout=5)
            self._sock = self._context.wrap_socket(raw, server_hostname=host)
        except Exception:
            self._sock = None

    def _close_socket(self) -> None:
        if self._sock:
            with contextlib.suppress(Exception):
                self._sock.close()
        self._sock = None


class EventLog:
    def __init__(self, limit: int, streamer: AlertStreamer) -> None:
        self._events: Deque[AlertRecord] = deque(maxlen=limit)
        self._lock = threading.Lock()
        self._file_path = Path.home() / ".nethtop_plus_events.jsonl"
        self._streamer = streamer
        self._cooldown_index: Dict[Tuple[str, str], float] = {}

    def add(self, alert: AlertRecord) -> bool:
        if alert.severity.lower() != "info":
            key = (alert.category, alert.summary)
            now = alert.timestamp
            last = self._cooldown_index.get(key)
            if last is not None and now - last < ALERT_COOLDOWN:
                return False
            self._cooldown_index[key] = now
        with self._lock:
            self._events.append(alert)
        self._append_to_disk(alert)
        if self._streamer:
            self._streamer.send(alert)
        return True

    def recent(self, count: int) -> List[AlertRecord]:
        with self._lock:
            return list(self._events)[-count:]

    def export(self) -> Path:
        ALERT_EXPORT_DIR.mkdir(parents=True, exist_ok=True)
        now = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        path = ALERT_EXPORT_DIR / f"nethtop_plus_alerts_{now}.json"
        with self._lock:
            payload = [record.as_dict() for record in self._events]
        with path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
        return path

    def _append_to_disk(self, alert: AlertRecord) -> None:
        try:
            self._file_path.parent.mkdir(parents=True, exist_ok=True)
            with self._file_path.open("a", encoding="utf-8") as handle:
                handle.write(alert.to_json())
                handle.write("\n")
        except OSError:
            pass


class LoopbackAnomalyTracker:
    def __init__(self) -> None:
        self._previous: Optional[set] = None
        self._last_timestamp: Optional[float] = None

    def analyze(self, connections: Sequence[ConnectionRow], timestamp: float) -> List[AlertRecord]:
        loopback_now: set = set()
        fanout_tracker: Dict[str, set] = defaultdict(set)
        for row in connections:
            if not row.laddr:
                continue
            if row.laddr.startswith("127.") or row.laddr.startswith("::1"):
                key = (row.protocol, row.laddr, row.raddr)
                loopback_now.add(key)
                port = row.laddr.split(":")[-1] if ":" in row.laddr else row.laddr
                fanout_tracker[port].add(row.raddr or "[none]")
        alerts: List[AlertRecord] = []
        if self._previous is not None and self._last_timestamp is not None:
            new_connections = loopback_now - self._previous
            dt = max(timestamp - self._last_timestamp, 1e-6)
            rate = len(new_connections) / dt
            if rate > LOOPBACK_BURST_THRESHOLD and new_connections:
                alerts.append(
                    AlertRecord(
                        timestamp=timestamp,
                        category="loopback",
                        severity="warning",
                        summary="Loopback connection burst detected",
                        details={
                            "rate_per_sec": round(rate, 2),
                            "sample_connections": list(new_connections)[:5],
                        },
                    )
                )
            noisy_ports = [port for port, peers in fanout_tracker.items() if len(peers) >= LOOPBACK_PORT_FANOUT]
            if noisy_ports:
                alerts.append(
                    AlertRecord(
                        timestamp=timestamp,
                        category="loopback",
                        severity="warning",
                        summary="Loopback port fan-out anomaly",
                        details={
                            "ports": noisy_ports,
                            "peer_counts": {port: len(fanout_tracker[port]) for port in noisy_ports},
                        },
                    )
                )
        self._previous = loopback_now
        self._last_timestamp = timestamp
        return alerts


class PacketCaptureManager:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._process: Optional[subprocess.Popen] = None
        self._target: Optional[str] = None
        self._file: Optional[Path] = None
        self._monitor: Optional[threading.Thread] = None

    def toggle(
        self,
        row: ConnectionRow,
        callback: Callable[[AlertRecord], None],
        *,
        iface: Optional[str] = None,
        prefix: str = "capture",
    ) -> None:
        with self._lock:
            if self._process:
                self._stop_capture(callback)
                return
            self._start_capture(row, callback, iface=iface, prefix=prefix)

    def _start_capture(
        self,
        row: ConnectionRow,
        callback: Callable[[AlertRecord], None],
        *,
        iface: Optional[str] = None,
        prefix: str = "capture",
    ) -> None:
        target_ip = row.remote_ip or (row.laddr_tuple[0] if row.laddr_tuple else None)
        target_port = None
        if row.remote_ip and row.raddr_tuple:
            target_port = row.raddr_tuple[1]
        elif row.laddr_tuple:
            target_port = row.laddr_tuple[1]
        if not target_ip:
            callback(
                AlertRecord(
                    timestamp=time.time(),
                    category="pcap",
                    severity="info",
                    summary="Capture skipped: no IP available",
                    details={},
                )
            )
            return
        CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
        timestamp_label = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        file_label = f"{prefix}_{target_ip.replace(':', '_')}_{target_port or 'any'}_{timestamp_label}.pcap"
        pcap_path = CAPTURE_DIR / file_label
        bpf = ["host", target_ip]
        if target_port:
            bpf += ["and", "port", str(target_port)]
        interface = iface or "any"
        cmd = [
            "tcpdump",
            "-i",
            interface,
            "-s",
            "0",
            "-G",
            str(CAPTURE_DURATION),
            "-W",
            "1",
            "-w",
            str(pcap_path),
        ] + bpf
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except FileNotFoundError:
            callback(
                AlertRecord(
                    timestamp=time.time(),
                    category="pcap",
                    severity="error",
                    summary="tcpdump not available",
                    details={"command": " ".join(cmd)},
                )
            )
            return
        except PermissionError:
            callback(
                AlertRecord(
                    timestamp=time.time(),
                    category="pcap",
                    severity="error",
                    summary="Permission denied starting tcpdump",
                    details={"command": " ".join(cmd)},
                )
            )
            return
        self._process = proc
        self._target = f"{target_ip}:{target_port or 'any'}"
        self._file = pcap_path
        self._monitor = threading.Thread(
            target=self._await_completion, args=(proc, callback), daemon=True
        )
        self._monitor.start()
        callback(
            AlertRecord(
                timestamp=time.time(),
                category="pcap",
                severity="info",
                summary="Packet capture started (60s)",
                details={"target": self._target, "file": str(pcap_path)},
            )
        )

    def _stop_capture(self, callback: Callable[[AlertRecord], None]) -> None:
        if not self._process:
            return
        with contextlib.suppress(Exception):
            self._process.terminate()
        with contextlib.suppress(Exception):
            self._process.wait(timeout=3)
        if self._monitor and self._monitor.is_alive():
            self._monitor.join(timeout=0.5)
        callback(
            AlertRecord(
                timestamp=time.time(),
                category="pcap",
                severity="info",
                summary="Packet capture stopped",
                details={"target": self._target, "file": str(self._file) if self._file else None},
            )
        )
        self._process = None
        self._target = None
        self._file = None
        self._monitor = None

    def _await_completion(self, proc: subprocess.Popen, callback: Callable[[AlertRecord], None]) -> None:
        proc.wait()
        with self._lock:
            if self._process is not proc:
                return
            target = self._target
            file_path = str(self._file) if self._file else None
            self._process = None
            self._target = None
            self._file = None
            self._monitor = None
        callback(
            AlertRecord(
                timestamp=time.time(),
                category="pcap",
                severity="info",
                summary="Packet capture finished",
                details={"target": target, "file": file_path},
            )
        )


class PluginManager:
    def __init__(self, alert_callback: Callable[[AlertRecord], None]) -> None:
        self._alert_callback = alert_callback
        self._plugins: List[Any] = []
        self._load_plugins()

    def _load_plugins(self) -> None:
        plugin_dir = Path(__file__).with_name(PLUGIN_DIR_NAME)
        if not plugin_dir.exists():
            return
        sys.path.insert(0, str(plugin_dir))
        for path in plugin_dir.glob("*.py"):
            module_name = path.stem
            try:
                module = __import__(module_name)
            except Exception as exc:
                self._alert_callback(
                    AlertRecord(
                        timestamp=time.time(),
                        category="plugin",
                        severity="error",
                        summary=f"Failed to load plugin {module_name}",
                        details={"error": str(exc)},
                    )
                )
                continue
            if hasattr(module, "run_detector"):
                self._plugins.append(module)

    def run_detectors(self, connections: Sequence[ConnectionRow], timestamp: float) -> None:
        for plugin in self._plugins:
            try:
                plugin.run_detector(connections, self._alert_callback, timestamp)
            except Exception as exc:
                self._alert_callback(
                    AlertRecord(
                        timestamp=time.time(),
                        category="plugin",
                        severity="error",
                        summary=f"Detector error: {plugin.__name__}",
                        details={"error": str(exc)},
                    )
                )


class Enricher:
    def __init__(self) -> None:
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._pending: Dict[str, Future] = {}

    def request(self, ip: Optional[str], executor: ThreadPoolExecutor) -> None:
        if not ip or ip in self._cache or ip in self._pending:
            return
        if IPWhois is None:
            return
        self._pending[ip] = executor.submit(self._lookup, ip)

    def poll(self) -> None:
        for ip, future in list(self._pending.items()):
            if future.done():
                self._pending.pop(ip, None)
                try:
                    result = future.result()
                except Exception:
                    result = None
                if result:
                    self._cache[ip] = result

    def data(self, ip: Optional[str]) -> Optional[Dict[str, Any]]:
        if not ip:
            return None
        return self._cache.get(ip)

    @staticmethod
    def _lookup(ip: str) -> Optional[Dict[str, Any]]:
        try:
            lookup = IPWhois(ip).lookup_rdap(depth=1)
        except Exception:
            return None
        asn = lookup.get("asn")
        network = (lookup.get("network") or {}).get("name")
        country = lookup.get("asn_country_code")
        return {
            "asn": asn,
            "network": network,
            "country": country,
            "description": lookup.get("asn_description"),
        }


class NetTopPlusPlusApp:
    def __init__(self, interval: float, kind: str) -> None:
        self.interval = max(interval, REFRESH_MIN_INTERVAL)
        self.kind = kind
        self.connections: List[ConnectionRow] = []
        self.selected_index = 0
        self.scroll_offset = 0
        self.last_refresh = 0.0
        self.prev_counters: Optional[Dict[str, psutil._common.snetio]] = None
        self.prev_time: Optional[float] = None
        self.nic_history: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=HISTORY_LENGTH))
        self.nic_history_rx: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=HISTORY_LENGTH))
        self.nic_history_tx: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=HISTORY_LENGTH))
        self.nic_rates: Dict[str, Tuple[float, float]] = {}
        self.addr_to_iface: Dict[str, str] = {}
        self.status_message = ""
        self.status_timestamp = 0.0
        self.dns_cache: Dict[str, str] = {}
        self.pending_lookups: Dict[str, Future] = {}
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.process_cache: Dict[int, Tuple[str, str]] = {}
        self.process_cache_expiry: Dict[int, float] = {}
        self.pid_to_launchd: Dict[int, str] = {}
        self.ghost_last_run = 0.0
        self.launchd_last_run = 0.0
        self.loopback_tracker = LoopbackAnomalyTracker()
        self.streamer = AlertStreamer()
        self.alert_log = EventLog(EVENT_LOG_LIMIT, self.streamer)
        self.enricher = Enricher()
        self.packet_captures = PacketCaptureManager()
        self.plugin_manager = PluginManager(self._record_alert)
        self.launchd_duplicates: Dict[str, int] = {}
        self.ghost_entries: List[Dict[str, Any]] = []
        self.show_ghost_overlay = False
        self.ghost_cursor = 0
        self.trace_overlay = False
        self.trace_target: Optional[str] = None
        self.trace_lines: List[str] = []
        self.trace_future: Optional[Future] = None
        self.trace_scroll = 0
        self.trace_visible_rows = 0

    def run(self) -> None:
        try:
            curses.wrapper(self._main)
        finally:
            self.executor.shutdown(wait=False)

    def update_data(self) -> None:
        now = time.time()
        counters = psutil.net_io_counters(pernic=True)
        try:
            if_addrs = psutil.net_if_addrs()
        except psutil.Error:  # pragma: no cover - defensive
            if_addrs = {}
        self.addr_to_iface = {}
        for nic, addrs in if_addrs.items():
            for addr in addrs:
                family = getattr(addr, "family", None)
                address = getattr(addr, "address", None)
                if family not in (socket.AF_INET, socket.AF_INET6) or not address:
                    continue
                base_address = address.split("%", 1)[0]
                self.addr_to_iface[base_address] = nic
        if self.prev_counters is not None and self.prev_time is not None:
            dt = max(now - self.prev_time, 1e-6)
            for nic, stats in counters.items():
                prev = self.prev_counters.get(nic)
                if prev is None:
                    continue
                send_rate = max(0.0, (stats.bytes_sent - prev.bytes_sent) / dt)
                recv_rate = max(0.0, (stats.bytes_recv - prev.bytes_recv) / dt)
                total_rate = send_rate + recv_rate
                self.nic_rates[nic] = (send_rate, recv_rate)
                self.nic_history[nic].append(total_rate)
                self.nic_history_rx[nic].append(recv_rate)
                self.nic_history_tx[nic].append(send_rate)
        self.prev_counters = counters
        self.prev_time = now

        collected = self._collect_connections()
        self.connections = collected
        if self.selected_index >= len(self.connections):
            self.selected_index = max(0, len(self.connections) - 1)
        if self.selected_index < 0:
            self.selected_index = 0

        loopback_alerts = self.loopback_tracker.analyze(self.connections, now)
        for alert in loopback_alerts:
            self._record_alert(alert)

        if now - self.ghost_last_run >= GHOST_CHECK_INTERVAL:
            for alert in self._detect_ghost_sockets():
                self._record_alert(alert)
            self.ghost_last_run = now

        if now - self.launchd_last_run >= LAUNCHD_SCAN_INTERVAL:
            for alert in self._scan_launchd():
                self._record_alert(alert)
            self.launchd_last_run = now

        for alert in self._detect_container_anomalies(now):
            self._record_alert(alert)

        self.plugin_manager.run_detectors(self.connections, now)

    def _collect_connections(self) -> List[ConnectionRow]:
        rows: List[ConnectionRow] = []
        try:
            connections = psutil.net_connections(kind=self.kind)
        except psutil.Error as exc:  # pragma: no cover - defensive
            self.set_status(f"Failed to collect connections: {exc}")
            return rows

        for conn in connections:
            laddr = self._format_addr(conn.laddr)
            remote_ip = self._extract_ip(conn.raddr)
            if remote_ip:
                self.enricher.request(remote_ip, self.executor)
            raddr = self._format_addr(conn.raddr)
            protocol = self._protocol_name(conn)
            status = conn.status
            pid = conn.pid
            laddr_tuple = self._addr_tuple(conn.laddr)
            raddr_tuple = self._addr_tuple(conn.raddr)
            proc_name, cmdline = self._process_info(pid)
            rows.append(
                ConnectionRow(
                    protocol=protocol,
                    laddr=laddr,
                    raddr=raddr,
                    remote_ip=remote_ip,
                    status=status,
                    pid=pid,
                    proc_name=proc_name,
                    cmdline=cmdline,
                    laddr_tuple=laddr_tuple,
                    raddr_tuple=raddr_tuple,
                )
            )
        rows.sort(key=lambda row: (row.protocol, row.status, row.proc_name, row.laddr, row.raddr))
        return rows

    def _process_info(self, pid: Optional[int]) -> Tuple[str, str]:
        if not pid:
            return ("-", "")
        now = time.time()
        cached = self.process_cache.get(pid)
        expiry = self.process_cache_expiry.get(pid, 0.0)
        if cached and expiry > now:
            return cached
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            cmdline_list = proc.cmdline()
            cmdline = " ".join(cmdline_list) if cmdline_list else proc.exe() or proc_name
        except psutil.NoSuchProcess:
            proc_name = "<terminated>"
            cmdline = ""
        except psutil.AccessDenied:
            proc_name = "<denied>"
            cmdline = ""
        except psutil.Error as exc:  # pragma: no cover - defensive
            proc_name = f"<error {exc}>"
            cmdline = ""
        self.process_cache[pid] = (proc_name, cmdline)
        self.process_cache_expiry[pid] = now + PROCESS_CACHE_TTL
        return proc_name, cmdline

    @staticmethod
    def _protocol_name(conn: psutil._common.sconn) -> str:
        base = "?"
        if conn.type == socket.SOCK_STREAM:
            base = "TCP"
        elif conn.type == socket.SOCK_DGRAM:
            base = "UDP"
        family = getattr(conn, "family", None)
        if family == socket.AF_INET6:
            return base + "6"
        if family == socket.AF_INET:
            return base + "4"
        return base

    @staticmethod
    def _format_addr(addr: Optional[psutil._common.addr]) -> str:
        if not addr:
            return ""
        if isinstance(addr, tuple):
            if len(addr) >= 2:
                return f"{addr[0]}:{addr[1]}"
            return str(addr[0])
        ip = getattr(addr, "ip", str(addr))
        port = getattr(addr, "port", "")
        if port in ("", 0):
            return f"{ip}"
        return f"{ip}:{port}"

    @staticmethod
    def _extract_ip(addr: Optional[psutil._common.addr]) -> Optional[str]:
        if not addr:
            return None
        if isinstance(addr, tuple):
            if len(addr) == 0:
                return None
            return addr[0]
        return getattr(addr, "ip", None) or str(addr)

    @staticmethod
    def _addr_tuple(addr: Optional[psutil._common.addr]) -> Optional[Tuple[str, int]]:
        if not addr:
            return None
        if isinstance(addr, tuple):
            if len(addr) >= 2:
                return addr[0], int(addr[1])
            if len(addr) == 1:
                return addr[0], 0
            return None
        ip = getattr(addr, "ip", None)
        port = getattr(addr, "port", None)
        if ip is None:
            return None
        try:
            port_int = int(port) if port is not None else 0
        except (TypeError, ValueError):
            port_int = 0
        return ip, port_int

    def resolve_selected(self) -> None:
        conn = self._current_selection()
        if not conn:
            self.set_status("No connection selected")
            return
        if not conn.remote_ip:
            self.set_status("Selected row has no remote address")
            return
        ip = conn.remote_ip
        if ip in self.dns_cache:
            self.set_status(f"{ip} -> {self.dns_cache[ip]}")
            return
        future = self.pending_lookups.get(ip)
        if future is None:
            future = self.executor.submit(self._reverse_lookup, ip)
            self.pending_lookups[ip] = future
            self.set_status(f"Resolving {ip} …")
        else:
            self.set_status(f"Lookup already in progress for {ip}")

    @staticmethod
    def _reverse_lookup(ip: str) -> Tuple[str, Optional[str]]:
        try:
            host, _aliases, _ = socket.gethostbyaddr(ip)
            return ip, host
        except socket.herror:
            return ip, None
        except Exception as exc:  # pragma: no cover - defensive
            return ip, f"error: {exc}"

    def poll_async(self) -> None:
        self.enricher.poll()
        completed: List[str] = []
        for ip, future in list(self.pending_lookups.items()):
            if future.done():
                completed.append(ip)
                try:
                    ip_key, host = future.result()
                    if host is None:
                        self.set_status(f"No PTR record for {ip_key}")
                    elif host.startswith("error: "):
                        self.set_status(f"Lookup failed for {ip_key}: {host[7:]}")
                        self._record_alert(
                            AlertRecord(
                                timestamp=time.time(),
                                category="dns",
                                severity="warning",
                                summary=f"Reverse lookup failed for {ip_key}",
                                details={"error": host[7:]},
                            )
                        )
                    else:
                        self.dns_cache[ip_key] = host
                        self.set_status(f"{ip_key} -> {host}")
                except Exception as exc:  # pragma: no cover - defensive
                    self.set_status(f"Lookup failed: {exc}")
        for ip in completed:
            self.pending_lookups.pop(ip, None)

    def terminate_selected_process(self) -> None:
        conn = self._current_selection()
        if not conn:
            self.set_status("No connection selected")
            return
        if not conn.pid:
            self.set_status("Selected row has no owning process")
            return
        try:
            proc = psutil.Process(conn.pid)
        except psutil.NoSuchProcess:
            self.set_status("Process already exited")
            return
        except psutil.AccessDenied:
            self.set_status(f"Permission denied inspecting PID {conn.pid}")
            return
        except psutil.Error as exc:  # pragma: no cover - defensive
            self.set_status(f"Process lookup failed: {exc}")
            return

        try:
            proc.terminate()
        except psutil.AccessDenied:
            self.set_status(f"Permission denied terminating PID {conn.pid}")
            return
        except psutil.Error as exc:  # pragma: no cover - defensive
            self.set_status(f"Terminate failed for PID {conn.pid}: {exc}")
            return

        _, alive = psutil.wait_procs([proc], timeout=2.0)
        if alive:
            for survivor in alive:
                try:
                    survivor.kill()
                except psutil.AccessDenied:
                    self.set_status(f"Permission denied killing PID {conn.pid}")
                    return
                except psutil.Error as exc:  # pragma: no cover - defensive
                    self.set_status(f"Kill failed for PID {conn.pid}: {exc}")
                    return
            psutil.wait_procs(alive, timeout=2.0)

        if proc.is_running():
            self.set_status(f"PID {conn.pid} is still running")
            return

        self.process_cache.pop(conn.pid, None)
        self.process_cache_expiry.pop(conn.pid, None)
        self._record_alert(
            AlertRecord(
                timestamp=time.time(),
                category="process",
                severity="info",
                summary=f"Terminated PID {conn.pid}",
                details={"pid": conn.pid, "proc_name": conn.proc_name},
            )
        )
        self.last_refresh = 0.0

    def close_selected_connection(self) -> None:
        conn = self._current_selection()
        if not conn:
            self.set_status("No connection selected")
            return
        if conn.pid is None:
            self.set_status("Selected row is not associated with a process")
            return
        target = self._find_process_connection(conn)
        if target is None:
            self.set_status("Unable to locate socket for selected connection")
            return
        fd = getattr(target, "fd", -1)
        if fd == -1:
            self.set_status("Socket file descriptor unavailable; cannot close")
            return
        proc_fd_path = f"/proc/{conn.pid}/fd/{fd}"
        if not os.path.exists(proc_fd_path):
            self.set_status("Closing sockets requires /proc access")
            return
        dup_fd: Optional[int] = None
        try:
            dup_fd = os.open(proc_fd_path, os.O_RDWR)
        except FileNotFoundError:
            self.set_status("Socket descriptor vanished before it could be closed")
            return
        except PermissionError:
            try:
                dup_fd = os.open(proc_fd_path, os.O_RDONLY)
            except PermissionError:
                self.set_status("Permission denied accessing socket descriptor")
                return
            except OSError as exc:  # pragma: no cover - defensive
                self.set_status(f"Failed to access socket: {exc}")
                return
        except OSError as exc:
            if exc.errno == errno.EACCES:
                try:
                    dup_fd = os.open(proc_fd_path, os.O_RDONLY)
                except PermissionError:
                    self.set_status("Permission denied accessing socket descriptor")
                    return
                except OSError as inner_exc:  # pragma: no cover - defensive
                    self.set_status(f"Failed to access socket: {inner_exc}")
                    return
            else:
                self.set_status(f"Failed to access socket: {exc}")
                return

        if dup_fd is None:
            self.set_status("Unable to access socket descriptor")
            return

        try:
            sock = socket.fromfd(dup_fd, target.family, target.type)
        except OSError as exc:
            with contextlib.suppress(OSError):
                os.close(dup_fd)
            self.set_status(f"Failed to attach to socket: {exc}")
            return

        with contextlib.suppress(OSError):
            os.close(dup_fd)
        with contextlib.suppress(OSError):
            sock.settimeout(0.0)
        with contextlib.suppress(OSError):
            sock.shutdown(socket.SHUT_RDWR)
        try:
            sock.close()
        except OSError as exc:
            self.set_status(f"Socket close failed: {exc}")
            return

        self._record_alert(
            AlertRecord(
                timestamp=time.time(),
                category="socket",
                severity="info",
                summary="Closed socket",
                details={"local": conn.laddr, "remote": conn.raddr or "[none]"},
            )
        )
        self.last_refresh = 0.0

    def toggle_packet_capture(self) -> None:
        conn = self._current_selection()
        if not conn:
            self.set_status("No connection selected")
            return
        self.packet_captures.toggle(conn, self._record_alert)

    def toggle_ghost_overlay(self) -> None:
        if not self.ghost_entries:
            self.set_status("No ghost sockets detected")
            self.show_ghost_overlay = False
            return
        if not self.show_ghost_overlay:
            self.trace_overlay = False
            self.ghost_cursor = min(self.ghost_cursor, len(self.ghost_entries) - 1)
            self.show_ghost_overlay = True
        else:
            self.show_ghost_overlay = False

    def interface_capture(self) -> None:
        conn = self._current_selection()
        if not conn:
            self.set_status("No connection selected")
            return
        iface_info = self._get_selected_interface()
        if not iface_info:
            self.set_status("No interface associated with selection")
            return
        nic, _ip = iface_info
        self.packet_captures.toggle(
            conn,
            self._record_alert,
            iface=nic,
            prefix="iface",
        )

    def dump_ghost_sockets(self) -> None:
        if not self.ghost_entries:
            self.set_status("No ghost sockets to dump")
            return
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
        path = Path.cwd() / f"ghost_sockets_{timestamp}.txt"
        try:
            with path.open("w", encoding="utf-8") as handle:
                handle.write("protocol\tlocal\tremote\tstate\n")
                for entry in self.ghost_entries:
                    handle.write(
                        f"{entry.get('protocol','')}\t{entry.get('local','')}\t{entry.get('remote','')}\t{entry.get('state','')}\n"
                    )
        except OSError as exc:
            self.set_status(f"Failed to write ghost dump: {exc}")
            return
        self.set_status(f"Ghost sockets dumped to {path}")

    def move_ghost_cursor(self, delta: int) -> None:
        if not self.ghost_entries:
            self.ghost_cursor = 0
            return
        self.ghost_cursor = max(0, min(len(self.ghost_entries) - 1, self.ghost_cursor + delta))

    def snapshot_current_ghost(self) -> None:
        entry = self._current_ghost_entry()
        if not entry:
            self.set_status("No ghost socket selected")
            return
        SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
        safe_local = entry.get("local", "unknown").replace(":", "_").replace("/", "-")
        path = SNAPSHOT_DIR / f"ghost_snapshot_{timestamp}_{safe_local}.json"
        payload = {
            "captured_at": timestamp,
            "entry": entry,
            "notes": {
                "plan": [
                    "1. Snapshot",
                    "2. Graceful shutdown",
                    "3. PF kill switch",
                    "4. Restart daemons",
                    "5. Hard kill",
                ]
            },
        }
        try:
            with path.open("w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
        except OSError as exc:
            self.set_status(f"Snapshot failed: {exc}")
            return
        self.set_status(f"Ghost snapshot saved to {path}")

    def graceful_shutdown_ghost(self) -> None:
        entry = self._current_ghost_entry()
        if not entry:
            self.set_status("No ghost socket selected")
            return
        pid = entry.get("candidate_pid") or self._identify_process_for_socket(
            entry.get("protocol", ""), entry.get("local", ""), entry.get("remote", "")
        )
        if not pid:
            self.set_status("No owning PID found for ghost socket")
            return
        try:
            proc = psutil.Process(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            self.set_status(f"Unable to inspect PID {pid}: {exc}")
            return
        try:
            proc.terminate()
        except psutil.AccessDenied:
            self.set_status(f"Permission denied terminating PID {pid}")
            return
        except psutil.Error as exc:
            self.set_status(f"Terminate failed for PID {pid}: {exc}")
            return
        _, alive = psutil.wait_procs([proc], timeout=2.0)
        if alive:
            for survivor in alive:
                try:
                    survivor.kill()
                except psutil.AccessDenied:
                    self.set_status(f"Permission denied killing PID {pid}")
                    return
                except psutil.Error as exc:
                    self.set_status(f"Kill failed for PID {pid}: {exc}")
                    return
            psutil.wait_procs(alive, timeout=2.0)
        if proc.is_running():
            self.set_status(f"PID {pid} still running after SIGKILL")
            return
        self.set_status(f"PID {pid} terminated for ghost socket")

    def firewall_block_ghost(self) -> None:
        entry = self._current_ghost_entry()
        if not entry:
            self.set_status("No ghost socket selected")
            return
        remote = entry.get("remote") or ""
        remote_tuple = self._parse_netstat_addr(remote)
        if not remote_tuple:
            self.set_status("Ghost socket has no remote peer to block")
            return
        ip, _port = remote_tuple
        cmd = ["pfctl", "-t", PF_TABLE_NAME, "-T", "add", ip]
        output = self._run_command(cmd)
        if "does not exist" in output.lower():
            pf_conf = Path.cwd() / "nethtop_pf.conf"
            try:
                pf_conf.write_text(f"table <{PF_TABLE_NAME}> persist\n", encoding="utf-8")
            except OSError:
                pass
            self._run_command(["pfctl", "-f", str(pf_conf)])
            output = self._run_command(cmd)
        if not output:
            self.set_status("pfctl returned no output; rule may require root or table setup")
            return
        self.set_status(f"pfctl response: {output.strip()[:80]}")

    def restart_network_daemons(self) -> None:
        uid = os.getuid()
        commands = [
            ["killall", "-HUP", "mDNSResponder"],
            ["killall", "-HUP", "netbiosd"],
            ["launchctl", "kickstart", "-k", f"gui/{uid}/com.docker.backend"],
        ]
        messages: List[str] = []
        for cmd in commands:
            result = self._run_command(cmd)
            if result:
                messages.append(f"{' '.join(cmd)} => ok")
            else:
                messages.append(f"{' '.join(cmd)} => check permissions")
        self.set_status("; ".join(messages)[:120])

    def hard_kill_ghost(self) -> None:
        entry = self._current_ghost_entry()
        if not entry:
            self.set_status("No ghost socket selected")
            return
        pid = entry.get("candidate_pid") or self._identify_process_for_socket(
            entry.get("protocol", ""), entry.get("local", ""), entry.get("remote", "")
        )
        if not pid:
            self.set_status("No PID to hard-kill; consider reboot")
            return
        success = self._force_close_socket(pid, entry.get("local"), entry.get("remote"))
        if success:
            self.set_status(f"Attempted hard close for PID {pid}")
        else:
            self.set_status("Hard close unsupported on this platform; consider reboot")

    def _current_ghost_entry(self) -> Optional[Dict[str, Any]]:
        if not self.ghost_entries:
            return None
        if self.ghost_cursor < 0 or self.ghost_cursor >= len(self.ghost_entries):
            return None
        return self.ghost_entries[self.ghost_cursor]

    def _force_close_socket(self, pid: int, local: str, remote: Optional[str]) -> bool:
        local_tuple = self._parse_netstat_addr(local)
        remote_tuple = self._parse_netstat_addr(remote) if remote else None
        if not local_tuple:
            return False
        try:
            proc = psutil.Process(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False
        conns = self._process_net_connections(proc)
        if not conns:
            return False
        for conn in conns:
            if self._addr_tuple(conn.laddr) != local_tuple:
                continue
            if remote_tuple and self._addr_tuple(conn.raddr) != remote_tuple:
                continue
            fd = getattr(conn, "fd", -1)
            if fd == -1:
                continue
            proc_fd_path = Path(f"/proc/{pid}/fd/{fd}")
            if not proc_fd_path.exists():
                continue
            try:
                dup_fd = os.open(proc_fd_path, os.O_RDWR)
            except OSError:
                continue
            try:
                sock = socket.fromfd(dup_fd, conn.family, conn.type)
            except OSError:
                os.close(dup_fd)
                continue
            with contextlib.suppress(OSError):
                os.close(dup_fd)
            with contextlib.suppress(OSError):
                sock.settimeout(0.0)
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(OSError):
                sock.close()
            return True
        return False

    def _find_process_connection(self, row: ConnectionRow) -> Optional[psutil._common.sconn]:
        if row.pid is None:
            return None
        try:
            proc = psutil.Process(row.pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
        except psutil.Error:  # pragma: no cover - defensive
            return None

        proc_conns = self._process_net_connections(proc)
        if not proc_conns:
            return None
        for candidate in proc_conns:
            if self._connection_matches(row, candidate):
                return candidate
        return None

    def _connection_matches(self, row: ConnectionRow, conn: psutil._common.sconn) -> bool:
        if self._addr_tuple(conn.laddr) != row.laddr_tuple:
            return False
        if self._addr_tuple(conn.raddr) != row.raddr_tuple:
            return False
        return self._protocol_name(conn) == row.protocol

    @staticmethod
    def _process_net_connections(proc: psutil.Process) -> Optional[List[psutil._common.sconn]]:
        getter = getattr(proc, "net_connections", None)
        try:
            if getter:
                return getter(kind="inet")
            return proc.connections(kind="inet")
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return None
        except psutil.Error:  # pragma: no cover - defensive
            return None

    def _get_selected_interface(self) -> Optional[Tuple[str, str]]:
        conn = self._current_selection()
        if not conn or not conn.laddr_tuple:
            return None
        ip = conn.laddr_tuple[0]
        if not ip:
            return None
        base_ip = ip.split("%", 1)[0]
        nic = self.addr_to_iface.get(base_ip)
        if nic:
            return nic, ip
        return None

    def _detect_container_anomalies(self, timestamp: float) -> List[AlertRecord]:
        docker_backends: List[int] = []
        anomalies: List[AlertRecord] = []
        try:
            for proc in psutil.process_iter(["pid", "name", "cmdline"]):
                name = proc.info.get("name") or ""
                if "docker" in name.lower():
                    if name == "com.docker.backend":
                        docker_backends.append(proc.info["pid"])
        except psutil.Error:
            return anomalies
        if len(docker_backends) > 1:
            anomalies.append(
                AlertRecord(
                    timestamp=timestamp,
                    category="container",
                    severity="warning",
                    summary="Multiple Docker backend processes detected",
                    details={"pids": docker_backends},
                )
            )
        return anomalies

    def _identify_process_for_socket(self, proto: str, local: str, remote: str) -> Optional[int]:
        local_tuple = self._parse_netstat_addr(local)
        remote_tuple = self._parse_netstat_addr(remote) if remote else None
        if not local_tuple:
            return None
        try:
            for proc in psutil.process_iter(["pid"]):
                conns = self._process_net_connections(proc)
                if not conns:
                    continue
                for conn in conns:
                    if self._addr_tuple(conn.laddr) != local_tuple:
                        continue
                    if remote_tuple and self._addr_tuple(conn.raddr) != remote_tuple:
                        continue
                    if self._protocol_name(conn) != proto:
                        continue
                    return proc.pid
        except psutil.Error:
            return None
        return None

    @staticmethod
    def _parse_netstat_addr(addr: str) -> Optional[Tuple[str, int]]:
        if not addr:
            return None
        if ":" in addr:
            # for IPv6 netstat may use '.'? but keep fallback
            try:
                host, port_str = addr.rsplit(":", 1)
                return host.strip(), int(port_str)
            except ValueError:
                pass
        if addr.count(".") >= 1:
            try:
                host, port_str = addr.rsplit(".", 1)
                return host.strip(), int(port_str)
            except ValueError:
                return None
        return None

    def _detect_ghost_sockets(self) -> List[AlertRecord]:
        timestamp = time.time()
        kernel_sockets = self._parse_netstat()
        userland_sockets = self._parse_lsof()
        ghosts = []
        for key, data in kernel_sockets.items():
            if key not in userland_sockets:
                ghosts.append((key, data))
        entries: List[Dict[str, Any]] = []
        for key, data in ghosts:
            proto, local, remote = key
            candidate_pid = self._identify_process_for_socket(proto, local, remote)
            entries.append(
                {
                    "protocol": proto,
                    "local": local,
                    "remote": remote,
                    "state": data.get("state"),
                    "detected_at": timestamp,
                    "candidate_pid": candidate_pid,
                }
            )
        self.ghost_entries = entries
        if self.ghost_cursor >= len(self.ghost_entries):
            self.ghost_cursor = max(0, len(self.ghost_entries) - 1)
        if not ghosts:
            self.show_ghost_overlay = False
        alerts: List[AlertRecord] = []
        if ghosts:
            top = ghosts[:10]
            alerts.append(
                AlertRecord(
                    timestamp=timestamp,
                    category="ghost",
                    severity="warning",
                    summary=f"{len(ghosts)} ghost sockets detected",
                    details={
                        "samples": [
                            {
                                "protocol": item[0][0],
                                "local": item[0][1],
                                "remote": item[0][2],
                                "state": item[1].get("state"),
                            }
                            for item in top
                        ]
                    },
                )
            )
        return alerts

    def _parse_netstat(self) -> Dict[Tuple[str, str, str], Dict[str, Any]]:
        result: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        output = self._run_command(["netstat", "-anv"])
        if not output:
            return result
        for line in output.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            proto = parts[0].lower()
            if not (proto.startswith("tcp") or proto.startswith("udp")):
                continue
            local = parts[3]
            remote = parts[4] if len(parts) > 4 else ""
            state = parts[5] if len(parts) > 5 else ""
            key = (proto.upper(), local, remote)
            result[key] = {"state": state}
        return result

    def _parse_lsof(self) -> Dict[Tuple[str, str, str], Dict[str, Any]]:
        result: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        try:
            output = self._run_command(["lsof", "-nP", "-iTCP", "-iUDP", "-FpnPTf"], timeout=10)
        except FileNotFoundError:
            return result
        line_pid = None
        proto = None
        local = ""
        remote = ""
        for line in output.splitlines():
            if not line:
                continue
            prefix = line[0]
            value = line[1:]
            if prefix == "p":
                line_pid = value
            elif prefix == "P":
                proto = value.upper()
            elif prefix == "n":
                if "->" in value:
                    local, remote = value.split("->", 1)
                else:
                    local = value
                    remote = ""
                key = (proto or "?", local, remote)
                result[key] = {"pid": line_pid}
        return result

    def _scan_launchd(self) -> List[AlertRecord]:
        output = self._run_command(["launchctl", "list"])
        if not output:
            return []
        pid_map: Dict[int, str] = {}
        label_counts: Dict[str, int] = defaultdict(int)
        lines = output.strip().splitlines()
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 3:
                continue
            pid_text, _status, label = parts[0], parts[1], parts[2]
            if pid_text != "-":
                try:
                    pid = int(pid_text)
                except ValueError:
                    continue
                pid_map[pid] = label
                label_counts[label] += 1
        self.pid_to_launchd = pid_map
        alerts: List[AlertRecord] = []
        multi = [label for label, count in label_counts.items() if count > 1]
        if multi:
            alerts.append(
                AlertRecord(
                    timestamp=time.time(),
                    category="launchd",
                    severity="warning",
                    summary="Launchd label claimed by multiple PIDs",
                    details={"labels": multi},
                )
            )
        return alerts

    def _run_command(self, cmd: List[str], timeout: int = 7) -> str:
        try:
            completed = subprocess.run(cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        except (subprocess.SubprocessError, OSError):
            return ""
        if completed.stdout:
            return completed.stdout
        return completed.stderr

    def poll_streams(self) -> None:
        self.poll_async()
        self.poll_trace()

    def _record_alert(self, alert: AlertRecord) -> None:
        accepted = self.alert_log.add(alert)
        if accepted:
            self.status_message = f"{alert.category.upper()}: {alert.summary}"
            self.status_timestamp = time.time()

    def export_alerts(self) -> None:
        path = self.alert_log.export()
        self.set_status(f"Alerts exported to {path}")

    def _current_selection(self) -> Optional[ConnectionRow]:
        if not self.connections:
            return None
        if self.selected_index < 0 or self.selected_index >= len(self.connections):
            return None
        return self.connections[self.selected_index]

    def move_selection(self, delta: int) -> None:
        if not self.connections:
            self.selected_index = 0
            return
        self.selected_index = max(0, min(len(self.connections) - 1, self.selected_index + delta))

    def set_status(self, message: str) -> None:
        self.status_message = message
        self.status_timestamp = time.time()

    def trace_selected_host(self) -> None:
        conn = self._current_selection()
        if not conn:
            self.set_status("No connection selected")
            return
        ip = conn.remote_ip
        if not ip:
            self.set_status("Selected row has no remote address")
            return
        if self.trace_future and not self.trace_future.done() and self.trace_target == ip:
            self.trace_overlay = True
            self.trace_scroll = 0
            self.show_ghost_overlay = False
            return
        self.trace_overlay = True
        self.show_ghost_overlay = False
        self.trace_target = ip
        self.trace_lines = [f"Tracing {ip} …"]
        self.trace_scroll = 0
        self.set_status(f"Tracing route to {ip}")
        self.trace_future = self.executor.submit(self._run_traceroute, ip)

    def poll_trace(self) -> None:
        if not self.trace_future:
            return
        if not self.trace_future.done():
            return
        try:
            result = self.trace_future.result()
        except Exception as exc:  # pragma: no cover - defensive
            result = [f"Traceroute failed: {exc}"]
        max_lines = 200
        self.trace_lines = (result or ["No traceroute output"])[:max_lines]
        self.trace_scroll = 0
        self.trace_future = None

    @staticmethod
    def _run_traceroute(ip: str) -> List[str]:
        commands = [
            ["traceroute", "-n", ip],
            ["tracepath", "-n", ip],
            ["traceroute", ip],
        ]
        for cmd in commands:
            try:
                completed = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=60,
                )
            except FileNotFoundError:
                continue
            except subprocess.SubprocessError as exc:
                return [f"Traceroute error: {exc}"]
            output = completed.stdout.strip()
            if output:
                return output.splitlines()
            error = completed.stderr.strip()
            if error:
                return error.splitlines()
        return ["Traceroute command not available on this system"]

    def _main(self, stdscr: "curses._CursesWindow") -> None:
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.timeout(200)
        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_CYAN, -1)
            curses.init_pair(2, curses.COLOR_YELLOW, -1)
            curses.init_pair(3, curses.COLOR_BLACK, curses.COLOR_CYAN)
            curses.init_pair(4, curses.COLOR_GREEN, -1)
            curses.init_pair(5, curses.COLOR_MAGENTA, -1)
        while True:
            now = time.time()
            if now - self.last_refresh >= self.interval:
                self.update_data()
                self.last_refresh = now
            self.poll_streams()
            self.render(stdscr)
            try:
                key = stdscr.getch()
            except KeyboardInterrupt:
                break
            if key == -1:
                continue
            if self.trace_overlay and self._handle_trace_overlay_key(key):
                continue
            if self.show_ghost_overlay and self._handle_ghost_overlay_key(key):
                continue
            if key in (ord("q"), ord("Q")):
                break
            if key in (curses.KEY_UP, ord("k")):
                self.move_selection(-1)
            elif key in (curses.KEY_DOWN, ord("j")):
                self.move_selection(1)
            elif key in (curses.KEY_NPAGE,):
                self.move_selection(10)
            elif key in (curses.KEY_PPAGE,):
                self.move_selection(-10)
            elif key in (ord("g"),):
                self.selected_index = 0
            elif key in (ord("G"),):
                self.selected_index = max(0, len(self.connections) - 1)
            elif key in (ord("r"), ord("R")):
                self.resolve_selected()
            elif key == ord(" "):
                self.last_refresh = 0.0
            elif key in (ord("x"), ord("X")):
                self.close_selected_connection()
            elif key in (ord("p"), ord("P")):
                self.terminate_selected_process()
            elif key in (ord("t"), ord("T")):
                self.toggle_packet_capture()
            elif key in (ord("o"), ord("O")):
                self.toggle_ghost_overlay()
            elif key in (ord("d"), ord("D")):
                self.dump_ghost_sockets()
            elif key in (ord("c"), ord("C")):
                self.interface_capture()
            elif key in (ord("z"), ord("Z")):
                self.trace_selected_host()
            elif key in (ord("e"), ord("E")):
                self.export_alerts()
            elif key in (ord("c"), ord("C")):
                self.status_message = ""
            elif key == curses.KEY_RESIZE:
                pass

    def render(self, stdscr: "curses._CursesWindow") -> None:
        stdscr.erase()
        height, width = stdscr.getmaxyx()
        header_color = curses.color_pair(1) | curses.A_BOLD if curses.has_colors() else curses.A_BOLD
        banner_height = len(BANNER_LINES)
        for idx, line in enumerate(BANNER_LINES):
            centered = line.center(width)
            self._safe_addstr(stdscr, idx, 0, centered[:width], header_color)
        header_text = f" NetHtop++ - {len(self.connections)} connections - {time.strftime('%H:%M:%S')} "
        focus_width = 0
        focus_start = width
        if width >= 60 and height >= 5:
            tentative = max(24, width // 3)
            focus_width = min(42, tentative)
            focus_start = width - focus_width
        left_width = focus_start if focus_width else width
        header_y = banner_height
        self._safe_addstr(stdscr, header_y, 0, header_text[:left_width].ljust(left_width), header_color)
        instruction = " arrows move  PgUp/PgDn jump  r resolve  x close  p kill  t capture  c iface-cap  z trace  o ghosts(S/K/F/R/H)  d dump  e export  q quit "
        instr_color = curses.color_pair(2) if curses.has_colors() else curses.A_BOLD
        instruction_y = header_y + 1
        self._safe_addstr(stdscr, instruction_y, 0, instruction[:left_width].ljust(left_width), instr_color)

        content_start = instruction_y + 1
        focus_height = 0
        if focus_width:
            focus_height = min(5, max(3, height - content_start - 1))
            if focus_height > 0:
                self._render_focus_interface(stdscr, content_start, focus_start, focus_width, focus_height)

        status_line = height - 1
        alert_lines = 3
        detail_lines = 5
        graph_lines = min(max(len(self.nic_rates), 1) + 2, max(3, height // 4))
        table_start = content_start + focus_height
        available = status_line - (table_start + detail_lines + alert_lines)
        if graph_lines > available:
            graph_lines = max(0, available)
        graph_start = max(table_start, status_line - detail_lines - alert_lines - graph_lines)
        table_height = max(0, graph_start - table_start)
        detail_start = graph_start + graph_lines
        alert_start = status_line - alert_lines

        if table_height > 1:
            self._render_table(stdscr, table_start, table_height, width)
        else:
            self._safe_addstr(stdscr, table_start, 0, "Window too small for table", curses.A_DIM)

        if graph_lines > 0:
            self._render_graphs(stdscr, graph_start, graph_lines, width)

        self._render_details(stdscr, detail_start, detail_lines, width)
        self._render_alerts(stdscr, alert_start, alert_lines, width)
        self._render_status(stdscr, status_line, width)
        stdscr.refresh()
        if self.show_ghost_overlay:
            self._render_ghost_overlay(stdscr)
        elif self.trace_overlay:
            self._render_trace_overlay(stdscr)

    def _render_table(self, stdscr: "curses._CursesWindow", start_y: int, height: int, width: int) -> None:
        proto_w = 6
        state_w = 12
        pid_w = 6
        padding = 5
        remaining = max(width - (proto_w + state_w + pid_w + padding), 10)
        addr_w = max(18, remaining // 3)
        proc_w = max(remaining - 2 * addr_w, 12)

        header = f"{'Proto':<6} {'Local Address':<{addr_w}} {'Remote Address':<{addr_w}} {'State':<{state_w}} {'PID':<{pid_w}} Process"
        header_attr = curses.color_pair(2) | curses.A_BOLD if curses.has_colors() else curses.A_BOLD
        self._safe_addstr(stdscr, start_y, 0, header[:width], header_attr)

        visible_rows = max(height - 1, 0)
        self._ensure_visible(visible_rows)
        rows = self.connections[self.scroll_offset : self.scroll_offset + visible_rows]
        for idx, row in enumerate(rows):
            row_index = self.scroll_offset + idx
            highlight = curses.color_pair(3) | curses.A_BOLD if (curses.has_colors() and row_index == self.selected_index) else (curses.A_REVERSE if row_index == self.selected_index else curses.A_NORMAL)
            proto = self._truncate(row.protocol, proto_w)
            local = self._truncate(row.laddr, addr_w)
            remote = self._truncate(row.raddr, addr_w)
            state = self._truncate(row.status, state_w)
            proc_name = self._truncate(row.proc_name, proc_w)
            line = f"{proto:<6} {local:<{addr_w}} {remote:<{addr_w}} {state:<{state_w}} {str(row.pid or '-'):>{pid_w}} {proc_name:<{proc_w}}"
            self._safe_addstr(stdscr, start_y + 1 + idx, 0, line[:width], highlight)

    def _render_focus_interface(self, stdscr: "curses._CursesWindow", y: int, x: int, width: int, height: int) -> None:
        if width <= 0 or height <= 0:
            return
        for offset in range(height):
            self._safe_addstr(stdscr, y + offset, x, " " * width)

        iface = self._get_selected_interface()
        if not iface:
            message = "[no interface]".center(width)
            self._safe_addstr(stdscr, y, x, message[:width], curses.A_DIM)
            return

        nic, ip = iface
        send_rate, recv_rate = self.nic_rates.get(nic, (0.0, 0.0))
        label_attr = curses.color_pair(4) | curses.A_BOLD if curses.has_colors() else curses.A_BOLD
        info_attr = curses.color_pair(5) if curses.has_colors() else curses.A_NORMAL
        label = self._truncate(f"{nic} {ip}", width)
        self._safe_addstr(stdscr, y, x, label.ljust(width), label_attr)

        if height >= 2:
            rates_line = f"↓ {self._format_rate(recv_rate)}  ↑ {self._format_rate(send_rate)}"
            self._safe_addstr(stdscr, y + 1, x, self._truncate(rates_line, width).ljust(width), info_attr)

        graph_width = max(1, width - 4)
        rx_history = self.nic_history_rx.get(nic)
        tx_history = self.nic_history_tx.get(nic)
        rx_graph = self._sparkline(rx_history if rx_history else [0.0], graph_width)
        tx_graph = self._sparkline(tx_history if tx_history else [0.0], graph_width)

        if height >= 3:
            self._safe_addstr(stdscr, y + 2, x, f"rx {rx_graph}"[:width].ljust(width), curses.color_pair(4) if curses.has_colors() else curses.A_NORMAL)
        if height >= 4:
            self._safe_addstr(stdscr, y + 3, x, f"tx {tx_graph}"[:width].ljust(width), curses.color_pair(2) if curses.has_colors() else curses.A_NORMAL)
        if height >= 5:
            self._safe_addstr(stdscr, y + 4, x, "Press t to toggle capture"[:width].ljust(width), curses.A_DIM)

    def _ensure_visible(self, visible_rows: int) -> None:
        if visible_rows <= 0:
            self.scroll_offset = 0
            return
        max_offset = max(0, len(self.connections) - visible_rows)
        if self.selected_index < self.scroll_offset:
            self.scroll_offset = self.selected_index
        elif self.selected_index >= self.scroll_offset + visible_rows:
            self.scroll_offset = self.selected_index - visible_rows + 1
        self.scroll_offset = max(0, min(self.scroll_offset, max_offset))

    def _render_graphs(self, stdscr: "curses._CursesWindow", start_y: int, height: int, width: int) -> None:
        labels_color = curses.color_pair(4) | curses.A_BOLD if curses.has_colors() else curses.A_BOLD
        self._safe_addstr(stdscr, start_y, 0, "Interface throughput (total)".ljust(width), labels_color)
        graph_rows = height - 1
        if graph_rows <= 0 or not self.nic_rates:
            self._safe_addstr(stdscr, start_y + 1, 0, "No interface data", curses.A_DIM)
            return
        sorted_nics = sorted(self.nic_rates.items())
        for idx, (nic, rates) in enumerate(sorted_nics[:graph_rows]):
            send_rate, recv_rate = rates
            hist = self.nic_history.get(nic, deque([0.0]))
            graph_width = max(10, width - 40)
            graph = self._sparkline(hist, graph_width)
            line = f" {nic:<10} rx {self._format_rate(recv_rate):>8}  tx {self._format_rate(send_rate):>8}  |{graph:<{graph_width}}|"
            color = curses.color_pair(5) if curses.has_colors() else curses.A_NORMAL
            self._safe_addstr(stdscr, start_y + 1 + idx, 0, line[:width], color)

    def _render_details(self, stdscr: "curses._CursesWindow", start_y: int, lines: int, width: int) -> None:
        if lines <= 0:
            return
        conn = self._current_selection()
        if not conn:
            self._safe_addstr(stdscr, start_y, 0, "No active connections", curses.A_DIM)
            return
        resolved = self.dns_cache.get(conn.remote_ip or "", "") if conn.remote_ip else ""
        iface = self._get_selected_interface()
        launchd_label = self.pid_to_launchd.get(conn.pid or -1)
        enrichment = self.enricher.data(conn.remote_ip)
        detail_lines = [
            f" Selected: {conn.protocol} {conn.laddr} -> {conn.raddr or '[none]'} [{conn.status}]",
            f" Process: PID {conn.pid or '-'} {conn.proc_name}",
            f" Command: {self._truncate(conn.cmdline, width - 10)}",
        ]
        if iface:
            nic, ip = iface
            detail_lines.insert(1, f" Interface: {nic} ({ip})")
        if launchd_label:
            detail_lines.append(f" Launchd label: {launchd_label}")
        if resolved:
            detail_lines.append(f" Resolved host: {resolved}")
        if enrichment:
            summary = ", ".join(
                f"{k}={v}" for k, v in enrichment.items() if v
            )
            if summary:
                detail_lines.append(f" Enriched: {summary}")
        for offset, text in enumerate(detail_lines[:lines]):
            self._safe_addstr(stdscr, start_y + offset, 0, text[:width])

    def _render_alerts(self, stdscr: "curses._CursesWindow", start_y: int, lines: int, width: int) -> None:
        recent = self.alert_log.recent(lines)
        if not recent:
            for i in range(lines):
                self._safe_addstr(stdscr, start_y + i, 0, "No alerts".ljust(width), curses.A_DIM)
            return
        for idx, alert in enumerate(recent[-lines:]):
            text = f"[{alert.severity.upper()}] {alert.category}: {alert.summary}"
            attr = curses.A_BOLD if alert.severity.lower() != "info" else curses.A_NORMAL
            self._safe_addstr(stdscr, start_y + idx, 0, self._truncate(text, width).ljust(width), attr)

    def _render_status(self, stdscr: "curses._CursesWindow", y: int, width: int) -> None:
        now = time.time()
        if self.status_message and now - self.status_timestamp > 6:
            self.status_message = ""
        message = self.status_message or "Press q to quit"
        attr = curses.color_pair(4) if curses.has_colors() else curses.A_BOLD
        self._safe_addstr(stdscr, y, 0, message.ljust(width), attr)

    def _render_ghost_overlay(self, stdscr: "curses._CursesWindow") -> None:
        height, width = stdscr.getmaxyx()
        overlay_h = min(max(9, len(self.ghost_entries) + 8), max(9, height - 2))
        overlay_w = min(max(50, width - 4), width - 2)
        start_y = max(0, (height - overlay_h) // 2)
        start_x = max(0, (width - overlay_w) // 2)
        win = curses.newwin(overlay_h, overlay_w, start_y, start_x)
        if curses.has_colors():
            win.bkgd(" ", curses.color_pair(3))
        try:
            win.box()
        except curses.error:
            return
        title = f" Ghost sockets ({len(self.ghost_entries)}) "
        try:
            win.addstr(0, max(1, (overlay_w - len(title)) // 2), title[: overlay_w - 2], curses.A_BOLD)
        except curses.error:
            pass
        info_line_start = 2
        if not self.ghost_entries:
            try:
                win.addstr(info_line_start, 2, "No ghost sockets detected", curses.A_DIM)
            except curses.error:
                pass
        else:
            header = "Sel Proto   Local Address                 Remote Address                State"
            try:
                win.addstr(1, 2, header[: overlay_w - 4], curses.A_UNDERLINE)
            except curses.error:
                pass
            max_rows = max(0, overlay_h - 7)
            for idx, entry in enumerate(self.ghost_entries[: max_rows]):
                pointer = ">" if idx == self.ghost_cursor else " "
                line = (
                    f"{pointer} {entry.get('protocol',''):<6} "
                    f"{self._truncate(entry.get('local',''), 24):<24}  "
                    f"{self._truncate(entry.get('remote',''), 24):<24}  "
                    f"{self._truncate(entry.get('state',''), 10):<10}"
                )
                try:
                    win.addstr(info_line_start + idx, 2, line[: overlay_w - 4])
                except curses.error:
                    break
            detail_line = info_line_start + max_rows + 1
            entry = self._current_ghost_entry()
            if entry and detail_line < overlay_h - 3:
                detected_at = entry.get("detected_at")
                detected_text = datetime.fromtimestamp(detected_at, timezone.utc).isoformat().replace("+00:00", "Z") if detected_at else "n/a"
                detail_lines = [
                    f"Detected: {detected_text}",
                    f"Owner PID: {entry.get('candidate_pid') or 'n/a'}",
                    f"Plan: S snapshot | K grace kill | F pf drop | R restart svc | H hard kill",
                ]
                for offset, text in enumerate(detail_lines):
                    if detail_line + offset >= overlay_h - 3:
                        break
                    try:
                        win.addstr(detail_line + offset, 2, self._truncate(text, overlay_w - 4))
                    except curses.error:
                        break
        footer = "↑/↓ select  S snap  K kill  F pf  R restart  H hard  o close  d dump"
        try:
            win.addstr(overlay_h - 2, 2, self._truncate(footer, overlay_w - 4), curses.A_DIM)
        except curses.error:
            pass
        win.refresh()

    def _render_trace_overlay(self, stdscr: "curses._CursesWindow") -> None:
        height, width = stdscr.getmaxyx()
        lines = self.trace_lines or ["No traceroute data"]
        overlay_h = min(max(7, len(lines) + 4), max(7, height - 2))
        overlay_w = min(max(60, width - 6), width - 2)
        start_y = max(0, (height - overlay_h) // 2)
        start_x = max(0, (width - overlay_w) // 2)
        win = curses.newwin(overlay_h, overlay_w, start_y, start_x)
        if curses.has_colors():
            win.bkgd(" ", curses.color_pair(5))
        try:
            win.box()
        except curses.error:
            return
        title_target = self.trace_target or ""
        title = f" Trace route to {title_target} " if title_target else " Trace route "
        try:
            win.addstr(0, max(1, (overlay_w - len(title)) // 2), title[: overlay_w - 2], curses.A_BOLD)
        except curses.error:
            pass
        body_start = 2
        max_rows = max(1, overlay_h - 4)
        self.trace_visible_rows = max_rows
        start_index = max(0, min(self.trace_scroll, max(0, len(lines) - max_rows)))
        for idx, line in enumerate(lines[start_index : start_index + max_rows]):
            try:
                win.addstr(body_start + idx, 2, self._truncate(line, overlay_w - 4))
            except curses.error:
                break
        footer = "z close  ↑/↓ scroll"
        try:
            win.addstr(overlay_h - 2, 2, self._truncate(footer, overlay_w - 4), curses.A_DIM)
        except curses.error:
            pass
        win.refresh()

    def _handle_ghost_overlay_key(self, key: int) -> bool:
        if not self.show_ghost_overlay:
            return False
        if key in (curses.KEY_UP, ord("k")):
            self.move_ghost_cursor(-1)
            return True
        if key in (curses.KEY_DOWN, ord("j")):
            self.move_ghost_cursor(1)
            return True
        if key in (ord("S"), ord("s")):
            self.snapshot_current_ghost()
            return True
        if key == ord("K"):
            self.graceful_shutdown_ghost()
            return True
        if key == ord("F"):
            self.firewall_block_ghost()
            return True
        if key == ord("R"):
            self.restart_network_daemons()
            return True
        if key == ord("H"):
            self.hard_kill_ghost()
            return True
        if key in (ord("o"), ord("O")):
            self.toggle_ghost_overlay()
            return True
        if key in (ord("d"), ord("D")):
            self.dump_ghost_sockets()
            return True
        return False

    def _handle_trace_overlay_key(self, key: int) -> bool:
        if not self.trace_overlay:
            return False
        if key in (ord("z"), ord("Z")):
            self.trace_overlay = False
            self.trace_scroll = 0
            return True
        if key in (curses.KEY_UP, ord("k")):
            self.trace_scroll = max(0, self.trace_scroll - 1)
            return True
        if key in (curses.KEY_DOWN, ord("j")):
            visible = self.trace_visible_rows or 1
            max_scroll = max(0, len(self.trace_lines) - visible)
            self.trace_scroll = min(max_scroll, self.trace_scroll + 1)
            return True
        return False

    def _safe_addstr(self, stdscr: "curses._CursesWindow", y: int, x: int, text: str, attr: int = curses.A_NORMAL) -> None:
        height, width = stdscr.getmaxyx()
        if y < 0 or y >= height or x >= width:
            return
        if x < 0:
            text = text[-x:]
            x = 0
        if not text:
            return
        trimmed = text[: max(0, width - x)]
        try:
            stdscr.addstr(y, x, trimmed, attr)
        except curses.error:
            pass

    @staticmethod
    def _format_rate(rate: float) -> str:
        units = ["B/s", "KB/s", "MB/s", "GB/s"]
        value = rate
        idx = 0
        while value >= 1024 and idx < len(units) - 1:
            value /= 1024.0
            idx += 1
        return f"{value:5.1f} {units[idx]}"

    @staticmethod
    def _sparkline(history: Sequence[float], width: int) -> str:
        if width <= 0 or not history:
            return ""
        values = list(history)[-width:]
        max_val = max(values) if values else 0.0
        if max_val <= 0:
            return " " * width
        scale = (len(GRAPH_CHARS) - 1) / max_val
        chars = []
        for val in values:
            idx = int(round(val * scale))
            idx = max(0, min(idx, len(GRAPH_CHARS) - 1))
            chars.append(GRAPH_CHARS[idx])
        if len(chars) < width:
            chars = [" "] * (width - len(chars)) + chars
        return "".join(chars[-width:])

    @staticmethod
    def _truncate(text: str, width: int) -> str:
        if width <= 0:
            return ""
        if len(text) <= width:
            return text
        if width <= 3:
            return text[:width]
        return text[: width - 3] + "..."


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Interactive network monitor with ghost response playbooks"
    )
    parser.add_argument("--interval", type=float, default=1.0, help="Refresh interval in seconds (default: 1.0)")
    parser.add_argument(
        "--kind",
        default="inet",
        choices=["inet", "inet4", "inet6", "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6"],
        help="Connection kind (psutil net_connections kind)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    app = NetTopPlusPlusApp(interval=args.interval, kind=args.kind)
    app.run()


if __name__ == "__main__":
    main()
