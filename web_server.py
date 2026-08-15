"""
web_server.py
=============
SENTRYMESH — IoT Default Credential Scanner Web Interface
Zero-dependency Python HTTP server (stdlib only).

API Endpoints:
  GET  /                    -> Serves index.html (SENTRYMESH dashboard)
  GET  /api/status          -> Returns network status and all 8 device states
  POST /api/toggle          -> Start/stop the virtual IoT device network
  POST /api/scan            -> Run credential scan (streams via SSE)
  GET  /api/stream          -> Server-Sent Events — live scan log feed
  GET  /api/results         -> Latest scan_results.json
  GET  /api/results/history -> List of all past scan files with labels
  POST /api/change-password -> Change a device's valid credential
  GET  /api/report/html     -> Generate and return path to static HTML report
  GET  /api/report/download -> Download the static HTML report file
  GET  /api/rawlog          -> Download raw_scan.log evidence file
"""

import os
import sys
import json
import socket
import logging
import threading
import time
import glob
import shutil
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse
from queue import Queue, Empty

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from network.launch_network import launch_all, shutdown_all
from scanner.cred_list import load_credentials
from scanner.scanner_core import CredentialScanner, ScanTarget
from scanner.risk_report import generate_full_report_data

# ─── Global State ─────────────────────────────────────────────────────────────

RUNNING_DEVICES = []
DEVICES_LOCK = threading.Lock()

# SSE message queues — each client gets its own Queue
SSE_CLIENTS: list = []
SSE_CLIENTS_LOCK = threading.Lock()

# Scan state
SCAN_RUNNING = False
SCAN_LOCK = threading.Lock()

NETWORK_CONFIG = []  # Loaded from network_config.json

# Logging config
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("sentrymesh-server")


def _load_network_config():
    """Load device configuration from network_config.json."""
    global NETWORK_CONFIG
    config_path = os.path.join(PROJECT_ROOT, "network", "network_config.json")
    try:
        with open(config_path) as f:
            NETWORK_CONFIG = json.load(f)
    except Exception as e:
        logger.error(f"Failed to load network_config.json: {e}")
        NETWORK_CONFIG = []


def _broadcast_sse(message: str):
    """Push a message to all connected SSE clients."""
    with SSE_CLIENTS_LOCK:
        dead = []
        for q in SSE_CLIENTS:
            try:
                q.put_nowait(message)
            except Exception:
                dead.append(q)
        for q in dead:
            SSE_CLIENTS.remove(q)


def _add_scan_log(message: str):
    """Streaming callback for the scanner — broadcasts to all SSE clients."""
    _broadcast_sse(message)


# ─── HTTP Handler ─────────────────────────────────────────────────────────────

class SentryMeshHandler(BaseHTTPRequestHandler):
    """HTTP request handler for SENTRYMESH dashboard and REST API."""

    def log_message(self, format, *args):
        # Suppress noisy access logs; errors still go through
        pass

    def _cors_headers(self, content_type="application/json", status=200):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_OPTIONS(self):
        self._cors_headers(status=200)

    def do_GET(self):
        url = urlparse(self.path)
        path = url.path

        # Dashboard
        if path in ("/", "/index.html"):
            self._serve_file("report/templates/index.html", "text/html")
            return

        # Static assets
        if path.startswith("/static/"):
            rel = path.lstrip("/")
            full = os.path.join(PROJECT_ROOT, rel)
            if os.path.isfile(full):
                ext = os.path.splitext(full)[1]
                mime = {".css": "text/css", ".js": "application/javascript",
                        ".png": "image/png", ".svg": "image/svg+xml"}.get(ext, "application/octet-stream")
                self._serve_file(rel, mime)
            else:
                self._error(404, "File not found")
            return

        routes = {
            "/api/status":          self._handle_status,
            "/api/results":         self._handle_results,
            "/api/results/history": self._handle_history,
            "/api/stream":          self._handle_sse_stream,
            "/api/report/view":     self._handle_report_view,
            "/api/report/download": self._handle_report_download,
            "/api/rawlog":          self._handle_rawlog_download,
        }
        handler = routes.get(path)
        if handler:
            handler()
        elif path == "/api/report/html":
            self._handle_generate_report()
        else:
            self._error(404, "Endpoint not found")

    def do_POST(self):
        url = urlparse(self.path)
        path = url.path

        content_length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(content_length) if content_length > 0 else b""
        body = {}
        if raw:
            try:
                body = json.loads(raw.decode("utf-8"))
            except Exception:
                pass

        routes = {
            "/api/toggle":          lambda: self._handle_toggle(body),
            "/api/scan":            lambda: self._handle_scan(body),
            "/api/change-password": lambda: self._handle_change_password(body),
        }
        handler = routes.get(path)
        if handler:
            handler()
        else:
            self._error(404, "Endpoint not found")

    # ─── Static File Serving ──────────────────────────────────────────────────

    def _serve_file(self, relative_path, content_type):
        full = os.path.join(PROJECT_ROOT, relative_path)
        try:
            with open(full, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self._error(500, f"Error reading file: {e}")

    def _send_json(self, data, status=200):
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(payload)

    def _error(self, code, message):
        self._send_json({"error": message}, status=code)

    # ─── GET /api/status ─────────────────────────────────────────────────────

    def _handle_status(self):
        global RUNNING_DEVICES, NETWORK_CONFIG
        with DEVICES_LOCK:
            running_map = {dev.device_id: dev.running for dev in RUNNING_DEVICES if getattr(dev, "running", False)}
            is_running = len(running_map) > 0

        devices_info = []
        for dev_cfg in NETWORK_CONFIG:
            port = dev_cfg["port"]
            dev_id = dev_cfg["device_id"]
            port_active = running_map.get(dev_id, False)

            devices_info.append({
                "device_id":    dev_id,
                "display_name": dev_cfg.get("display_name", dev_id),
                "device_type":  dev_cfg["device_type"],
                "type_label":   dev_cfg.get("type_label", dev_cfg["device_type"]),
                "port":         port,
                "hardened":     dev_cfg.get("hardened", False),
                "simulated_ip": dev_cfg.get("simulated_ip", ""),
                "service":      dev_cfg.get("service", "CoAP/5683"),
                "description":  dev_cfg.get("description", ""),
                "online":       port_active,
            })

        with SCAN_LOCK:
            scan_running = SCAN_RUNNING

        self._send_json({
            "network_running": is_running,
            "scan_running":    scan_running,
            "interface":       "tun0 (simulated)",
            "border_router":   "fd00::1 (Contiki-NG RPL root)" if is_running else "not connected",
            "devices":         devices_info,
        })

    # ─── POST /api/toggle ────────────────────────────────────────────────────

    def _handle_toggle(self, body):
        global RUNNING_DEVICES
        action = body.get("action", "toggle")

        with DEVICES_LOCK:
            currently_running = len(RUNNING_DEVICES) > 0

            if action == "start":
                should_start = True
            elif action == "stop":
                should_start = False
            else:
                should_start = not currently_running

            if should_start:
                if RUNNING_DEVICES:
                    shutdown_all(RUNNING_DEVICES)
                    RUNNING_DEVICES = []
                _broadcast_sse("[*] Initializing SENTRYMESH virtual IoT network...")
                RUNNING_DEVICES = launch_all()
                msg = f"Launched {len(RUNNING_DEVICES)} virtual IoT devices"
                _broadcast_sse(f"[✓] {msg}")
            else:
                if RUNNING_DEVICES:
                    _broadcast_sse("[*] Stopping all virtual IoT devices...")
                    shutdown_all(RUNNING_DEVICES)
                    RUNNING_DEVICES = []
                    msg = "All virtual IoT devices stopped"
                    _broadcast_sse(f"[✓] {msg}")
                else:
                    msg = "Network already offline"

        self._send_json({
            "success": True,
            "message": msg,
            "network_running": len(RUNNING_DEVICES) > 0,
        })

    # ─── POST /api/scan ───────────────────────────────────────────────────────

    def _handle_scan(self, body):
        global RUNNING_DEVICES, SCAN_RUNNING

        with DEVICES_LOCK:
            network_active = len(RUNNING_DEVICES) > 0

        if not network_active:
            self._error(400, "Network is offline. Start the network first.")
            return

        with SCAN_LOCK:
            if SCAN_RUNNING:
                self._error(409, "A scan is already running.")
                return
            SCAN_RUNNING = True

        max_attempts = body.get("max_attempts", None)
        hardened_only = body.get("hardened_only", False)
        run_label = body.get("run_label", "Scan")

        _broadcast_sse(f"🚀 SENTRYMESH Security Audit: '{run_label}'")
        _broadcast_sse(f"[*] Config: max_attempts={max_attempts}, hardened_only={hardened_only}")

        creds_file   = os.path.join(PROJECT_ROOT, "data", "iot_default_creds.txt")
        results_file = os.path.join(PROJECT_ROOT, "logs", "scan_results.json")
        raw_log_file = os.path.join(PROJECT_ROOT, "logs", "raw_scan.log")
        os.makedirs(os.path.join(PROJECT_ROOT, "logs"), exist_ok=True)

        try:
            credentials = load_credentials(creds_file)
            _broadcast_sse(f"[*] Loaded {len(credentials)} credential pairs from iot_default_creds.txt")

            protocol_map = {
                "camera":    "HTTP-like",
                "router":    "Telnet-like",
                "sensor":    "JSON-TCP",
                "smartplug": "REST-like",
            }

            targets = []
            for dev_cfg in NETWORK_CONFIG:
                if hardened_only and not dev_cfg.get("hardened", False):
                    continue
                targets.append(ScanTarget(
                    device_id=dev_cfg["device_id"],
                    device_type=dev_cfg["device_type"],
                    protocol=protocol_map.get(dev_cfg["device_type"], "Unknown"),
                    host="127.0.0.1",
                    port=dev_cfg["port"],
                    hardened=dev_cfg.get("hardened", False),
                    simulated_ip=dev_cfg.get("simulated_ip", ""),
                ))

            _broadcast_sse(f"[*] Targeting {len(targets)} device(s) across tun0 interface")
            _broadcast_sse("─" * 60)

            scanner = CredentialScanner(
                targets=targets,
                credentials=credentials,
                max_workers=4,
                timeout=3.0,
                max_attempts_per_device=max_attempts,
                backoff_base=1.5,
            )

            results = scanner.scan_all(
                streaming_callback=_broadcast_sse,
                raw_log_path=raw_log_file,
            )
            report_data = generate_full_report_data(results)
            scanner.save_results(
                results,
                results_file,
                run_label=run_label,
                network_config=NETWORK_CONFIG,
            )

            # Archive timestamped copy for before/after history
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            archive_path = os.path.join(PROJECT_ROOT, "logs", f"scan_{ts}.json")
            shutil.copy2(results_file, archive_path)

            cracked = report_data["summary"]["cracked"]
            total   = len(results)
            _broadcast_sse("─" * 60)
            _broadcast_sse(f"[✓] Audit complete — {cracked}/{total} devices compromised")

            # Generate static report
            try:
                from report.generate_report import generate_html_report
                report_html = os.path.join(PROJECT_ROOT, "report", "iot_scan_report.html")
                generate_html_report(report_data, report_html)
            except Exception as re:
                logger.warning(f"Static report generation failed: {re}")

            self._send_json(report_data)

        except Exception as e:
            _broadcast_sse(f"[✗] Error: {e}")
            logger.error(f"Scan error: {e}", exc_info=True)
            self._error(500, f"Scan failed: {e}")
        finally:
            with SCAN_LOCK:
                SCAN_RUNNING = False

    # ─── GET /api/stream (SSE) ────────────────────────────────────────────────

    def _handle_sse_stream(self):
        """Server-Sent Events endpoint for real-time scan log streaming."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        # Register this client
        q: Queue = Queue()
        with SSE_CLIENTS_LOCK:
            SSE_CLIENTS.append(q)

        try:
            self.wfile.write(b"data: [SENTRYMESH] Live stream connected\\n\\n")
            self.wfile.flush()

            while True:
                try:
                    msg = q.get(timeout=15)
                    # SSE format: data: <message>\n\n
                    line = f"data: {msg}\\n\\n".encode("utf-8")
                    self.wfile.write(line)
                    self.wfile.flush()
                except Empty:
                    # Send heartbeat comment to keep connection alive
                    self.wfile.write(b": heartbeat\\n\\n")
                    self.wfile.flush()
        except Exception:
            pass
        finally:
            with SSE_CLIENTS_LOCK:
                if q in SSE_CLIENTS:
                    SSE_CLIENTS.remove(q)

    # ─── GET /api/results ─────────────────────────────────────────────────────

    def _handle_results(self):
        results_file = os.path.join(PROJECT_ROOT, "logs", "scan_results.json")
        if os.path.exists(results_file):
            try:
                with open(results_file) as f:
                    data = json.load(f)
                self._send_json(data)
                return
            except Exception as e:
                self._error(500, f"Error reading results: {e}")
                return
        self._send_json({"devices": [], "summary": {}, "run_label": ""})

    # ─── GET /api/results/history ─────────────────────────────────────────────

    def _handle_history(self):
        """Return list of archived scan files with their run_label and timestamp."""
        logs_dir = os.path.join(PROJECT_ROOT, "logs")
        pattern  = os.path.join(logs_dir, "scan_*.json")
        files    = sorted(glob.glob(pattern), reverse=True)

        history = []
        for f in files[:20]:  # Last 20 scans
            try:
                with open(f) as fh:
                    data = json.load(fh)
                history.append({
                    "filename":    os.path.basename(f),
                    "filepath":    f,
                    "run_label":   data.get("run_label", "Scan"),
                    "timestamp":   data.get("timestamp", ""),
                    "scan_id":     data.get("scan_id", ""),
                    "total":       data.get("summary", {}).get("total_devices", 0),
                    "cracked":     data.get("summary", {}).get("cracked", 0),
                    "vuln_rate":   data.get("summary", {}).get("vulnerability_rate", 0),
                })
            except Exception:
                pass

        self._send_json({"history": history})

    # ─── POST /api/change-password ────────────────────────────────────────────

    def _handle_change_password(self, body):
        global RUNNING_DEVICES
        device_id = body.get("device_id", "")
        new_password = body.get("new_password", "")

        if not device_id or not new_password:
            self._error(400, "device_id and new_password are required")
            return

        with DEVICES_LOCK:
            target_device = None
            for dev in RUNNING_DEVICES:
                if dev.device_id == device_id:
                    target_device = dev
                    break

        if not target_device:
            self._error(404, f"Device '{device_id}' not found or not running")
            return

        # Update valid credentials on the running device
        old_creds = list(target_device.valid_credentials)
        new_creds = [{"username": c["username"], "password": new_password}
                     for c in old_creds]
        target_device.valid_credentials = new_creds

        _broadcast_sse(f"[✓] Password changed on {device_id} → new credential active")
        self._send_json({
            "success": True,
            "message": f"Password updated for {device_id}",
            "device_id": device_id,
        })

    # ─── GET /api/report/html ─────────────────────────────────────────────────

    def _handle_generate_report(self):
        results_file = os.path.join(PROJECT_ROOT, "logs", "scan_results.json")
        if not os.path.exists(results_file):
            self._error(404, "No scan results found. Run a scan first.")
            return
        try:
            from report.generate_report import generate_html_report
            from scanner.risk_report import generate_full_report_data
            from scanner.scanner_core import load_results

            results = load_results(results_file)
            report_data = generate_full_report_data(results)
            report_html = os.path.join(PROJECT_ROOT, "report", "iot_scan_report.html")
            generate_html_report(report_data, report_html)
            self._send_json({
                "success": True,
                "report_path": report_html,
                "download_url": "/api/report/download",
            })
        except Exception as e:
            self._error(500, f"Report generation failed: {e}")

    # ─── GET /api/report/view ─────────────────────────────────────────────────

    def _handle_report_view(self):
        report_path = os.path.join(PROJECT_ROOT, "report", "iot_scan_report.html")
        if not os.path.exists(report_path):
            self._error(404, "Report not yet generated.")
            return
        with open(report_path, "rb") as f:
            content = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    # ─── GET /api/report/download ─────────────────────────────────────────────

    def _handle_report_download(self):
        report_path = os.path.join(PROJECT_ROOT, "report", "iot_scan_report.html")
        if not os.path.exists(report_path):
            self._error(404, "Report not yet generated.")
            return
        with open(report_path, "rb") as f:
            content = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Disposition",
                         "attachment; filename=sentrymesh_report.html")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    # ─── GET /api/rawlog ──────────────────────────────────────────────────────

    def _handle_rawlog_download(self):
        log_path = os.path.join(PROJECT_ROOT, "logs", "raw_scan.log")
        if not os.path.exists(log_path):
            self._error(404, "No raw scan log found. Run a scan first.")
            return
        with open(log_path, "rb") as f:
            content = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Disposition",
                         "attachment; filename=raw_scan.log")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


# ─── Server Runner ────────────────────────────────────────────────────────────

from socketserver import ThreadingMixIn


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def run_server(port=5000):
    _load_network_config()
    httpd = None
    for try_port in [port, port + 1, port + 2, 5050, 8080]:
        try:
            server_address = ("", try_port)
            httpd = ThreadedHTTPServer(server_address, SentryMeshHandler)
            port = try_port
            break
        except OSError:
            logger.warning(f"Port {try_port} in use, trying next port...")

    if not httpd:
        logger.error("Could not bind to any available port.")
        sys.exit(1)

    logger.info(f"SENTRYMESH dashboard available at: http://localhost:{port}")

    try:
        import webbrowser
        webbrowser.open(f"http://localhost:{port}")
    except Exception:
        pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Stopping SENTRYMESH server...")
        with DEVICES_LOCK:
            if RUNNING_DEVICES:
                shutdown_all(RUNNING_DEVICES)
        httpd.server_close()
        logger.info("Server stopped.")


if __name__ == "__main__":
    port = 5000
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    run_server(port)
