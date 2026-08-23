"""
devices/smartplug_sim.py
========================
Simulates a WiFi smart plug with REST-like authentication.
"""

import json
from .device_base import BaseDevice


class SmartPlugDevice(BaseDevice):
    """
    REST-like smart plug simulator.
    Protocol: JSON body {"username": ..., "password": ...}\n, response JSON.
    """
    def __init__(self, device_id, host, port, hardened, valid_credentials=None):
        if not valid_credentials:
            valid_credentials = [
                {"username": "admin", "password": "password"},
            ]
        banner = (
            b'POST /api/login HTTP/1.1\r\n'
            b'Content-Type: application/json\r\n'
            b'X-Device: SmartPlug-WiFi/2.0\r\n'
            b'\r\n'
        )
        super().__init__(
            device_id=device_id,
            device_type="smartplug",
            host=host,
            port=port,
            valid_credentials=valid_credentials,
            hardened=hardened,
            lockout_threshold=5,
            lockout_window_seconds=60,
            rate_limit_delay=0.3,
            banner=banner,
        )

    def handle_connection(self, conn, addr):
        ip = addr[0]
        conn.settimeout(10.0)
        try:
            data = b""
            while b"\n" not in data:
                chunk = conn.recv(1)
                if not chunk:
                    return
                data += chunk

            line = data.decode(errors="ignore").strip()
            try:
                payload = json.loads(line)
                username = payload.get("username", "")
                password = payload.get("password", "")
            except json.JSONDecodeError:
                conn.sendall(b'{"status": "error", "message": "Invalid JSON"}\n')
                return

            if self.is_rate_limited(ip):
                conn.sendall(b'{"status": "rate_limited", "message": "Too many requests"}\n')
                self._log_attempt(ip, username, password, "rate_limited")
                return

            self.rate_limit_sleep()

            if self.is_locked_out(ip):
                conn.sendall(b'{"status": "locked_out", "message": "Account locked"}\n')
                self._log_attempt(ip, username, password, "locked_out")
                return

            if self.validate_credentials(username, password):
                conn.sendall(b'{"status": "ok", "message": "Access granted", "token": "sess_abc123"}\n')
                self._log_attempt(ip, username, password, "success")
            else:
                self.record_failure(ip)
                conn.sendall(b'{"status": "auth_fail", "message": "Invalid credentials"}\n')
                self._log_attempt(ip, username, password, "fail")
        except Exception:
            pass
