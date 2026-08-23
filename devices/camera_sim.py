"""
devices/camera_sim.py
=====================
Simulates an IP camera with HTTP-like authentication.
Default credentials provided via valid_credentials param or network_config.json.
"""

from .device_base import BaseDevice


class CameraDevice(BaseDevice):
    """
    HTTP-like IP camera simulator.
    Protocol: Send AUTH <user> <pass>\r\n, receive response line.
    """
    def __init__(self, device_id, host, port, hardened, valid_credentials=None):
        if not valid_credentials:
            valid_credentials = [
                {"username": "admin", "password": "admin"},
            ]
        banner = (
            b"HTTP/1.1 401 Unauthorized\r\n"
            b"WWW-Authenticate: Basic realm=\"IPCam-2000 HD\"\r\n"
            b"Server: IPCam/1.0 (RTSP/2.0)\r\n"
            b"\r\n"
        )
        super().__init__(
            device_id=device_id,
            device_type="camera",
            host=host,
            port=port,
            valid_credentials=valid_credentials,
            hardened=hardened,
            lockout_threshold=5,
            lockout_window_seconds=60,
            rate_limit_delay=0.4,
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
            parts = line.split(" ", 2)
            if len(parts) < 3 or parts[0].upper() != "AUTH":
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                return
            username, password = parts[1], parts[2]

            if self.is_rate_limited(ip):
                conn.sendall(b"HTTP/1.1 429 Too Many Requests\r\n\r\n")
                self._log_attempt(ip, username, password, "rate_limited")
                return

            self.rate_limit_sleep()

            if self.is_locked_out(ip):
                conn.sendall(b"HTTP/1.1 403 Account Locked\r\n\r\n")
                self._log_attempt(ip, username, password, "locked_out")
                return

            if self.validate_credentials(username, password):
                conn.sendall(b"HTTP/1.1 200 OK\r\nLogin Successful\r\n\r\n")
                self._log_attempt(ip, username, password, "success")
            else:
                self.record_failure(ip)
                conn.sendall(b"HTTP/1.1 401 Unauthorized\r\n\r\n")
                self._log_attempt(ip, username, password, "fail")
        except Exception:
            pass
