"""
devices/router_sim.py
=====================
Simulates a 6LoWPAN border router with Telnet-like authentication.
"""

from .device_base import BaseDevice


class RouterDevice(BaseDevice):
    """
    Telnet-like router simulator.
    Protocol: Banner + 'Username: ' prompt, client sends user, 'Password: ' prompt, client sends pass.
    """
    def __init__(self, device_id, host, port, hardened, valid_credentials=None):
        if not valid_credentials:
            valid_credentials = [
                {"username": "root", "password": "root"},
            ]
        banner = (
            b"\r\nContiki-NG 6LoWPAN Border Router\r\n"
            b"Firmware: v4.9.0 (RPL/CoAP enabled)\r\n"
            b"\r\n"
            b"Username: "
        )
        super().__init__(
            device_id=device_id,
            device_type="router",
            host=host,
            port=port,
            valid_credentials=valid_credentials,
            hardened=hardened,
            lockout_threshold=5,
            lockout_window_seconds=60,
            rate_limit_delay=0.5,
            banner=banner,
        )

    def handle_connection(self, conn, addr):
        ip = addr[0]
        conn.settimeout(10.0)
        try:
            username = b""
            while b"\n" not in username:
                ch = conn.recv(1)
                if not ch:
                    return
                username += ch
            username = username.decode(errors="ignore").strip()

            conn.sendall(b"Password: ")

            password = b""
            while b"\n" not in password:
                ch = conn.recv(1)
                if not ch:
                    return
                password += ch
            password = password.decode(errors="ignore").strip()

            if self.is_rate_limited(ip):
                conn.sendall(b"\r\nRate limited: too many attempts.\r\n")
                self._log_attempt(ip, username, password, "rate_limited")
                return

            self.rate_limit_sleep()

            if self.is_locked_out(ip):
                conn.sendall(b"\r\nAccount locked: too many failures.\r\n")
                self._log_attempt(ip, username, password, "locked_out")
                return

            if self.validate_credentials(username, password):
                conn.sendall(b"\r\nLogin successful. Welcome to router admin shell.\r\n# ")
                self._log_attempt(ip, username, password, "success")
            else:
                self.record_failure(ip)
                conn.sendall(b"\r\nLogin failed. Access denied.\r\n")
                self._log_attempt(ip, username, password, "fail")
        except Exception:
            pass
