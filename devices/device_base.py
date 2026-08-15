import socket
import threading
import time
from datetime import datetime

class BaseDevice:
    """
    Base TCP server class for IoT device simulation.
    Handles connections, rate limiting, and lockouts (for hardened devices).
    """
    def __init__(self, device_id, device_type, host, port, valid_credentials,
                 hardened=False, lockout_threshold=5, lockout_window_seconds=60,
                 rate_limit_delay=0.5, banner=""):
        self.device_id = device_id
        self.device_type = device_type
        self.host = host
        self.port = port
        self.valid_credentials = valid_credentials
        self.hardened = hardened
        self.lockout_threshold = lockout_threshold
        self.lockout_window_seconds = lockout_window_seconds
        self.rate_limit_delay = rate_limit_delay
        self.banner = banner
        
        self.attempt_log = []
        self.log_lock = threading.Lock()
        
        # Track failed attempts per IP for lockout mechanism
        # ip: [timestamp1, timestamp2, ...]
        self.failed_attempts = {}
        self.lock_lock = threading.Lock()
        
        # Track last request timestamp per IP for rate limiting
        self.last_request = {}
        self.rate_lock = threading.Lock()
        
        self.server_socket = None
        self.running = False

    def start(self):
        """Starts the server thread as a daemon."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.running = True
        
        server_thread = threading.Thread(target=self._accept_connections)
        server_thread.daemon = True
        server_thread.start()

    def _accept_connections(self):
        """Accepts incoming TCP connections."""
        while self.running:
            try:
                self.server_socket.settimeout(1.0)
                conn, addr = self.server_socket.accept()
                client_thread = threading.Thread(target=self._handle_client, args=(conn, addr))
                client_thread.daemon = True
                client_thread.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"Error accepting connection on {self.device_id}: {e}")

    def stop(self):
        """Stops the server and closes the socket."""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass

    def get_attempt_log(self):
        """Returns a copy of the attempt log in a thread-safe manner."""
        with self.log_lock:
            return list(self.attempt_log)
            
    def _log_attempt(self, ip, username, password, result):
        """Thread-safe logging of authentication attempts."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "ip": ip,
            "username": username,
            "password": password,
            "result": result,
            "device_id": self.device_id
        }
        with self.log_lock:
            self.attempt_log.append(entry)

    def is_locked_out(self, ip):
        """Checks if an IP is currently locked out."""
        if not self.hardened:
            return False
            
        now = time.time()
        with self.lock_lock:
            if ip in self.failed_attempts:
                # Remove timestamps older than the window
                self.failed_attempts[ip] = [ts for ts in self.failed_attempts[ip] 
                                            if now - ts <= self.lockout_window_seconds]
                if len(self.failed_attempts[ip]) >= self.lockout_threshold:
                    return True
        return False

    def record_failure(self, ip):
        """Records a failed authentication attempt for an IP."""
        if not self.hardened:
            return
            
        now = time.time()
        with self.lock_lock:
            if ip not in self.failed_attempts:
                self.failed_attempts[ip] = []
            self.failed_attempts[ip].append(now)

    def rate_limit_sleep(self):
        """Applies a sleep delay if device is hardened (simulates rate limit)."""
        if self.hardened:
            time.sleep(self.rate_limit_delay)
            
    def is_rate_limited(self, ip):
        """Checks if request is coming too fast from the same IP."""
        if not self.hardened:
            return False
            
        now = time.time()
        with self.rate_lock:
            last = self.last_request.get(ip, 0)
            if now - last < self.rate_limit_delay:
                self.last_request[ip] = now
                return True
            self.last_request[ip] = now
        return False

    def validate_credentials(self, username, password):
        """Validates if the provided credentials match any valid ones."""
        for cred in self.valid_credentials:
            if cred.get("username") == username and cred.get("password") == password:
                return True
        return False

    def _handle_client(self, conn, addr):
        """Wrapper to send banner and call subclass handler."""
        ip = addr[0]
        try:
            conn.settimeout(5.0)
            if self.banner:
                if isinstance(self.banner, str):
                    conn.sendall(self.banner.encode())
                else:
                    conn.sendall(self.banner)
            self.handle_connection(conn, addr)
        except Exception as e:
            # Silently handle disconnected clients or errors
            pass
        finally:
            try:
                conn.close()
            except:
                pass

    def handle_connection(self, conn, addr):
        """
        To be overridden by subclasses. Implements the specific protocol auth flow.
        """
        pass
