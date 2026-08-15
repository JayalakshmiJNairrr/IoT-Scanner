"""
scanner/scanner_core.py
=======================
Multi-threaded IoT credential scanner with bypass detection.

This module implements the core scanning engine that:
  1. Connects to each simulated IoT device
  2. Reads its banner to fingerprint the protocol
  3. Systematically tries credential pairs from the list
  4. Detects lockout and rate-limiting responses (hardening indicators)
  5. Attempts limited bypass via timed retry (models real attacker behavior)
  6. Records rich per-attempt telemetry for downstream analysis

Educational context: This replicates the scan phase used by botnets like Mirai.
Understanding how it works is essential to understanding why hardening matters.
All connections are 127.0.0.1 only — no external network access.
"""

import json
import logging
import socket
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

from scanner.cred_list import CredentialEntry

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Data Classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ScanTarget:
    """Represents a single IoT device to be scanned."""
    device_id: str
    device_type: str      # "camera", "router", "sensor", "smartplug"
    protocol: str         # "HTTP-like", "Telnet-like", "JSON-TCP", "REST-like"
    host: str
    port: int
    hardened: bool
    simulated_ip: str = ""  # IPv6 address for display (e.g. fd00::201)


@dataclass
class AttemptResult:
    """Result of a single credential attempt against a device."""
    username: str
    password: str
    result: str           # "AUTH_OK" | "AUTH_FAIL" | "LOCKED_OUT" | "RATE_LIMITED" | "ERROR"
    latency_ms: float
    timestamp: str        # ISO 8601


@dataclass
class DeviceResult:
    """Aggregated scan result for one device."""
    target: ScanTarget
    banner: str
    cracked: bool
    cracked_credential: Optional[Dict[str, str]]
    attempts: int
    time_to_crack_seconds: Optional[float]
    cred_rank: Optional[int]
    lockout_detected: bool
    rate_limit_detected: bool
    bypass_attempts: int
    all_attempts: List[AttemptResult] = field(default_factory=list)
    # These are filled in by risk_report.py after scanning:
    risk_score: int = 0
    risk_level: str = "UNKNOWN"
    hardening_recommendations: List[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Response Classification Helpers
# ─────────────────────────────────────────────────────────────────────────────

_AUTH_OK_MARKERS = [
    "auth_ok", "200 ok", "login successful", "access_granted", '"ok"', 'status": "ok'
]
_LOCKED_MARKERS = [
    "locked_out", "403", "account locked", '"locked"', 'status": "locked'
]
_RATE_LIMITED_MARKERS = [
    "rate_limited", "429", "too many", '"rate_limited"', 'status": "rate_limited'
]


def _classify_response(response: str) -> str:
    """
    Map a raw device response string to a standardized result code.

    Args:
        response: Raw string received from the device socket.

    Returns:
        One of: "AUTH_OK", "LOCKED_OUT", "RATE_LIMITED", "AUTH_FAIL"
    """
    resp_lower = response.lower()

    # Check in priority order: OK first, then blocking states, then fail
    if any(marker in resp_lower for marker in _AUTH_OK_MARKERS):
        return "AUTH_OK"
    if any(marker in resp_lower for marker in _LOCKED_MARKERS):
        return "LOCKED_OUT"
    if any(marker in resp_lower for marker in _RATE_LIMITED_MARKERS):
        return "RATE_LIMITED"
    return "AUTH_FAIL"


# ─────────────────────────────────────────────────────────────────────────────
# Protocol-specific Send/Receive Methods
# ─────────────────────────────────────────────────────────────────────────────

def _recv_until(sock: socket.socket, timeout: float = 5.0, max_bytes: int = 4096) -> str:
    """Receive data from socket until quiet or timeout."""
    sock.settimeout(timeout)
    chunks = []
    try:
        while True:
            chunk = sock.recv(1024)
            if not chunk:
                break
            chunks.append(chunk)
            # Stop if we see a prompt or end-of-response indicator
            combined = b"".join(chunks)
            if (combined.endswith(b"\n") or combined.endswith(b"\r\n")
                    or b"Username:" in combined or b"Password:" in combined
                    or b"Send:" in combined or b"AUTH" in combined
                    or len(combined) >= max_bytes):
                break
    except socket.timeout:
        pass
    return b"".join(chunks).decode("utf-8", errors="replace")


def _try_camera(sock: socket.socket, username: str, password: str,
                timeout: float) -> tuple[str, str]:
    """
    HTTP-like camera protocol.
    Send: AUTH <username> <password>\\r\\n
    Receive: response line
    Returns: (banner, response)
    """
    # Read banner
    banner = _recv_until(sock, timeout=timeout)
    # Send auth command
    cmd = f"AUTH {username} {password}\r\n".encode()
    sock.sendall(cmd)
    response = _recv_until(sock, timeout=timeout)
    return banner, response


def _try_router(sock: socket.socket, username: str, password: str,
                timeout: float) -> tuple[str, str]:
    """
    Telnet-like router protocol.
    Device sends banner + "Username: " prompt.
    Client sends username, device sends "Password: ", client sends password.
    Returns: (banner, response after password)
    """
    # Read banner (includes "Username: " prompt at the end)
    banner_data = b""
    sock.settimeout(timeout)
    try:
        while True:
            chunk = sock.recv(256)
            if not chunk:
                break
            banner_data += chunk
            if b"Username:" in banner_data or b"username:" in banner_data:
                break
    except socket.timeout:
        pass

    banner = banner_data.decode("utf-8", errors="replace")

    # Send username
    sock.sendall((username + "\r\n").encode())

    # Read until password prompt
    pw_prompt = b""
    sock.settimeout(timeout)
    try:
        while True:
            chunk = sock.recv(256)
            if not chunk:
                break
            pw_prompt += chunk
            if b"Password:" in pw_prompt or b"password:" in pw_prompt:
                break
    except socket.timeout:
        pass

    # Send password
    sock.sendall((password + "\r\n").encode())

    # Read response
    response = _recv_until(sock, timeout=timeout)
    return banner, response


def _try_sensor(sock: socket.socket, username: str, password: str,
                timeout: float) -> tuple[str, str]:
    """
    JSON-TCP sensor protocol.
    Device sends JSON banner.
    Client sends JSON {"user": ..., "pass": ...}.
    Device responds JSON {"status": ...}.
    Returns: (banner, response)
    """
    # Read JSON banner
    banner = _recv_until(sock, timeout=timeout)

    # Send JSON auth payload
    payload = json.dumps({"user": username, "pass": password}) + "\n"
    sock.sendall(payload.encode())

    # Read JSON response
    response = _recv_until(sock, timeout=timeout)
    return banner, response


def _try_smartplug(sock: socket.socket, username: str, password: str,
                   timeout: float) -> tuple[str, str]:
    """
    REST-like smart plug protocol.
    Device sends banner.
    Client sends JSON {"username": ..., "password": ...}\n.
    Device responds JSON {"status": ...}.
    Returns: (banner, response)
    """
    # Read banner
    banner = _recv_until(sock, timeout=timeout)

    # Send JSON auth payload (matching smartplug_sim.py's JSON parser)
    payload = json.dumps({"username": username, "password": password}) + "\n"
    sock.sendall(payload.encode())

    # Read response
    response = _recv_until(sock, timeout=timeout)
    return banner, response


# Protocol dispatch table
_PROTOCOL_HANDLERS = {
    "HTTP-like": _try_camera,
    "Telnet-like": _try_router,
    "JSON-TCP": _try_sensor,
    "REST-like": _try_smartplug,
}


# ─────────────────────────────────────────────────────────────────────────────
# Main Scanner Class
# ─────────────────────────────────────────────────────────────────────────────

class CredentialScanner:
    """
    Multi-threaded IoT credential scanner.

    Scans multiple devices concurrently, tries credential lists in priority
    order, detects lockout/rate-limit defenses, and attempts timed bypasses
    to evaluate hardening effectiveness.

    Args:
        targets:               List of ScanTarget devices to scan.
        credentials:           Ordered list of CredentialEntry pairs to try.
        max_workers:           Thread pool size for concurrent scanning.
        timeout:               Socket operation timeout in seconds.
        max_attempts_per_device: Stop after N attempts per device (None = try all).
        backoff_base:          Base wait time (seconds) before bypass attempt.
    """

    def __init__(
        self,
        targets: List[ScanTarget],
        credentials: List[CredentialEntry],
        max_workers: int = 4,
        timeout: float = 5.0,
        max_attempts_per_device: Optional[int] = None,
        backoff_base: float = 2.0,
    ):
        self.targets = targets
        self.credentials = credentials
        self.max_workers = max_workers
        self.timeout = timeout
        self.max_attempts_per_device = max_attempts_per_device
        self.backoff_base = backoff_base

    # ─── Public API ───────────────────────────────────────────────────────────

    def scan_all(
        self,
        streaming_callback=None,
        raw_log_path: Optional[str] = None,
    ) -> List[DeviceResult]:
        """
        Scan all targets concurrently using a thread pool.

        Args:
            streaming_callback: Optional callable(str) invoked after every
                credential attempt with a formatted log line. Used by the
                web server to push SSE events in real time.
            raw_log_path: Optional path to write a timestamped raw scan log
                (e.g. logs/raw_scan.log) suitable for submission evidence.

        Returns:
            List of DeviceResult (one per target).
        """
        import os as _os
        self._streaming_callback = streaming_callback
        self._raw_log_lines: List[str] = []
        self._raw_log_lock = threading.Lock()

        results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_target = {
                executor.submit(self._scan_device, target): target
                for target in self.targets
            }
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as exc:
                    logger.error(f"Scan of {target.device_id} raised exception: {exc}")
                    results.append(DeviceResult(
                        target=target,
                        banner="(connection failed)",
                        cracked=False,
                        cracked_credential=None,
                        attempts=0,
                        time_to_crack_seconds=None,
                        cred_rank=None,
                        lockout_detected=False,
                        rate_limit_detected=False,
                        bypass_attempts=0,
                    ))

        # Write raw evidence log
        if raw_log_path:
            try:
                _os.makedirs(_os.path.dirname(raw_log_path), exist_ok=True)
                with open(raw_log_path, "w", encoding="utf-8") as f:
                    f.write("\n".join(self._raw_log_lines) + "\n")
            except Exception as e:
                logger.warning(f"Could not write raw log: {e}")

        return results

    def save_results(
        self,
        results: List[DeviceResult],
        filepath: str,
        run_label: str = "Scan",
        network_config: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        """
        Serialize DeviceResult list to JSON at filepath.

        The schema is designed for easy consumption by the report generator
        and for archival / reproducibility of experiments.
        """
        import os
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        by_protocol: Dict[str, Dict] = {}
        by_risk: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        cracked_count = 0
        crack_times = []
        crack_attempts_list = []

        # Build a lookup from device_id -> network_config entry (for simulated_ip/service)
        cfg_lookup: Dict[str, Dict] = {}
        if network_config:
            for c in network_config:
                cfg_lookup[c["device_id"]] = c

        device_dicts = []
        for r in results:
            if r.cracked:
                cracked_count += 1
                if r.time_to_crack_seconds is not None:
                    crack_times.append(r.time_to_crack_seconds)
                if r.attempts:
                    crack_attempts_list.append(r.attempts)

            proto = r.target.protocol
            if proto not in by_protocol:
                by_protocol[proto] = {"cracked": 0, "total": 0}
            by_protocol[proto]["total"] += 1
            if r.cracked:
                by_protocol[proto]["cracked"] += 1

            level = r.risk_level
            if level in by_risk:
                by_risk[level] += 1

            # Enrich with config metadata (IPv6, service label, display fields)
            cfg = cfg_lookup.get(r.target.device_id, {})
            simulated_ip = cfg.get("simulated_ip", f"fd00::{r.target.port % 256:03d}")
            service_label = cfg.get("service", "CoAP/5683")
            type_label    = cfg.get("type_label", r.target.device_type.title())
            display_name  = cfg.get("display_name", r.target.device_id)

            # Crack credential formatted string (for brief's spec)
            cred_str = None
            if r.cracked and r.cracked_credential:
                u = r.cracked_credential.get("username", "")
                p = r.cracked_credential.get("password", "")
                cred_str = f"{u}:{p}" if p else f"{u}:(empty)"

            # Risk status string for the brief's JSON shape
            status_map = {"CRITICAL": "critical", "HIGH": "high",
                          "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "low"}
            status = status_map.get(r.risk_level, "low")

            # First recommendation, condensed
            rec = ""
            if r.hardening_recommendations:
                rec = r.hardening_recommendations[0][:120]

            # Time string
            time_str = (
                f"{r.time_to_crack_seconds:.1f}s"
                if r.time_to_crack_seconds is not None
                else "N/A"
            )

            device_dicts.append({
                # ── Brief's exact JSON shape ───────────────────────────────
                "name":     display_name,
                "type":     type_label,
                "ip":       simulated_ip,
                "service":  service_label,
                "tested":   len(r.all_attempts),
                "status":   status,
                "cred":     cred_str,
                "attempts": r.attempts,
                "time":     time_str,
                "rec":      rec,
                # ── Extended fields for internal use ──────────────────────
                "device_id":    r.target.device_id,
                "device_type":  r.target.device_type,
                "protocol":     r.target.protocol,
                "host":         r.target.host,
                "port":         r.target.port,
                "hardened":     r.target.hardened,
                "banner":       r.banner[:200],
                "cracked":      r.cracked,
                "cracked_credential": r.cracked_credential,
                "time_to_crack_seconds": r.time_to_crack_seconds,
                "cred_rank":    r.cred_rank,
                "lockout_detected":    r.lockout_detected,
                "rate_limit_detected": r.rate_limit_detected,
                "bypass_attempts":     r.bypass_attempts,
                "risk_score":   r.risk_score,
                "risk_level":   r.risk_level,
                "hardening_recommendations": r.hardening_recommendations,
                "all_attempts": [
                    {
                        "username":   a.username,
                        "password":   a.password,
                        "result":     a.result,
                        "latency_ms": a.latency_ms,
                        "timestamp":  a.timestamp,
                    }
                    for a in r.all_attempts
                ],
            })

        output = {
            "scan_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "run_label": run_label,
            "devices": device_dicts,
            "summary": {
                "total_devices": len(results),
                "cracked": cracked_count,
                "not_cracked": len(results) - cracked_count,
                "by_protocol": by_protocol,
                "by_risk_level": by_risk,
                "fastest_crack_seconds": min(crack_times) if crack_times else None,
                "avg_attempts_to_crack": (
                    round(sum(crack_attempts_list) / len(crack_attempts_list), 1)
                    if crack_attempts_list else None
                ),
                "vulnerability_rate": (
                    round(cracked_count / len(results) * 100, 1)
                    if results else 0.0
                ),
            },
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)

        logger.info(f"Scan results saved to {filepath}")

    # ─── Device Scanning ──────────────────────────────────────────────────────

    def _emit(self, line: str) -> None:
        """Emit a log line to the streaming callback and raw log buffer."""
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        full = f"[{ts}] {line}"
        with self._raw_log_lock:
            self._raw_log_lines.append(full)
        if self._streaming_callback:
            try:
                self._streaming_callback(full)
            except Exception:
                pass
        logger.debug(full)

    def _scan_device(self, target: ScanTarget) -> DeviceResult:
        """
        Scan a single device by iterating through the credential list.

        Strategy:
          - Try credentials in rank order (most common first)
          - On LOCKED_OUT: record the event, wait backoff_base seconds, retry once
          - On RATE_LIMITED: wait 0.5s before next attempt
          - Stop immediately on AUTH_OK (first valid credential)
          - Stop if max_attempts_per_device reached
        """
        self._emit(f"[*] Scanning {target.device_id} ({target.protocol}) port {target.port} ...")

        all_attempts: List[AttemptResult] = []
        lockout_detected = False
        rate_limit_detected = False
        bypass_attempts = 0
        scan_start = time.monotonic()
        banner = ""

        creds_to_try = self.credentials
        if self.max_attempts_per_device:
            creds_to_try = creds_to_try[: self.max_attempts_per_device]

        for cred in creds_to_try:
            attempt_start = time.monotonic()
            ts = datetime.now(timezone.utc).isoformat()

            # Connect fresh for each attempt (mirrors real scanner behavior;
            # avoids state leakage between attempts from a persistent connection)
            try:
                attempt_result, banner_out = self._connect_and_try(target, cred)
                if banner_out and not banner:
                    banner = banner_out  # capture first banner seen
            except Exception as exc:
                latency = (time.monotonic() - attempt_start) * 1000
                logger.debug(f"  [!] {target.device_id} {cred.username}/{cred.password}: {exc}")
                all_attempts.append(AttemptResult(
                    username=cred.username,
                    password=cred.password,
                    result="ERROR",
                    latency_ms=round(latency, 2),
                    timestamp=ts,
                ))
                time.sleep(0.1)
                continue

            latency = (time.monotonic() - attempt_start) * 1000
            result_code = attempt_result

            # Emit live attempt line (raw scan log format from the brief)
            result_display = {
                "AUTH_OK": "200 OK",
                "AUTH_FAIL": "401 Unauthorized",
                "LOCKED_OUT": "403 Locked",
                "RATE_LIMITED": "429 Rate Limited",
            }.get(result_code, result_code)
            simulated_ip = getattr(target, "simulated_ip", target.host)
            self._emit(
                f"{target.device_id} ({simulated_ip}) -> /login "
                f"{cred.username}:{cred.password or '<empty>'} -> {result_display}"
            )

            # Track protective responses
            if result_code == "LOCKED_OUT":
                lockout_detected = True
                self._emit(
                    f"[🔒] {target.device_id}: Lockout triggered after "
                    f"{len(all_attempts)+1} attempts. Attempting bypass ..."
                )
                # Bypass: wait and retry the same credential once
                time.sleep(self.backoff_base)
                try:
                    bypass_result, _ = self._connect_and_try(target, cred)
                    bypass_attempts += 1
                    if bypass_result == "AUTH_OK":
                        # Lockout bypassed — treat as cracked with bypass note
                        elapsed = time.monotonic() - scan_start
                        all_attempts.append(AttemptResult(
                            username=cred.username,
                            password=cred.password,
                            result="LOCKED_OUT",
                            latency_ms=round(latency, 2),
                            timestamp=ts,
                        ))
                        all_attempts.append(AttemptResult(
                            username=cred.username,
                            password=cred.password,
                            result="AUTH_OK",
                            latency_ms=round((time.monotonic() - attempt_start) * 1000, 2),
                            timestamp=datetime.now(timezone.utc).isoformat(),
                        ))
                        self._emit(f"[!] {target.device_id}: Lockout BYPASSED — {cred.username}:{cred.password!r}")
                        return DeviceResult(
                            target=target, banner=banner,
                            cracked=True,
                            cracked_credential={"username": cred.username, "password": cred.password},
                            attempts=len(all_attempts),
                            time_to_crack_seconds=round(elapsed, 3),
                            cred_rank=cred.rank,
                            lockout_detected=True,
                            rate_limit_detected=rate_limit_detected,
                            bypass_attempts=bypass_attempts,
                            all_attempts=all_attempts,
                        )
                except Exception:
                    pass
                # Lockout not bypassed — stop scanning this device
                all_attempts.append(AttemptResult(
                    username=cred.username,
                    password=cred.password,
                    result="LOCKED_OUT",
                    latency_ms=round(latency, 2),
                    timestamp=ts,
                ))
                break  # device is locked, move on

            elif result_code == "RATE_LIMITED":
                rate_limit_detected = True
                logger.debug(f"  [~] {target.device_id}: Rate limited, backing off ...")
                all_attempts.append(AttemptResult(
                    username=cred.username,
                    password=cred.password,
                    result="RATE_LIMITED",
                    latency_ms=round(latency, 2),
                    timestamp=ts,
                ))
                time.sleep(0.5)  # respect rate limit briefly
                continue

            elif result_code == "AUTH_OK":
                elapsed = time.monotonic() - scan_start
                all_attempts.append(AttemptResult(
                    username=cred.username,
                    password=cred.password,
                    result="AUTH_OK",
                    latency_ms=round(latency, 2),
                    timestamp=ts,
                ))
                self._emit(
                    f"[✓] CRACKED: {target.device_id} — "
                    f"{cred.username}:{cred.password!r} "
                    f"(rank #{cred.rank}, {elapsed:.2f}s)"
                )
                return DeviceResult(
                    target=target, banner=banner,
                    cracked=True,
                    cracked_credential={"username": cred.username, "password": cred.password},
                    attempts=len(all_attempts),
                    time_to_crack_seconds=round(elapsed, 3),
                    cred_rank=cred.rank,
                    lockout_detected=lockout_detected,
                    rate_limit_detected=rate_limit_detected,
                    bypass_attempts=bypass_attempts,
                    all_attempts=all_attempts,
                )
            else:
                # AUTH_FAIL — continue
                all_attempts.append(AttemptResult(
                    username=cred.username,
                    password=cred.password,
                    result="AUTH_FAIL",
                    latency_ms=round(latency, 2),
                    timestamp=ts,
                ))

        # All credentials exhausted without success
        self._emit(f"[✗] NOT CRACKED: {target.device_id} ({len(all_attempts)} attempts tried)")
        return DeviceResult(
            target=target, banner=banner,
            cracked=False,
            cracked_credential=None,
            attempts=len(all_attempts),
            time_to_crack_seconds=None,
            cred_rank=None,
            lockout_detected=lockout_detected,
            rate_limit_detected=rate_limit_detected,
            bypass_attempts=bypass_attempts,
            all_attempts=all_attempts,
        )

    def _connect_and_try(
        self, target: ScanTarget, cred: CredentialEntry
    ) -> tuple[str, str]:
        """
        Open a TCP connection to target, run the protocol-specific auth exchange.

        Returns:
            (result_code, banner) — result_code is one of AUTH_OK/AUTH_FAIL/LOCKED_OUT/RATE_LIMITED/ERROR
        """
        handler = _PROTOCOL_HANDLERS.get(target.protocol)
        if handler is None:
            raise ValueError(f"Unknown protocol: {target.protocol}")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            sock.connect((target.host, target.port))
            banner, response = handler(sock, cred.username, cred.password, self.timeout)

        result_code = _classify_response(response)
        return result_code, banner


# ─────────────────────────────────────────────────────────────────────────────
# Result Persistence
# ─────────────────────────────────────────────────────────────────────────────

def load_results(filepath: str) -> List[DeviceResult]:
    """
    Load previously saved scan results from JSON and reconstruct DeviceResult objects.

    Used by the report generator so it can run independently from the scanner.
    """
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    results = []
    for d in data["devices"]:
        target = ScanTarget(
            device_id=d["device_id"],
            device_type=d["device_type"],
            protocol=d["protocol"],
            host=d["host"],
            port=d["port"],
            hardened=d["hardened"],
        )
        attempts = [
            AttemptResult(
                username=a["username"],
                password=a["password"],
                result=a["result"],
                latency_ms=a["latency_ms"],
                timestamp=a["timestamp"],
            )
            for a in d.get("all_attempts", [])
        ]
        results.append(DeviceResult(
            target=target,
            banner=d.get("banner", ""),
            cracked=d["cracked"],
            cracked_credential=d.get("cracked_credential"),
            attempts=d["attempts"],
            time_to_crack_seconds=d.get("time_to_crack_seconds"),
            cred_rank=d.get("cred_rank"),
            lockout_detected=d.get("lockout_detected", False),
            rate_limit_detected=d.get("rate_limit_detected", False),
            bypass_attempts=d.get("bypass_attempts", 0),
            all_attempts=attempts,
            risk_score=d.get("risk_score", 0),
            risk_level=d.get("risk_level", "UNKNOWN"),
            hardening_recommendations=d.get("hardening_recommendations", []),
        ))
    return results
