"""
scanner/risk_report.py
======================
Risk scoring engine and analysis modules for the IoT scanner.

Implements:
  - RiskScorer: assigns a 0–10 score and CRITICAL/HIGH/MEDIUM/LOW label to each
    device based on how and whether it was cracked, and whether hardening measures
    were in place or bypassed.
  - ProtocolAnalyzer: aggregates crack rates and timing by protocol type.
  - PasswordPatternAnalyzer: categorizes cracked passwords by pattern weakness.
  - generate_full_report_data: one-shot function that runs all analysis and
    returns a complete data dict ready for the HTML report generator.
"""

from typing import List, Dict, Any, Optional, Tuple
from scanner.scanner_core import DeviceResult


# ─────────────────────────────────────────────────────────────────────────────
# Risk Scoring
# ─────────────────────────────────────────────────────────────────────────────

class RiskScorer:
    """
    Assigns risk scores to scanned devices using a tiered rubric.

    Rubric (priority order — first matching rule wins):
      Score 10, CRITICAL  — Cracked with a top-5 most common credential
      Score  9, CRITICAL  — Cracked with empty password
      Score  7, HIGH      — Cracked after bypassing lockout
      Score  8, HIGH      — Cracked with a top-20 credential
      Score  6, HIGH      — Cracked, credential ranked 21+
      Score  4, MEDIUM    — Not cracked, no lockout mechanism detected
      Score  2, LOW       — Not cracked, lockout enforced (hardened)
    """

    # Tailored recommendations by device type
    _DEVICE_RECS: Dict[str, List[str]] = {
        "camera": [
            "Disable remote HTTP access if not required for operations.",
            "Move camera admin UI behind a VPN or private VLAN.",
            "Enable HTTPS with a valid TLS certificate.",
        ],
        "router": [
            "Disable Telnet; use SSH with key-based authentication instead.",
            "Restrict admin access to LAN only — block WAN management.",
            "Update firmware to latest version to patch authentication vulnerabilities.",
        ],
        "sensor": [
            "Use mutual TLS (mTLS) or certificate-based auth for sensor endpoints.",
            "Disable plaintext TCP; tunnel through an encrypted transport (DTLS/TLS).",
            "Implement per-sensor unique credentials, not a shared default.",
        ],
        "smartplug": [
            "Enable two-factor authentication for the device management API.",
            "Restrict API access by source IP or MAC address allowlist.",
            "Use signed API tokens instead of password-based HTTP auth.",
        ],
    }

    # Universal recommendations added based on condition
    _UNIVERSAL_RECS = {
        "cracked_top5": (
            "⚠ CRITICAL: This credential is in the top-5 most commonly tried IoT "
            "defaults (Mirai-level). Change immediately — this device is at maximum risk."
        ),
        "empty_password": (
            "Device accepted an empty password. This is a severe misconfiguration. "
            "Require a non-empty password of at least 12 characters."
        ),
        "no_lockout": (
            "Implement account lockout after 5 consecutive failures within 60 seconds."
        ),
        "bypass_succeeded": (
            "Rate-limiting / lockout was detected but bypassed via timed retry. "
            "Implement exponential backoff, CAPTCHA, or IP-based permanent ban "
            "after repeated bypass attempts."
        ),
        "always_change": (
            "Force a mandatory password change on first login. "
            "Never ship devices with enabled default credentials."
        ),
        "long_password": (
            "Enforce a minimum password length of 12 characters with complexity requirements."
        ),
        "audit_log": (
            "Enable persistent audit logging of all authentication attempts "
            "with IP, timestamp, and outcome."
        ),
    }

    def score_device(
        self, result: DeviceResult
    ) -> Tuple[int, str, List[str]]:
        """
        Compute risk score, level, and tailored recommendations for one device.

        Args:
            result: A DeviceResult from the scanner.

        Returns:
            (score: int 0–10, level: str, recommendations: List[str])
        """
        score, level = self._compute_score(result)
        recs = self._build_recommendations(result)
        return score, level, recs

    def _compute_score(self, r: DeviceResult) -> Tuple[int, str]:
        """Apply the rubric and return (score, level)."""
        # Cracked scenarios
        if r.cracked:
            # Empty password — extremely dangerous
            cred_pass = (r.cracked_credential or {}).get("password", "NONEMPTY")
            if cred_pass == "":
                return 9, "CRITICAL"

            # Top-5 credential
            if r.cred_rank is not None and r.cred_rank <= 5:
                return 10, "CRITICAL"

            # Bypassed lockout — actively defeated hardening
            if r.lockout_detected and r.bypass_attempts > 0:
                return 7, "HIGH"

            # Top-20 credential
            if r.cred_rank is not None and r.cred_rank <= 20:
                return 8, "HIGH"

            # Cracked but required deep search
            return 6, "HIGH"

        # Not cracked scenarios
        if not r.lockout_detected:
            return 4, "MEDIUM"   # No lockout — only chance saved it
        return 2, "LOW"          # Lockout worked — hardening is effective

    def _build_recommendations(self, r: DeviceResult) -> List[str]:
        """Build an ordered, deduplicated list of recommendations."""
        recs = []

        if r.cracked:
            recs.append(self._UNIVERSAL_RECS["always_change"])

            cred_pass = (r.cracked_credential or {}).get("password", "NONEMPTY")
            if cred_pass == "":
                recs.append(self._UNIVERSAL_RECS["empty_password"])

            if r.cred_rank is not None and r.cred_rank <= 5:
                recs.append(self._UNIVERSAL_RECS["cracked_top5"])

        if not r.lockout_detected:
            recs.append(self._UNIVERSAL_RECS["no_lockout"])

        if r.lockout_detected and r.bypass_attempts > 0 and r.cracked:
            recs.append(self._UNIVERSAL_RECS["bypass_succeeded"])

        recs.append(self._UNIVERSAL_RECS["long_password"])
        recs.append(self._UNIVERSAL_RECS["audit_log"])

        # Device-specific recommendations
        device_type = r.target.device_type
        recs.extend(self._DEVICE_RECS.get(device_type, []))

        # Deduplicate preserving order
        seen = set()
        deduped = []
        for rec in recs:
            if rec not in seen:
                seen.add(rec)
                deduped.append(rec)

        return deduped


# ─────────────────────────────────────────────────────────────────────────────
# Protocol-Level Analysis
# ─────────────────────────────────────────────────────────────────────────────

class ProtocolAnalyzer:
    """
    Aggregates scan results by protocol to identify which communication
    protocol is most susceptible to credential attacks.
    """

    def analyze(self, results: List[DeviceResult]) -> Dict[str, Any]:
        """
        Compute per-protocol vulnerability statistics.

        Returns dict keyed by protocol name:
            total, cracked, not_cracked, crack_rate_pct,
            avg_attempts_to_crack, avg_time_to_crack_s,
            hardened_cracked, hardened_total,
            most_common_cracked_cred
        """
        buckets: Dict[str, List[DeviceResult]] = {}
        for r in results:
            proto = r.target.protocol
            buckets.setdefault(proto, []).append(r)

        stats = {}
        for proto, devs in buckets.items():
            cracked = [d for d in devs if d.cracked]
            times = [d.time_to_crack_seconds for d in cracked if d.time_to_crack_seconds]
            attempts_list = [d.attempts for d in cracked if d.attempts]
            hardened_total = sum(1 for d in devs if d.target.hardened)
            hardened_cracked = sum(1 for d in cracked if d.target.hardened)

            # Most common cracked credential across this protocol
            cred_counter: Dict[str, int] = {}
            for d in cracked:
                if d.cracked_credential:
                    key = "{username}/{password}".format(**d.cracked_credential)
                    cred_counter[key] = cred_counter.get(key, 0) + 1
            most_common = max(cred_counter, key=cred_counter.get) if cred_counter else None

            stats[proto] = {
                "total": len(devs),
                "cracked": len(cracked),
                "not_cracked": len(devs) - len(cracked),
                "crack_rate_pct": round(len(cracked) / len(devs) * 100, 1) if devs else 0,
                "avg_attempts_to_crack": (
                    round(sum(attempts_list) / len(attempts_list), 1)
                    if attempts_list else None
                ),
                "avg_time_to_crack_s": (
                    round(sum(times) / len(times), 3) if times else None
                ),
                "hardened_total": hardened_total,
                "hardened_cracked": hardened_cracked,
                "most_common_cracked_cred": most_common,
            }
        return stats


# ─────────────────────────────────────────────────────────────────────────────
# Password Pattern Analysis
# ─────────────────────────────────────────────────────────────────────────────

class PasswordPatternAnalyzer:
    """
    Analyzes the passwords of cracked devices to identify which password
    patterns are most prevalent and therefore most dangerous in IoT deployments.
    """

    _DEVICE_KEYWORDS = {
        "ipcam", "camera", "cam", "router", "sensor", "plug", "gateway",
        "modem", "wifi", "iot", "device", "netcam", "nvr", "dvr",
        "cctv", "ubnt", "motorola", "raspberry", "alpine", "smcadmin",
    }

    def _categorize(self, password: str) -> str:
        if password == "":
            return "empty"
        import re
        if re.fullmatch(r"\d+", password):
            return "numeric_only"
        if re.fullmatch(r"[a-zA-Z]+", password):
            pw_low = password.lower()
            if any(kw in pw_low for kw in self._DEVICE_KEYWORDS):
                return "device_specific"
            return "alpha_only"
        if any(kw in password.lower() for kw in self._DEVICE_KEYWORDS):
            return "device_specific"
        if len(password) <= 6:
            return "short_simple"
        return "alphanumeric"

    def analyze(self, results: List[DeviceResult]) -> Dict[str, Any]:
        """
        Categorize passwords of cracked devices and return distribution stats.

        Returns dict: {pattern_name: {count, pct, examples}}
        """
        cracked_passwords = [
            r.cracked_credential["password"]
            for r in results
            if r.cracked and r.cracked_credential
        ]
        total = len(cracked_passwords)
        if total == 0:
            return {}

        buckets: Dict[str, List[str]] = {}
        for pw in cracked_passwords:
            cat = self._categorize(pw)
            buckets.setdefault(cat, []).append(pw)

        return {
            cat: {
                "count": len(pws),
                "pct": round(len(pws) / total * 100, 1),
                "examples": list(dict.fromkeys(pws))[:3],
            }
            for cat, pws in sorted(buckets.items(), key=lambda kv: -len(kv[1]))
        }


# ─────────────────────────────────────────────────────────────────────────────
# Full Report Data Assembly
# ─────────────────────────────────────────────────────────────────────────────

def generate_full_report_data(results: List[DeviceResult]) -> Dict[str, Any]:
    """
    Run all analysis passes and return a unified data dict for the HTML generator.

    This function also mutates each DeviceResult in-place to attach
    risk_score, risk_level, and hardening_recommendations.

    Args:
        results: DeviceResult list from CredentialScanner.scan_all()

    Returns:
        Complete report dict with "devices", "summary", "protocol_analysis",
        "password_patterns", and "hardening_comparison" sections.
    """
    scorer = RiskScorer()
    proto_analyzer = ProtocolAnalyzer()
    pw_analyzer = PasswordPatternAnalyzer()

    # Score each device and mutate result in-place
    for r in results:
        score, level, recs = scorer.score_device(r)
        r.risk_score = score
        r.risk_level = level
        r.hardening_recommendations = recs

    # Summary statistics
    cracked = [r for r in results if r.cracked]
    not_cracked = [r for r in results if not r.cracked]
    crack_times = [r.time_to_crack_seconds for r in cracked if r.time_to_crack_seconds]
    by_risk: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in results:
        if r.risk_level in by_risk:
            by_risk[r.risk_level] += 1

    by_protocol_raw = {}
    for r in results:
        proto = r.target.protocol
        by_protocol_raw.setdefault(proto, {"cracked": 0, "total": 0})
        by_protocol_raw[proto]["total"] += 1
        if r.cracked:
            by_protocol_raw[proto]["cracked"] += 1

    # Before/After hardening comparison
    normal_devs = [r for r in results if not r.target.hardened]
    hardened_devs = [r for r in results if r.target.hardened]
    hardening_comparison = {
        "normal": {
            "total": len(normal_devs),
            "cracked": sum(1 for r in normal_devs if r.cracked),
            "crack_rate_pct": (
                round(sum(1 for r in normal_devs if r.cracked) / len(normal_devs) * 100, 1)
                if normal_devs else 0
            ),
        },
        "hardened": {
            "total": len(hardened_devs),
            "cracked": sum(1 for r in hardened_devs if r.cracked),
            "crack_rate_pct": (
                round(sum(1 for r in hardened_devs if r.cracked) / len(hardened_devs) * 100, 1)
                if hardened_devs else 0
            ),
            "lockout_events": sum(1 for r in hardened_devs if r.lockout_detected),
            "bypass_successes": sum(1 for r in hardened_devs if r.bypass_attempts > 0 and r.cracked),
        },
    }

    # Serialize device results
    device_dicts = []
    for r in results:
        device_dicts.append({
            "device_id": r.target.device_id,
            "device_type": r.target.device_type,
            "protocol": r.target.protocol,
            "host": r.target.host,
            "port": r.target.port,
            "hardened": r.target.hardened,
            "banner": r.banner[:300],
            "cracked": r.cracked,
            "cracked_credential": r.cracked_credential,
            "attempts": r.attempts,
            "time_to_crack_seconds": r.time_to_crack_seconds,
            "cred_rank": r.cred_rank,
            "lockout_detected": r.lockout_detected,
            "rate_limit_detected": r.rate_limit_detected,
            "bypass_attempts": r.bypass_attempts,
            "risk_score": r.risk_score,
            "risk_level": r.risk_level,
            "hardening_recommendations": r.hardening_recommendations,
            "all_attempts": [
                {
                    "username": a.username,
                    "password": a.password,
                    "result": a.result,
                    "latency_ms": a.latency_ms,
                    "timestamp": a.timestamp,
                }
                for a in r.all_attempts
            ],
        })

    return {
        "devices": device_dicts,
        "summary": {
            "total_devices": len(results),
            "cracked": len(cracked),
            "not_cracked": len(not_cracked),
            "by_risk_level": by_risk,
            "by_protocol": by_protocol_raw,
            "fastest_crack_seconds": min(crack_times) if crack_times else None,
            "avg_time_to_crack": (
                round(sum(crack_times) / len(crack_times), 3) if crack_times else None
            ),
        },
        "protocol_analysis": proto_analyzer.analyze(results),
        "password_patterns": pw_analyzer.analyze(results),
        "hardening_comparison": hardening_comparison,
    }
