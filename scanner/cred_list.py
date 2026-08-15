"""
scanner/cred_list.py
====================
Credential list loader and analyzer for the IoT scanner.

Loads username/password pairs from the curated default-credentials file,
assigns priority ranks, and provides password-pattern analysis utilities
to understand which credential patterns are most dangerous.
"""

import re
from dataclasses import dataclass
from typing import List, Dict
from pathlib import Path


@dataclass
class CredentialEntry:
    """A single username/password credential pair with metadata."""
    username: str
    password: str
    rank: int           # 1-based sequential rank (lower = higher priority)
    category: str       # "TOP5", "TOP20", or "EXTENDED"

    def __repr__(self):
        return f"CredentialEntry(rank={self.rank}, user={self.username!r}, pass={self.password!r}, cat={self.category})"


# Known IoT device-related keywords for pattern detection
_DEVICE_KEYWORDS = {
    "ipcam", "camera", "cam", "router", "sensor", "plug", "switch",
    "gateway", "modem", "wireless", "wifi", "iot", "device", "netcam",
    "nvr", "dvr", "cctv", "hikvision", "dahua", "ubnt", "ubiquiti",
    "motorola", "technicolor", "smcadmin", "alpine", "raspberry",
}

# Common English words that are NOT device-specific
_COMMON_WORDS = {
    "password", "admin", "root", "user", "guest", "setup", "default",
    "support", "service", "operator", "manager", "system", "login",
    "pass", "device", "test", "demo", "temp",
}


def load_credentials(filepath: str) -> List[CredentialEntry]:
    """
    Parse the credential file into a ranked list of CredentialEntry objects.

    The file format:
        # ─── CATEGORY_NAME ─────────
        username,password
        ...

    Category is determined by the most recent section comment before each entry.

    Args:
        filepath: Path to the .txt credential file.

    Returns:
        Ordered list of CredentialEntry objects (rank 1 = highest priority).
    """
    entries: List[CredentialEntry] = []
    current_category = "EXTENDED"  # default if no header seen yet
    rank = 0

    # Map section header keywords → canonical category names
    category_map = {
        "TOP5": "TOP5",
        "TOP20": "TOP20",
        "EXTENDED": "EXTENDED",
    }

    with open(filepath, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()

            # Skip blank lines
            if not line:
                continue

            # Section header comment (e.g., "# ─── TOP5 ─────────")
            if line.startswith("#"):
                for key, cat in category_map.items():
                    if key in line.upper():
                        current_category = cat
                        break
                continue  # skip comment lines entirely

            # Credential line: username,password (password may be empty)
            if "," in line:
                parts = line.split(",", 1)
                username = parts[0].strip()
                password = parts[1].strip() if len(parts) > 1 else ""
                rank += 1
                entries.append(
                    CredentialEntry(
                        username=username,
                        password=password,
                        rank=rank,
                        category=current_category,
                    )
                )

    return entries


def get_top_n(creds: List[CredentialEntry], n: int) -> List[CredentialEntry]:
    """Return the first N credentials (highest priority)."""
    return creds[:n]


def categorize_password(password: str) -> str:
    """
    Classify a password string into a vulnerability pattern category.

    Categories (ordered by severity / ease of cracking):
        "empty"              - No password at all
        "numeric_only"       - Only digits (e.g., "1234", "12345")
        "alpha_only"         - Only letters (e.g., "root", "admin", "password")
        "device_specific"    - Contains a device/manufacturer name
        "common_word"        - Common English auth word
        "short_simple"       - ≤6 chars, alphanumeric mix
        "alphanumeric"       - Mix of letters and numbers, more complex

    Returns:
        Category string.
    """
    if password == "":
        return "empty"

    pw_lower = password.lower()

    if re.fullmatch(r"\d+", password):
        return "numeric_only"

    if re.fullmatch(r"[a-zA-Z]+", password):
        # Check if it's a device keyword
        if any(kw in pw_lower for kw in _DEVICE_KEYWORDS):
            return "device_specific"
        if pw_lower in _COMMON_WORDS:
            return "common_word"
        return "alpha_only"

    # Mixed alphanumeric
    if any(kw in pw_lower for kw in _DEVICE_KEYWORDS):
        return "device_specific"

    if len(password) <= 6:
        return "short_simple"

    return "alphanumeric"


def password_pattern_stats(creds: List[CredentialEntry]) -> Dict[str, dict]:
    """
    Compute password pattern distribution across the full credential list.

    Args:
        creds: List of CredentialEntry objects.

    Returns:
        Dict mapping pattern name → {count, percentage, examples}.
    """
    pattern_buckets: Dict[str, List[str]] = {}

    for cred in creds:
        pat = categorize_password(cred.password)
        if pat not in pattern_buckets:
            pattern_buckets[pat] = []
        pattern_buckets[pat].append(cred.password)

    total = len(creds)
    stats = {}
    for pattern, passwords in sorted(pattern_buckets.items()):
        stats[pattern] = {
            "count": len(passwords),
            "percentage": round(len(passwords) / total * 100, 1) if total else 0,
            "examples": list(dict.fromkeys(passwords))[:3],  # up to 3 unique examples
        }

    return stats
