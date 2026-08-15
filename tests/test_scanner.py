"""
tests/test_scanner.py
======================
Unit tests for scanner modules: credential loader, pattern categorization, risk scoring rubric.
"""

import os
import pytest
from scanner.cred_list import load_credentials, categorize_password, password_pattern_stats
from scanner.risk_report import RiskScorer
from scanner.scanner_core import DeviceResult, ScanTarget, AttemptResult


def test_credential_loader(tmp_path):
    """Test loading and ranking default credentials."""
    cred_file = tmp_path / "creds.txt"
    cred_file.write_text("# TOP5\nadmin,admin\nroot,root\nadmin,1234\n")

    creds = load_credentials(str(cred_file))
    assert len(creds) == 3
    assert creds[0].username == "admin"
    assert creds[0].password == "admin"
    assert creds[0].rank == 1


def test_categorize_password():
    """Test password pattern categorization."""
    assert categorize_password("123456") == "numeric_only"
    assert categorize_password("password") == "alpha_only"
    assert categorize_password("") == "empty"
    assert categorize_password("ipcam") == "device_specific"


def test_risk_scorer():
    """Test risk scoring rubric logic."""
    target = ScanTarget("cam_1", "camera", "HTTP-like", "127.0.0.1", 9001, False)
    
    # Critical risk: cracked with top-5 credential
    res_critical = DeviceResult(
        target=target,
        banner="IPCam-2000",
        cracked=True,
        cracked_credential={"username": "admin", "password": "admin"},
        attempts=1,
        time_to_crack_seconds=0.01,
        cred_rank=1,
        lockout_detected=False,
        rate_limit_detected=False,
        bypass_attempts=0,
        all_attempts=[]
    )

    score, level, recs = RiskScorer.score_device(res_critical)
    assert score == 10
    assert level == "CRITICAL"
    assert len(recs) > 0
