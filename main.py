"""
IoT Default Credential & Weak Authentication Scanner
=====================================================
Main CLI entry point.

Usage:
    python main.py --all                  # Full pipeline: launch, scan, report
    python main.py --launch               # Start all simulated IoT devices
    python main.py --scan                 # Run credential scan (devices must be running)
    python main.py --report               # Generate HTML report from last scan
    python main.py --scan --hardened-only # Scan only hardened devices
    python main.py --scan --max-attempts 30

Real-world context: This tool simulates the credential-stuffing technique used by
the Mirai botnet (2016), which compromised 600,000+ IoT devices using ~60 default
credential pairs. All activity is strictly localhost — no real devices are involved.
"""

import argparse
import json
import os
import sys
import time
import threading
import logging

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
DATA_DIR = os.path.join(BASE_DIR, "data")
REPORT_DIR = os.path.join(BASE_DIR, "report")
NETWORK_CONFIG = os.path.join(BASE_DIR, "network", "network_config.json")
CREDS_FILE = os.path.join(DATA_DIR, "iot_default_creds.txt")
RESULTS_FILE = os.path.join(LOG_DIR, "scan_results.json")
REPORT_FILE = os.path.join(REPORT_DIR, "iot_scan_report.html")

# Ensure directories exist
for d in [LOG_DIR, REPORT_DIR]:
    os.makedirs(d, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("iot-scanner-main")


def print_banner():
    banner = r"""
╔══════════════════════════════════════════════════════════════════════╗
║       IoT Default Credential & Weak Authentication Scanner          ║
║                                                                      ║
║   Simulates Mirai-style credential stuffing on a virtual IoT net    ║
║   For educational/research purposes only — localhost only            ║
╚══════════════════════════════════════════════════════════════════════╝
"""
    print(banner)


def load_network_config():
    """Load device configuration from network_config.json."""
    if not os.path.exists(NETWORK_CONFIG):
        logger.error(f"Network config not found: {NETWORK_CONFIG}")
        sys.exit(1)
    with open(NETWORK_CONFIG) as f:
        return json.load(f)


def cmd_launch(args):
    """Phase 1: Launch all simulated IoT devices."""
    sys.path.insert(0, BASE_DIR)
    try:
        from network.launch_network import launch_all, shutdown_all
    except ImportError as e:
        logger.error(f"Cannot import network launcher: {e}")
        sys.exit(1)

    print("\n[+] Launching simulated IoT network...")
    devices = launch_all()

    print(f"\n[+] {len(devices)} devices running:")
    for dev in devices:
        harden_label = "🔒 hardened" if dev.hardened else "⚠  normal"
        print(f"    • {dev.device_id:<25} port {dev.port}  [{harden_label}]")

    print("\n[*] Network is UP. Press Ctrl+C to shutdown all devices.\n")
    try:
        # Keep main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Shutting down all devices...")
        shutdown_all(devices)
        print("[+] All devices stopped.")


def cmd_scan(args):
    """Phase 3-5: Run the credential scanner against all devices."""
    sys.path.insert(0, BASE_DIR)
    try:
        from scanner.cred_list import load_credentials
        from scanner.scanner_core import CredentialScanner, ScanTarget
        from scanner.risk_report import generate_full_report_data
    except ImportError as e:
        logger.error(f"Cannot import scanner modules: {e}")
        sys.exit(1)

    config = load_network_config()
    credentials = load_credentials(CREDS_FILE)

    print(f"\n[+] Loaded {len(credentials)} credentials from {os.path.basename(CREDS_FILE)}")
    print(f"[+] Targeting {len(config)} devices on localhost\n")

    # Build scan targets from config
    protocol_map = {
        "camera": "HTTP-like",
        "router": "Telnet-like",
        "sensor": "JSON-TCP",
        "smartplug": "REST-like",
    }

    targets = []
    for dev_cfg in config:
        # Optionally filter to hardened-only
        if args.hardened_only and not dev_cfg.get("hardened", False):
            continue
        targets.append(
            ScanTarget(
                device_id=dev_cfg["device_id"],
                device_type=dev_cfg["device_type"],
                protocol=protocol_map.get(dev_cfg["device_type"], "Unknown"),
                host="127.0.0.1",
                port=dev_cfg["port"],
                hardened=dev_cfg.get("hardened", False),
                simulated_ip=dev_cfg.get("simulated_ip", ""),
            )
        )

    max_attempts = args.max_attempts if args.max_attempts else None
    scanner = CredentialScanner(
        targets=targets,
        credentials=credentials,
        max_workers=4,
        timeout=5.0,
        max_attempts_per_device=max_attempts,
        backoff_base=2.0,
    )

    start_time = time.time()
    print("[*] Starting scan...\n")
    raw_log_file = os.path.join(LOG_DIR, "raw_scan.log")
    results = scanner.scan_all(raw_log_path=raw_log_file)
    elapsed = time.time() - start_time

    # Enrich with risk scores
    report_data = generate_full_report_data(results)

    # Save with run_label and config for IPv6 enrichment
    scanner.save_results(
        results, RESULTS_FILE,
        run_label=getattr(args, 'run_label', 'Scan'),
        network_config=config,
    )
    print(f"\n[+] Scan complete in {elapsed:.1f}s. Results saved to {RESULTS_FILE}")

    # Print summary table
    _print_scan_summary(report_data)

    return report_data


def _print_scan_summary(report_data):
    """Print a formatted summary table to stdout."""
    devices = report_data.get("devices", [])
    summary = report_data.get("summary", {})

    print("\n" + "─" * 70)
    print(f"  {'DEVICE ID':<28} {'PROTOCOL':<12} {'RESULT':<12} {'RISK':<10}")
    print("─" * 70)

    level_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}

    for dev in devices:
        result_str = "CRACKED ✓" if dev.get("cracked") else "NOT CRACKED"
        level = dev.get("risk_level", "N/A")
        icon = level_icons.get(level, "  ")
        print(
            f"  {dev['device_id']:<28} {dev['protocol']:<12} {result_str:<12} {icon} {level}"
        )

    print("─" * 70)
    print(
        f"\n  Total: {summary.get('total_devices', 0)} devices  |  "
        f"Cracked: {summary.get('cracked', 0)}  |  "
        f"Not Cracked: {summary.get('not_cracked', 0)}"
    )

    by_risk = summary.get("by_risk_level", {})
    print(
        f"  Risk: 🔴 CRITICAL={by_risk.get('CRITICAL',0)}  "
        f"🟠 HIGH={by_risk.get('HIGH',0)}  "
        f"🟡 MEDIUM={by_risk.get('MEDIUM',0)}  "
        f"🟢 LOW={by_risk.get('LOW',0)}"
    )
    print()


def cmd_report(args):
    """Phase 6: Generate HTML report from saved scan results."""
    sys.path.insert(0, BASE_DIR)
    try:
        from report.generate_report import generate_html_report
        from scanner.risk_report import generate_full_report_data
        from scanner.scanner_core import load_results
    except ImportError as e:
        logger.error(f"Cannot import report module: {e}")
        sys.exit(1)

    if not os.path.exists(RESULTS_FILE):
        logger.error(f"No scan results found at {RESULTS_FILE}. Run --scan first.")
        sys.exit(1)

    print(f"\n[+] Loading results from {RESULTS_FILE}")
    results = load_results(RESULTS_FILE)
    report_data = generate_full_report_data(results)

    print("[+] Generating HTML report with charts...")
    generate_html_report(report_data, REPORT_FILE)
    print(f"[+] Report saved to: {REPORT_FILE}")
    print(f"    Open in browser: file://{REPORT_FILE}\n")


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="IoT Default Credential & Weak Authentication Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --all                     # Full pipeline
  python main.py --launch                  # Start devices only
  python main.py --scan                    # Scan (devices must be running externally)
  python main.py --scan --max-attempts 20  # Limit attempts per device
  python main.py --report                  # Generate report from last scan
        """,
    )

    parser.add_argument("--launch", action="store_true", help="Launch simulated IoT network")
    parser.add_argument("--scan", action="store_true", help="Run credential scan")
    parser.add_argument("--report", action="store_true", help="Generate HTML report")
    parser.add_argument(
        "--all", action="store_true", help="Run full pipeline: launch → scan → report"
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=None,
        metavar="N",
        help="Maximum credential attempts per device",
    )
    parser.add_argument(
        "--hardened-only",
        action="store_true",
        help="Scan only hardened devices (for bypass detection demo)",
    )

    args = parser.parse_args()

    if not any([args.launch, args.scan, args.report, args.all]):
        parser.print_help()
        sys.exit(0)

    if args.all:
        # Full pipeline: launch in background, scan, report
        sys.path.insert(0, BASE_DIR)
        try:
            from network.launch_network import launch_all, shutdown_all
        except ImportError as e:
            logger.error(f"Cannot import network launcher: {e}")
            sys.exit(1)

        config = load_network_config()

        print("[+] Phase 1: Launching simulated IoT devices...")
        devices = launch_all()
        print(f"    {len(devices)} devices started on ports {[d.port for d in devices]}")

        print("\n[*] Waiting 1s for devices to initialize...")
        time.sleep(1.0)

        print("\n[+] Phase 2: Running credential scanner...")
        cmd_scan(args)

        print("\n[+] Phase 3: Generating report...")
        cmd_report(args)

        print("\n[+] Shutting down simulated devices...")
        shutdown_all(devices)
        print("[+] Done! Full pipeline complete.\n")

    elif args.launch:
        cmd_launch(args)
    elif args.scan:
        cmd_scan(args)
    elif args.report:
        cmd_report(args)


if __name__ == "__main__":
    main()
