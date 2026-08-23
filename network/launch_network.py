"""
network/launch_network.py
=========================
Launches all 8 simulated IoT device servers with per-device unique credentials.
Supports all 4 device types: camera, sensor, router, smartplug.
"""

import json
import time
import sys
import os

# Ensure the parent directory is in the path to import devices
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from devices.camera_sim import CameraDevice
from devices.sensor_sim import SensorDevice
from devices.router_sim import RouterDevice
from devices.smartplug_sim import SmartPlugDevice

DEVICE_CLASS_MAP = {
    "camera":     CameraDevice,
    "sensor":     SensorDevice,
    "router":     RouterDevice,
    "smartplug":  SmartPlugDevice,
}


def launch_all():
    """Reads network_config.json and launches all configured IoT simulators."""
    config_path = os.path.join(os.path.dirname(__file__), 'network_config.json')
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
    except Exception as e:
        print(f"Failed to load config: {e}")
        return []

    devices = []
    for item in config:
        device_type = item.get("device_type")
        device_id   = item.get("device_id")
        port        = item.get("port")
        hardened    = item.get("hardened", False)
        host        = "0.0.0.0"
        valid_credentials = item.get("valid_credentials")

        cls = DEVICE_CLASS_MAP.get(device_type)
        if cls is None:
            print(f"Unknown device type '{device_type}' for {device_id} — skipping.")
            continue

        try:
            device = cls(device_id, host, port, hardened, valid_credentials=valid_credentials)
            device.start()
            devices.append(device)
            harden_label = "hardened" if hardened else "default creds"
            cred_str = valid_credentials[0]['password'] if valid_credentials else "default"
            print(f"  [+] {device_id:<25} port {port}  [{harden_label}]  cred={valid_credentials[0]['username']}:{cred_str}")
        except Exception as e:
            print(f"  [!] Failed to start {device_id} on port {port}: {e}")

    return devices


def shutdown_all(devices):
    """Stops all running simulated devices."""
    for device in devices:
        try:
            device.stop()
        except Exception:
            pass
    print("All simulated IoT devices shut down.")


if __name__ == '__main__':
    print("Starting SENTRYMESH IoT Network Simulator...")
    devices = launch_all()
    if not devices:
        print("No devices were started. Check network_config.json.")
        sys.exit(1)

    print(f"\n{len(devices)} device(s) running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nInterrupt received. Shutting down...")
        shutdown_all(devices)
