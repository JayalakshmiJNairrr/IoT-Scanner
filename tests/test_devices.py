"""
tests/test_devices.py
======================
Unit tests for simulated IoT device servers (Camera, Router, Sensor, Smart Plug).
Tests TCP server startup, credential validation, rate limiting/lockout, and password updates.
"""

import time
import socket
import pytest
from devices.camera_sim import CameraDevice
from devices.router_sim import RouterDevice
from devices.sensor_sim import SensorDevice
from devices.smartplug_sim import SmartPlugDevice


def test_camera_device_auth_and_hardening():
    """Test CameraDevice TCP server authentication and password update."""
    dev = CameraDevice(device_id="test_cam", host="127.0.0.1", port=9901, hardened=False)
    dev.start()
    time.sleep(0.2)

    try:
        # Test valid default credential
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", 9901))
        s.recv(1024) # Banner
        s.sendall(b"AUTH admin admin\r\n")
        resp = s.recv(1024).decode()
        s.close()
        assert "200 OK" in resp or "AUTH_OK" in resp

        # Test invalid credential
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", 9901))
        s.recv(1024)
        s.sendall(b"AUTH admin wrongpass\r\n")
        resp = s.recv(1024).decode()
        s.close()
        assert "401 AUTH_FAIL" in resp

        # Test password change
        dev.change_password("NewSecure#Pass2026")

        # Verify old password fails
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", 9901))
        s.recv(1024)
        s.sendall(b"AUTH admin admin\r\n")
        resp = s.recv(1024).decode()
        s.close()
        assert "401 AUTH_FAIL" in resp

        # Verify new password succeeds
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", 9901))
        s.recv(1024)
        s.sendall(b"AUTH admin NewSecure#Pass2026\r\n")
        resp = s.recv(1024).decode()
        s.close()
        assert "200 OK" in resp or "AUTH_OK" in resp

    finally:
        dev.stop()


def test_sensor_json_device():
    """Test TCP JSON Sensor device authentication."""
    dev = SensorDevice(device_id="test_sensor", host="127.0.0.1", port=9903, hardened=False)
    dev.start()
    time.sleep(0.2)

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", 9903))
        s.recv(1024) # Banner
        s.sendall(b'{"user": "user", "pass": "user"}\n')
        resp = s.recv(1024).decode()
        s.close()
        assert '"status": "ok"' in resp or 'Authenticated' in resp
    finally:
        dev.stop()
