# Abstract Default Credential and Weak Authentication Scanner for Simulated IoT Devices

**Technical Research & Evaluation Paper**

---

## Executive Summary

The proliferation of Internet of Things (IoT) devices has created an expansive attack surface vulnerable to automated botnets such as Mirai, Hajime, and Mozi. A primary driver of large-scale IoT compromises is the widespread reliance on factory default credentials and weak authentication mechanisms.

This project implements an abstract security scanning and simulation framework to evaluate, analyze, and remediate weak authentication across simulated IoT networks. By deploying a heterogeneous network of mock TCP sensors, IP security cameras, gateways, and smart home actuators on `127.0.0.1`, the scanner systematically executes dictionary-based credential stuffing attacks using public IoT credential lists. The framework evaluates protocol-level vulnerabilities, analyzes password cracking velocity, measures hardening policies (account lockout and forced password changes), and generates self-contained evaluation reports.

---

## 1. Introduction & Background

### 1.1 Motivation
Unlike conventional enterprise systems, IoT devices are frequently deployed with static manufacturer credentials (e.g., `admin/admin`, `root/root`). Devices are often exposed directly to the public internet without mandatory initial credential modification. The 2016 Mirai botnet demonstrated the catastrophic potential of this vulnerability by taking control of over 600,000 IoT cameras and routers using a table of just 60 default username/password pairs, subsequently orchestrating massive Distributed Denial of Service (DDoS) attacks against major DNS providers.

### 1.2 Research Objectives
1. **Heterogeneous Device Simulation**: Create lightweight, thread-safe TCP servers mimicking multi-protocol IoT authentications (RTSP/HTTP Camera, Telnet Router, TCP JSON Sensor, REST Smart Bulb).
2. **Credential Stuffing & Fingerprinting**: Design a multi-threaded scanner capable of banner fingerprinting, dictionary attack execution, and latency tracking.
3. **Analytical Risk Scoring**: Develop an empirical rubric scoring devices on a scale of 0 to 10 based on credential prevalence rank, lockout posture, and cracking time.
4. **Hardening & Remediation Evaluation**: Compare default configurations against hardened twins enforcing lockout thresholds and forced password changes.

---

## 2. System Architecture

```
+-----------------------------------------------------------------------------------+
|                                 WEB DASHBOARD / CLI                               |
|              (Control Panel, Wokwi Circuit Simulator, HTML Report Download)        |
+-----------------------------------------------------------------------------------+
                                         |
                                  REST API / IPC
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                                  SCANNER CORE                                     |
|  +-----------------------+    +-----------------------+    +-------------------+  |
|  | Credential Dictionary |    | Protocol Fingerprint  |    | Risk Rubric &     |  |
|  | (Ranked Mirai List)   |    | (HTTP, Telnet, JSON)  |    | Analytical Engine |  |
|  +-----------------------+    +-----------------------+    +-------------------+  |
+-----------------------------------------------------------------------------------+
                                         |
                                  Concurrent Sockets
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                             VIRTUAL IOT NETWORK                                   |
|  [Port 9001] Smart Camera (Normal)      [Port 9002] Smart Camera (Hardened)      |
|  [Port 9003] Home Gateway (Normal)      [Port 9004] Home Gateway (Hardened)      |
|  [Port 9005] Thermostat (Normal)        [Port 9006] Thermostat (Hardened)        |
|  [Port 9007] Smart Bulb (Normal)        [Port 9008] Smart Bulb (Hardened)        |
+-----------------------------------------------------------------------------------+
```

### 2.1 Virtual Device Layer (`devices/`)
The base device class `BaseDevice` implements a non-blocking TCP socket server loop using Python's `socket` and `threading` modules.
- **`CameraDevice`** (`9001`/`9002`): Simulates HTTP Basic Auth (`AUTH <user> <pass>`).
- **`RouterDevice`** (`9003`/`9004`): Simulates Telnet interactive login prompts (`Username:`, `Password:`).
- **`SensorDevice`** (`9005`/`9006`): Simulates raw TCP JSON payloads (`{"user": "...", "pass": "..."}`).
- **`SmartPlugDevice`** (`9007`/`9008`): Simulates REST form-encoded payloads (`username=X&password=Y`).

### 2.2 Scanner Engine (`scanner/`)
The `CredentialScanner` manages a `ThreadPoolExecutor` worker pool.
- **Lockout & Bypass Detection**: Detects `403 LOCKED_OUT` or `429 RATE_LIMITED` status codes. The scanner logs lockout triggers and executes timed exponential backoff retries to measure lockout bypass susceptibility.
- **Pattern Analyzer**: Categorizes cracked credentials into `numeric_only`, `alpha_only`, `short_simple`, `empty`, or `device_specific` patterns.

---

## 3. Risk Rubric & Scoring Methodology

The framework evaluates security posture using an ordered priority rubric:

| Rank | Condition | Risk Score | Risk Level |
|---|---|---|---|
| 1 | Cracked with Top-5 default credential | **10 / 10** | 🔴 CRITICAL |
| 2 | Cracked with empty password | **9 / 10** | 🔴 CRITICAL |
| 3 | Cracked with Top-20 credential | **8 / 10** | 🟠 HIGH |
| 4 | Lockout bypassed via retry, then cracked | **7 / 10** | 🟠 HIGH |
| 5 | Cracked after 20+ attempts | **6 / 10** | 🟠 HIGH |
| 6 | Not cracked, but no lockout policy enforced | **4 / 10** | 🟡 MEDIUM |
| 7 | Not cracked, account lockout enforced | **2 / 10** | 🟢 LOW |

---

## 4. Experimental Evaluation Results

### 4.1 Default Network Audit Results

| Device ID | Protocol | Result | Attempts | Time to Crack | Risk Score | Risk Level |
|---|---|---|---|---|---|---|
| `camera_normal` | HTTP-like | **CRACKED** | 1 | 0.010s | 10 / 10 | 🔴 CRITICAL |
| `router_normal` | Telnet-like | **CRACKED** | 2 | 0.012s | 10 / 10 | 🔴 CRITICAL |
| `sensor_normal` | JSON-TCP | **CRACKED** | 7 | 0.015s | 8 / 10 | 🟠 HIGH |
| `smartplug_normal`| REST-like | **CRACKED** | 1 | 0.008s | 10 / 10 | 🔴 CRITICAL |
| `camera_hardened` | HTTP-like | **CRACKED** | 1 | 0.505s | 10 / 10 | 🔴 CRITICAL |
| `smartplug_hardened`| REST-like | **CRACKED** | 1 | 0.502s | 10 / 10 | 🔴 CRITICAL |
| `sensor_hardened` | JSON-TCP | **SECURED** | 6 | — | 2 / 10 | 🟢 LOW |

### 4.2 Key Analytical Findings

> **Finding 1: Lockout Timing Window Vulnerability**
> Devices with default credentials in the Top-4 list (e.g., `admin/admin`, `root/root`) are cracked on the **very first attempt**, *before* threshold-based lockouts (e.g., 5 attempts) can engage. Therefore, threshold lockouts offer zero protection against top Mirai credentials.

> **Finding 2: Hardening Efficacy**
> For credentials further down the dictionary (e.g. `user/user` at rank #7), the hardened sensor's lockout policy engaged after 5 failed attempts, successfully stopping the brute-force attack and dropping the risk level to **LOW (2/10)**.

---

## 5. Hardening Recommendations

To achieve robust defense against IoT credential stuffing attacks:

1. **Forced Initial Credential Modification**: Enforce mandatory password updates during first-time setup before enabling network access.
2. **Account Lockout & Exponential Backoff**: Implement progressive rate limiting (e.g., 1s, 2s, 4s delays) and lock accounts after 5 failures within 60 seconds.
3. **Disable Legacy Cleartext Protocols**: Deprecate Telnet and HTTP in favor of SSH and HTTPS/TLS.
4. **Multi-Factor Authentication (MFA)**: Require TOTP or WebAuthn for management API endpoints.

---

## 6. How to Run the Project

### Command Line Interface (CLI)
```bash
cd /home/jayalakshmi-j-nair/iot_scanner

# Run complete end-to-end audit pipeline
python3 main.py --all

# Run individual components
python3 main.py --launch      # Start simulated TCP servers
python3 main.py --scan        # Execute scanner against running network
python3 main.py --report      # Generate HTML report
```

### Interactive Web Dashboard & Circuit Simulator
```bash
python3 web_server.py
```
Open **`http://localhost:5000`** in your browser to view the interactive Wokwi circuit board, run step-by-step audits, perform forced password changes, and download reports.

### Automated Unit Test Suite
```bash
pytest tests/
```
