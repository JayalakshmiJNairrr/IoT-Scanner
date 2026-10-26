# 🛡️ Abstract Default Credential and Weak Authentication Scanner for Simulated IoT Devices

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-green.svg)](https://www.python.org/)
[![UI: Zero--Dependency](https://img.shields.io/badge/UI-Vanilla--JS%20%2B%20SVG-indigo.svg)](#interactive-web-dashboard)
[![Security: Educational](https://img.shields.io/badge/Security-Educational--Research-red.svg)](#security-context)

A lightweight security scanning and simulation toolkit that identifies IoT sensors, cameras, gateways, and smart home devices configured with weak or factory default credentials — a primary attack vector for real-world IoT botnets like **Mirai**, **Hajime**, and **Mozi**.

---

## 📌 Features

- **⚡ Multi-Protocol IoT Device Simulators**: TCP servers mimicking HTTP Cameras (`IPCam-2000`), Telnet Routers (`DD-WRT`), TCP JSON Sensors (`SmartSense`), and REST Smart Bulbs (`SmartPlug-X1`).
- **🎯 Curated Mirai & OWASP Wordlist**: Includes top-50 default username/password pairs ranked by real-world botnet prevalence.
- **🚀 Multi-Threaded Credential Scanner**: Thread-pool scanner supporting banner fingerprinting, rate limiting, and exponential backoff retry detection.
- **📊 Quantitative Risk Rubric**: Scores devices from `0` (Lowest Risk) to `10` (Critical Risk) based on credential rank, time-to-crack, and lockout policies.

- **📈 Self-Contained HTML/PDF Report Generator**: Generates standalone reports featuring embedded Matplotlib charts (Risk Donut, Protocol Bar, Crack-Time Histogram, Attempts CDF, and Hardening Comparison).
- **🧪 Unit Test Suite**: Includes automated unit tests verifying device socket response, rate limiting, and credential scanner functions.

---

## 📁 Repository Structure

```
iot_scanner/
├── devices/              # Simulated IoT Victim Servers
│   ├── device_base.py    # Base TCP server with attempt logging & lockout logic
│   ├── camera_sim.py     # HTTP IPCam authentication server
│   ├── router_sim.py     # Telnet Router interactive prompt server
│   ├── sensor_sim.py     # JSON-TCP IoT sensor server
│   └── smartplug_sim.py  # REST Smart Bulb API server
├── network/              # Virtual Network Orchestrator
│   ├── launch_network.py # Spawns N device threads (Normal vs. Hardened twins)
│   └── network_config.json # Device registry (ports 9001-9008)
├── scanner/              # Core Security Audit Engine
│   ├── cred_list.py      # Wordlist loader & password pattern analyzer
│   ├── scanner_core.py   # Multi-threaded dictionary scanner
│   └── risk_report.py    # Analytical engine & priority risk rubric
├── data/
│   └── iot_default_creds.txt # Curated default credentials (Mirai/SecLists)
├── report/               # Reporting & Visualizations
│   ├── generate_report.py  # Matplotlib base64 HTML report builder
│   └── templates/
│       └── index.html    # Interactive Web Control Center & Wokwi Circuit UI
├── docs/                 # Research Documentation
│   └── TECHNICAL_REPORT.md # Academic research paper & methodology
├── tests/                # Automated Test Suite
│   ├── test_devices.py   # Unit tests for TCP device servers
│   └── test_scanner.py   # Unit tests for scanner core & rubric
├── main.py               # Unified CLI Pipeline Entrypoint
├── web_server.py         # Zero-dependency REST API & Web Server
├── requirements.txt      # Python dependencies
└── README.md             # Project documentation
```

---

## 🚀 Quick Start & Usage

### 1. Installation
Clone the repository and install the optional plotting dependencies:
```bash
git clone file:///home/jayalakshmi-j-nair/iot_scanner.git
cd iot_scanner
pip install -r requirements.txt
```

### 2. Command Line Interface (CLI)
Run the complete end-to-end audit pipeline via `main.py`:
```bash
# Execute complete pipeline: Launch -> Scan -> Generate Report
python3 main.py --all

# Or run individual modules:
python3 main.py --launch     # Spin up virtual IoT devices
python3 main.py --scan       # Run credential scanner
python3 main.py --report     # Generate HTML report with charts
```

### 3. Interactive Web Control Center
Launch the zero-dependency REST API server and open the UI:
```bash
python3 web_server.py
```
Open **[http://localhost:5000](http://localhost:5000)** in your browser to:
1. Toggle the simulated IoT network ON/OFF with animated wire handshakes.
2. Switch to **📹 Smart Camera Focus View** for full-screen camera testing.
3. Perform **Forced Password Changes** and verify brute-force defense re-audits.
4. Download the final HTML security evaluation report.

### 4. Running Tests
Run the test suite with `pytest`:
```bash
pytest tests/
```

---

## 📊 Analytical Risk Rubric

| Risk Score | Level | Trigger Condition |
|---|---|---|
| **10 / 10** | 🔴 CRITICAL | Cracked using Top-5 default credential (`admin/admin`, `root/root`) |
| **9 / 10** | 🔴 CRITICAL | Cracked using empty password (`root/""`) |
| **8 / 10** | 🟠 HIGH | Cracked using Top-20 credential (`admin/12345`) |
| **7 / 10** | 🟠 HIGH | Lockout triggered but bypassed via timed retry |
| **6 / 10** | 🟠 HIGH | Cracked after 20+ dictionary attempts |
| **4 / 10** | 🟡 MEDIUM | Not cracked, but no account lockout policy active |
| **2 / 10** | 🟢 LOW | Not cracked & account lockout active after 5 failures |

---

## 🛡 Security Context & Disclaimer

This project is strictly for **educational, academic research, and defensive evaluation purposes**. All device simulators and scanner routines operate exclusively on `127.0.0.1` (localhost) ports (`9001–9008`). It does not contain exploit payloads for non-simulated infrastructure.

---

## 📜 License

Distributed under the [MIT License](LICENSE).
