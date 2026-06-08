# JUST-JD NOC Platform v3.3

A modern Network Operations Center (NOC) and Network Monitoring Platform built using Python and PyQt6.

The platform provides real-time network monitoring, device discovery, inventory management, port scanning, traceroute analysis, event logging, and health assessment through an interactive dashboard.

---

## Features

### Network Diagnostics

- Ping Test
- DNS Resolution
- Packet Loss Analysis
- Local IP Detection
- Default Gateway Detection
- Traceroute Analysis
- Port Scanning
- Network Health Score

---

### Internal Network Discovery

- ARP-Based Device Discovery
- Vendor Detection using MAC Address
- Subnet Analysis
- Host Enumeration
- Internal Network Visibility

---

### External Network Analysis

- Public IP Scanning
- Domain Analysis
- DNS Resolution
- Traceroute to Remote Hosts
- Open Port Detection

---

### Monitoring Features

- Real-Time Monitoring
- Availability Tracking
- Historical Monitoring Logs
- Device Event Tracking
- Alert Generation
- Continuous Host Monitoring

---

### Asset Management

- Asset Inventory
- Device Inventory Tracking
- Host Management
- Device Record Storage

---

### Reporting

- TXT Report Export
- CSV Event Logging
- Historical Monitoring Reports
- Scan Summary Generation

---

### Dashboard Features

- Modern PyQt6 Interface
- Live Monitoring Console
- Health Dashboard
- Alert Dashboard
- Device Statistics
- Uptime Tracking
- Event Statistics

---

## Screenshots

### Dashboard

<img width="1915" height="1020" alt="image" src="https://github.com/user-attachments/assets/d5898b70-72ce-44e0-8be4-a3d4287f3625" />


### Live Monitoring
<img width="1907" height="971" alt="image" src="https://github.com/user-attachments/assets/59c8d0f6-4d72-4d93-a827-3d05a11b737a" />


### Scan Results

<img width="1453" height="522" alt="image" src="https://github.com/user-attachments/assets/60c22376-80c3-4904-95d3-49b2999f41c1" />


---

## Scan Modes

### Internal Network Scan

When a Private/Internal IP Address is provided:

- Device Discovery Enabled
- ARP Scanning Enabled
- Vendor Detection Enabled
- Subnet Analysis Enabled

Example:

```text
192.168.1.1
10.0.0.1
172.16.1.1
```

---

### External Scan

When a Public IP or Domain is provided:

- Device Discovery Skipped
- Subnet Analysis Skipped
- External Port Scan
- DNS Analysis
- Traceroute Analysis

Example:

```text
8.8.8.8
103.240.34.98
example.com
google.com
```

---

## Technologies Used

### Core Technologies

- Python 3
- PyQt6
- Socket
- Subprocess
- ipaddress
- CSV

### Networking Libraries

- Scapy
- Ping3
- Mac Vendor Lookup

### Operating System Support

- Windows
- Ubuntu
- Debian
- Kali Linux

---

## Requirements

### Windows

- Python 3.10+
- Npcap (Required for Device Discovery)

Download:

https://npcap.com

---

### Linux

Required Packages:

```bash
sudo apt update

sudo apt install python3 python3-pyqt6 traceroute net-tools -y
```

---

### Python Dependencies

```bash
pip install PyQt6
pip install scapy
pip install ping3
pip install mac-vendor-lookup
```

or

```bash
pip install -r requirements.txt
```

---

## Installation

### Clone Repository

```bash
git clone https://github.com/JAXY1304/Just-JD-Network-Scanning-Tool.git

cd Just-JD-Network-Scanning-Tool
```

---

### Run From Source

```bash
python gui.py
```

---

## Windows Installation

Download the latest:

```text
gui.exe
```

from GitHub Releases and run directly.

No installation required.

---

## Linux Installation

Install Debian Package:

```bash
sudo dpkg -i justjdnoc_3.3.deb
```

Launch:

```bash
justjdnoc
```

---

## Project Structure

```text
Just-JD-Network-Scanning-Tool
│
├── gui.py
├── main.py
├── README.md
├── LICENSE
│
├── modules
│   ├── arp_scan.py
│   ├── device_events.py
│   ├── dns_test.py
│   ├── health_score.py
│   ├── inventory.py
│   ├── monitor.py
│   ├── network_discovery.py
│   ├── network_info.py
│   ├── packet_loss.py
│   ├── ping_test.py
│   ├── port_scan.py
│   ├── security_check.py
│   ├── subnet_calc.py
│   └── traceroute.py
│
└── reports
    └── scan_report.txt
```

---

## Current Version

```text
Version: v3.3
```

Latest Improvements:

- Modern NOC Dashboard
- Public IP Detection Logic
- Domain Detection Logic
- Smart Scan Mode Selection
- Device Discovery Control
- Asset Inventory
- Historical Monitoring
- Device Event Logging
- Linux Package Support
- Windows Executable Support

---

## Future Roadmap (v4.0)

- PDF Report Export
- HTML Report Export
- Email Alerts
- Multi Host Monitoring
- SNMP Monitoring
- Syslog Collection
- Wazuh Integration
- Dark/Light Theme Support
- Scheduled Scans
- Vulnerability Scanning Module

---

## Author

**Jay Soni**

Cybersecurity | SOC Analyst | Network Security

GitHub:
https://github.com/JAXY1304

---

## License

This project is licensed under the MIT License.

See the LICENSE file for details.

---

## Disclaimer

This tool is intended for:

- Network Monitoring
- Asset Visibility
- Internal Network Diagnostics
- Security Assessment
- Educational Purposes

Only scan systems and networks that you own or have explicit authorization to assess.

Unauthorized scanning may violate local laws, regulations, or organizational policies.
