import sys
import os
import ipaddress
import csv
from datetime import datetime

from PyQt6.QtCore import QThread, pyqtSignal, QTimer

from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QTextEdit,
    QVBoxLayout, QHBoxLayout, QGridLayout, QFrame,
    QProgressBar, QLineEdit
)

from modules.ping_test import check_ping
from modules.dns_test import resolve_domain
from modules.network_info import get_local_ip, get_gateway, get_cidr
from modules.health_score import calculate_score
from modules.packet_loss import packet_loss_test
from modules.port_scan import scan_port
from modules.arp_scan import scan_network
from modules.network_discovery import get_arp_devices
from modules.security_check import analyze_port
from modules.traceroute import run_traceroute
from modules.subnet_calc import calculate_subnet
from modules.monitor import monitor_host
from modules.inventory import save_inventory


class ScanWorker(QThread):

    log_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)
    finished_signal = pyqtSignal()

    # Safety signals for updating UI labels from background thread
    internet_signal = pyqtSignal(str)
    dns_signal = pyqtSignal(str)
    devices_signal = pyqtSignal(str)
    score_signal = pyqtSignal(str)
    risk_signal = pyqtSignal(str)
    hosts_signal = pyqtSignal(str)

    def __init__(self, gui, target):
        super().__init__()
        self.gui = gui
        self.target = target

    def run(self):
        self.gui.perform_scan(
            self.target,
            self.log_signal,
            self.progress_signal,
            self.internet_signal,
            self.dns_signal,
            self.devices_signal,
            self.score_signal,
            self.risk_signal,
            self.hosts_signal
        )

        self.finished_signal.emit()


class NetworkScannerGUI(QWidget):

    def __init__(self):
        super().__init__()

        self.report_data = ""
        
        self.monitor_log_file = "reports/monitor_logs.csv"
        self.previous_devices = set()
        self.alert_file = "reports/alerts.csv"
        self.mac_history = {}
        self.total_checks = 0
        self.online_checks = 0
        self.offline_checks = 0

        self.monitor_timer = QTimer()

        self.monitor_timer.timeout.connect(
            self.run_monitor_check
        )

        self.monitored_hosts = []

        self.setWindowTitle("Just-JD Network Scanning Tool v2.2")
        self.resize(1200, 800)

        self.setStyleSheet("""
        QWidget { background-color:#1e1e1e; color:white; }
        QPushButton {
            background-color:#0078d7;
            color:white;
            padding:10px;
            border-radius:5px;
        }
        QTextEdit {
            background-color:#2b2b2b;
            color:white;
        }
        QFrame {
            background-color:#2b2b2b;
            border:1px solid #444;
            border-radius:10px;
        }
        """)

        main_layout = QVBoxLayout()

        title = QLabel("JUST-JD NETWORK SCANNING TOOL")
        title.setStyleSheet("font-size:28px;font-weight:bold;color:#00aaff;")
        main_layout.addWidget(title)

        main_layout.addWidget(QLabel("Target Host / IP"))

        self.target_input = QLineEdit()
        gateway = get_gateway()
        if gateway and gateway != "Not Found":
            self.target_input.setText(gateway)
        self.target_input.setPlaceholderText("Enter IP or Domain")
        main_layout.addWidget(self.target_input)

        dashboard = QGridLayout()

        self.internet_value = QLabel("WAIT")
        self.dns_value = QLabel("WAIT")
        self.devices_value = QLabel("0")
        self.score_value = QLabel("0/100")
        self.risk_value = QLabel("0")
        self.monitored_value = QLabel("0")
        self.alert_value = QLabel("0")
        self.alert_count = 0
        self.hosts_value = QLabel("0")

        dashboard.addWidget(self.create_card("INTERNET", self.internet_value), 0, 0)
        dashboard.addWidget(self.create_card("DNS", self.dns_value), 0, 1)
        dashboard.addWidget(self.create_card("DEVICES", self.devices_value), 0, 2)
        dashboard.addWidget(self.create_card("RISKS", self.risk_value), 0, 3)
        dashboard.addWidget(self.create_card("MONITORED", self.monitored_value), 0, 4)
        dashboard.addWidget(self.create_card("ALERTS", self.alert_value), 0, 5)
        dashboard.addWidget(self.create_card("HOSTS", self.hosts_value), 0, 6)
        dashboard.addWidget(self.create_card("HEALTH", self.score_value), 0, 7)

        main_layout.addLayout(dashboard)

        self.progress = QProgressBar()
        self.progress.setValue(0)
        main_layout.addWidget(self.progress)

        btn_layout = QHBoxLayout()

        self.scan_button = QPushButton("Run Full Scan")
        self.scan_button.clicked.connect(self.run_scan)

        self.monitor_button = QPushButton(
            "Start Monitoring"
        )

        self.monitor_button.clicked.connect(
            self.start_monitoring
        )

        self.stop_monitor_button = QPushButton(
            "Stop Monitoring"
        )

        self.stop_monitor_button.clicked.connect(
            self.stop_monitoring
        )

        self.export_button = QPushButton("Export Report")
        self.export_button.clicked.connect(self.export_report)

        btn_layout.addWidget(self.scan_button)
        btn_layout.addWidget(
            self.monitor_button
        )
        btn_layout.addWidget(
            self.stop_monitor_button
        )
        btn_layout.addWidget(self.export_button)

        main_layout.addLayout(btn_layout)

        self.output_box = QTextEdit()
        self.output_box.setReadOnly(True)
        main_layout.addWidget(self.output_box)

        self.setLayout(main_layout)

    def create_card(self, title, value_label):
        card = QFrame()
        layout = QVBoxLayout()

        t = QLabel(title)
        t.setStyleSheet("font-size:14px;font-weight:bold;color:#00aaff;border:none;")

        value_label.setStyleSheet("font-size:22px;font-weight:bold;color:#00ff88;border:none;")

        layout.addWidget(t)
        layout.addWidget(value_label)
        card.setLayout(layout)

        return card

    def save_monitor_log(self, host, status):
        os.makedirs("reports", exist_ok=True)
        file_exists = os.path.isfile(self.monitor_log_file)
        with open(self.monitor_log_file, "a", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            if not file_exists:
                writer.writerow(["TIME", "HOST", "STATUS"])
            writer.writerow([datetime.now().strftime("%H:%M:%S"), host, status])

    def save_alert(self, host, alert):
        os.makedirs("reports", exist_ok=True)
        with open(self.alert_file, "a", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow([datetime.now().strftime("%H:%M:%S"), host, alert])

    def log(self, text):
        self.output_box.append(text)
        self.report_data += text + "\n"

    def run_scan(self):

        self.output_box.clear()
        self.report_data = ""
        self.update_risk_card("0")

        self.scan_button.setEnabled(False)

        target = self.target_input.text().strip()
        if not target:
            target = get_gateway()

        self.worker = ScanWorker(self, target)

        self.worker.log_signal.connect(self.log)
        self.worker.progress_signal.connect(self.progress.setValue)
        self.worker.internet_signal.connect(self.internet_value.setText)
        self.worker.dns_signal.connect(self.dns_value.setText)
        self.worker.devices_signal.connect(self.devices_value.setText)
        self.worker.score_signal.connect(self.score_value.setText)
        self.worker.risk_signal.connect(self.update_risk_card)
        self.worker.hosts_signal.connect(self.hosts_value.setText)
        self.worker.finished_signal.connect(self.scan_finished)

        self.worker.start()

    def scan_finished(self):

        self.scan_button.setEnabled(True)
        self.log("\nSCAN COMPLETED")

    def update_risk_card(self, risk_count_str):

        self.risk_value.setText(risk_count_str)

        try:
            risk_count = int(risk_count_str)
        except ValueError:
            risk_count = 0

        if risk_count == 0:
            self.risk_value.setStyleSheet(
                "font-size:22px;font-weight:bold;color:#00ff88;border:none;"
            )

        elif risk_count <= 2:
            self.risk_value.setStyleSheet(
                "font-size:22px;font-weight:bold;color:#ffaa00;border:none;"
            )

        else:
            self.risk_value.setStyleSheet(
                "font-size:22px;font-weight:bold;color:#ff4444;border:none;"
            )

    def start_monitoring(self):

        target = self.target_input.text().strip()

        if not target:
            return

        self.monitored_hosts = [target]

        self.monitored_value.setText(
            str(len(self.monitored_hosts))
        )

        self.alert_count = 0

        self.alert_value.setText("0")

        self.update_alert_color()

        self.monitor_timer.start(5000)

        self.log(
            f"\nMonitoring Started: {target}"
        )

    def stop_monitoring(self):

        self.monitor_timer.stop()

        self.monitored_hosts = []

        self.monitored_value.setText("0")

        self.log(
            "\nMonitoring Stopped"
        )

    def run_monitor_check(self):

        current_time = datetime.now().strftime(
            "%H:%M:%S"
        )

        for host in self.monitored_hosts:

            status = monitor_host(host)

            if status:
                self.total_checks += 1
                self.online_checks += 1
                self.save_monitor_log(host, "ONLINE")

                self.log(
                    f"\n[MONITOR] {host} ONLINE"
                )

                self.log(
                    f"Time: {current_time}"
                )

            else:
                self.total_checks += 1
                self.offline_checks += 1
                self.save_monitor_log(host, "OFFLINE")
                self.save_alert(host, "OFFLINE")

                QApplication.beep()

                self.alert_count += 1

                self.alert_value.setText(
                    str(self.alert_count)
                )

                self.update_alert_color()

                self.log(
                    f"\n[ALERT] {host} OFFLINE"
                )

                self.log(
                    f"Time: {current_time}"
                )
                
        if self.total_checks > 0:
            availability = (self.online_checks / self.total_checks) * 100
            self.log(f"Availability: {availability:.2f}%")

    def update_alert_color(self):

        if self.alert_count == 0:

            self.alert_value.setStyleSheet(
                "font-size:22px;font-weight:bold;color:#00ff88;border:none;"
            )

        elif self.alert_count <= 2:

            self.alert_value.setStyleSheet(
                "font-size:22px;font-weight:bold;color:#ffaa00;border:none;"
            )

        else:

            self.alert_value.setStyleSheet(
                "font-size:22px;font-weight:bold;color:#ff4444;border:none;"
            )

    def perform_scan(
        self,
        target,
        log_signal,
        progress_signal,
        internet_signal,
        dns_signal,
        devices_signal,
        score_signal,
        risk_signal,
        hosts_signal
    ):

        progress_signal.emit(0)

        log_signal.emit("=" * 60)
        log_signal.emit("JUST-JD NETWORK SCANNING TOOL v2.2")
        log_signal.emit("=" * 60)

        ping_result = check_ping(target)
        log_signal.emit("\nPING TEST")
        log_signal.emit(ping_result)

        internet_signal.emit(
            "ONLINE" if "Reachable" in ping_result else "OFFLINE"
        )

        progress_signal.emit(10)

        if any(c.isalpha() for c in target):

            dns_result = resolve_domain(target)

        else:

            dns_result = "IP Target - DNS Skipped"
        log_signal.emit("\nDNS TEST")
        log_signal.emit(dns_result)

        if "->" in dns_result:

            dns_signal.emit("OK")

        elif "Skipped" in dns_result:

            dns_signal.emit("N/A")

        else:

            dns_signal.emit("FAIL")

        progress_signal.emit(20)

        local_ip = get_local_ip()

        log_signal.emit("\nLOCAL IP")
        log_signal.emit(local_ip)

        progress_signal.emit(30)

        gateway = get_gateway()

        log_signal.emit("\nDEFAULT GATEWAY")
        log_signal.emit(gateway)

        progress_signal.emit(40)

        loss = packet_loss_test(target)

        log_signal.emit("\nPACKET LOSS TEST")
        log_signal.emit(f"Packet Loss: {loss}")

        progress_signal.emit(50)

        log_signal.emit("\nDEVICE DISCOVERY")

        try:
            cidr = get_cidr()

            network = ipaddress.ip_network(
            f"{local_ip}/{cidr}",
            strict=False
            )

            devices = get_arp_devices()
            
            current_devices = set()

            for device in devices:
                ip = device["ip"]
                mac = device["mac"]
                current_devices.add(ip)
                
                if ip in self.mac_history:
                    old_mac = self.mac_history[ip]
                    if old_mac != mac:
                        log_signal.emit(f"[WARNING] {ip} MAC Changed")
                self.mac_history[ip] = mac

                log_signal.emit(
                    f"IP: {device['ip']} | "
                    f"HOST: {device['hostname']} | "
                    f"MAC: {device['mac']} | "
                    f"VENDOR: {device['vendor']}"
                )

            new_devices = current_devices - self.previous_devices
            for ip in new_devices:
                log_signal.emit(f"[NEW DEVICE] {ip}")
                
            lost_devices = self.previous_devices - current_devices
            for ip in lost_devices:
                log_signal.emit(f"[DEVICE LOST] {ip}")
                
            self.previous_devices = current_devices
            
            save_inventory(devices)

            log_signal.emit(f"\nTotal Devices Found: {len(devices)}")
            devices_signal.emit(str(len(devices)))
            hosts_signal.emit(str(len(devices)))

        except Exception as e:
            log_signal.emit(str(e))

        progress_signal.emit(65)

        log_signal.emit("\nSUBNET ANALYSIS")

        try:
            cidr = get_cidr()

            subnet = calculate_subnet(local_ip, cidr)

            log_signal.emit(f"Network ID : {subnet['network_id']}")
            log_signal.emit(f"Broadcast : {subnet['broadcast']}")
            log_signal.emit(f"Usable Hosts : {subnet['total_hosts']}")
            log_signal.emit(f"CIDR : {subnet['cidr']}")

        except Exception as e:
            log_signal.emit(str(e))

        progress_signal.emit(75)

        log_signal.emit("\nPORT SCAN")

        ports = [22, 80, 443, 445, 3389]
        open_ports = 0
        risk_count = 0
        security_findings = []
        
        risk_table = {
            23: "HIGH",
            21: "HIGH",
            445: "MEDIUM",
            80: "LOW",
            443: "LOW"
        }

        for port in ports:
            if port in risk_table:
                severity = risk_table[port]
                log_signal.emit(f"Risk: {severity}")

            try:
                status = scan_port(
                    target,
                    port
                )

            except Exception as e:
                status = f"ERROR: {e}"

            log_signal.emit(f"Port {port}: {status}")

            if status == "OPEN":

                finding = analyze_port(
                    port,
                    status
                )

                if finding:

                    security_findings.append(
                        (
                            port,
                            finding
                        )
                    )

                    if finding["risk"] in [
                        "HIGH",
                        "WARNING",
                        "MEDIUM"
                    ]:
                        risk_count += 1

                open_ports += 1

        log_signal.emit(f"\nOpen Ports Found: {open_ports}")

        log_signal.emit("\nSECURITY FINDINGS")

        if security_findings:

            for port, finding in security_findings:

                log_signal.emit(
                    f"\n{port}/TCP {finding['service']}"
                )

                log_signal.emit(
                    f"Risk: {finding['risk']}"
                )

                log_signal.emit(
                    f"Reason: {finding['reason']}"
                )

        else:

            log_signal.emit(
                "No risky open ports detected."
            )

        risk_signal.emit(str(risk_count))

        progress_signal.emit(90)

        log_signal.emit("\nTRACEROUTE")

        try:
            trace = run_traceroute(target)
        except Exception as e:
            trace = f"Traceroute Error: {e}"

        if trace:
            log_signal.emit(trace[:5000])
        else:
            log_signal.emit("Traceroute Failed")

        progress_signal.emit(95)

        score = calculate_score(
            ping_result,
            dns_result,
            open_ports
        )

        log_signal.emit("\nNETWORK HEALTH SCORE")
        log_signal.emit(f"{score}/100")

        score_signal.emit(f"{score}/100")

        progress_signal.emit(100)

    def export_report(self):

        os.makedirs("reports", exist_ok=True)

        path = "reports/scan_report.txt"

        with open(path, "w", encoding="utf-8") as f:
            f.write(self.report_data)

        self.log(f"\nReport Saved: {path}")
        self.log("Professional Report Pack Saved")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetworkScannerGUI()
    window.show()
    sys.exit(app.exec())
