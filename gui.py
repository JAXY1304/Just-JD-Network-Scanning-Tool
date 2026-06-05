import sys
import os
import ipaddress
import csv
from datetime import datetime

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer

from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QTextEdit,
    QVBoxLayout, QHBoxLayout, QGridLayout, QFrame,
    QProgressBar, QLineEdit, QSizePolicy
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
from modules.device_events import save_device_event


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
    uptime_signal = pyqtSignal(str)

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
            self.hosts_signal,
            self.uptime_signal
        )

        self.finished_signal.emit()


class NetworkScannerGUI(QWidget):

    def __init__(self):
        super().__init__()

        self.report_data = ""
        
        self.monitor_log_file = "reports/monitor_logs.csv"
        self.previous_devices = {}
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

        self.setWindowTitle("JUST-JD NOC PLATFORM v3.2")
        screen = QApplication.primaryScreen()
        size = screen.availableGeometry()
        self.resize(size.width(), size.height())

        self.setStyleSheet("""
QWidget {
    background-color: #0f172a;
    color: white;
    font-size: 12px;
}

QFrame {
    background-color: #1e293b;
    border-radius: 12px;
}

QPushButton {
    background:#3366dd;
    color:white;
    border:none;
    border-radius:12px;
    font-weight:bold;
    padding:12px;
}

QPushButton:hover {
    background:#4477ff;
}

QTextEdit {
    background-color: #111827;
    border: 1px solid #334155;
    color: #00ff88;
}

QLineEdit {
    background-color: #111827;
    border: 1px solid #334155;
    padding: 10px;
    border-radius: 8px;
}
""")

        main_layout = QVBoxLayout()

        title = QLabel("JUST-JD NOC PLATFORM")
        title.setStyleSheet("font-size:28px;font-weight:bold;color:#00aaff;")
        title.setFixedHeight(45)
        main_layout.addWidget(title)

        main_layout.addWidget(QLabel("Target Host / IP"))

        self.target_input = QLineEdit()
        gateway = get_gateway()
        if gateway and gateway != "Not Found":
            self.target_input.setText(gateway)
        self.target_input.setPlaceholderText("Enter IP or Domain")
        main_layout.addWidget(self.target_input)

        dashboard = QGridLayout()
        dashboard.setHorizontalSpacing(8)
        dashboard.setVerticalSpacing(8)
        dashboard.setContentsMargins(0, 0, 0, 0)

        self.internet_value = QLabel("WAIT")
        self.dns_value = QLabel("WAIT")
        self.devices_value = QLabel("0")
        self.score_value = QLabel("N/A")
        self.risk_value = QLabel("0")
        self.monitored_value = QLabel("0")
        self.alert_value = QLabel("0")
        self.alert_count = 0
        self.hosts_value = QLabel("0")
        self.events_value = QLabel("0")

        self.uptime_value = QLabel("N/A")
        


        dashboard.addWidget(self.create_card("🖥 TOTAL HOSTS", self.hosts_value), 0, 0)
        dashboard.addWidget(self.create_card("🌐 ONLINE HOSTS", self.monitored_value), 0, 1)
        dashboard.addWidget(self.create_card("🚨 ALERTS", self.alert_value), 0, 2)
        dashboard.addWidget(self.create_card("⚠ RISKS", self.risk_value), 0, 3)

        dashboard.addWidget(self.create_card("📈 UPTIME", self.uptime_value), 1, 0)
        dashboard.addWidget(self.create_card("📋 EVENTS", self.events_value), 1, 1)
        dashboard.addWidget(self.create_card("💚 HEALTH", self.score_value), 1, 2)
        dashboard.addWidget(self.create_card("🔍 DEVICES", self.devices_value), 1, 3)

        main_layout.addLayout(dashboard)

        # self.progress = QProgressBar()
        # self.progress.setValue(0)
        # main_layout.addWidget(self.progress)

        btn_layout = QHBoxLayout()

        self.scan_button = QPushButton("🔍 Run Full Scan")
        self.scan_button.clicked.connect(self.run_scan)

        self.monitor_button = QPushButton("▶ Start Monitoring")
        self.monitor_button.clicked.connect(self.start_monitoring)

        self.stop_button = QPushButton("⏹ Stop Monitoring")
        self.stop_button.clicked.connect(self.stop_monitoring)

        self.export_button = QPushButton("📄 Export Report")
        self.export_button.clicked.connect(self.export_report)

        btn_layout.addWidget(self.scan_button)
        btn_layout.addWidget(self.monitor_button)
        btn_layout.addWidget(self.stop_button)
        btn_layout.addWidget(self.export_button)

        main_layout.addLayout(btn_layout)
        
        console_title = QLabel("📡 LIVE MONITORING CONSOLE")
        console_title.setStyleSheet("""
font-size:22px;
font-weight:bold;
color:#33bbff;
""")
        main_layout.addWidget(console_title)

        self.output_box = QTextEdit()
        self.output_box.setStyleSheet("""
QTextEdit{
    background:#04132d;
    color:#00ffae;
    font-family:Consolas;
    font-size:11pt;
    border:1px solid #00bfff;
    border-radius:10px;
    padding:10px;
}
""")
        self.output_box.setReadOnly(True)
        self.output_box.setMinimumHeight(250)
        self.output_box.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Expanding
        )
        main_layout.addWidget(self.output_box, stretch=1)

        self.setLayout(main_layout)

    def create_card(self, title, value_label):
        card = QFrame()
        card.setFixedHeight(90)
        card.setMinimumWidth(250)
        card.setStyleSheet("""
QFrame{
    background:#1b2a44;
    border:1px solid #00bfff;
    border-radius:15px;
}
QFrame:hover{
    border:2px solid #00ffff;
}
""")
        
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        layout = QVBoxLayout()

        t = QLabel(title)
        t.setStyleSheet("font-size:14px;font-weight:bold;color:#00aaff;border:none;")

        value_label.setStyleSheet(
"""
font-size:32px;
font-weight:bold;
color:#00ff88;
border:none;
"""
        )

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
        self.output_box.verticalScrollBar().setValue(
            self.output_box.verticalScrollBar().maximum()
        )

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
        # self.worker.progress_signal.connect(self.progress.setValue)
        self.worker.internet_signal.connect(self.internet_value.setText)
        self.worker.dns_signal.connect(self.dns_value.setText)
        self.worker.devices_signal.connect(self.devices_value.setText)
        self.worker.score_signal.connect(self.score_value.setText)
        self.worker.risk_signal.connect(self.update_risk_card)
        self.worker.hosts_signal.connect(self.hosts_value.setText)
        self.worker.uptime_signal.connect(self.uptime_value.setText)
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
            self.uptime_value.setText(f"{availability:.2f}%")

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
        hosts_signal,
        uptime_signal
    ):

        progress_signal.emit(0)

        log_signal.emit("=" * 60)
        log_signal.emit("JUST-JD NETWORK SCANNING TOOL v3.2")
        log_signal.emit("=" * 60)

        # ── Target Classification ──
        is_private_ip = False
        is_public_ip = False
        is_domain = False

        try:
            ip_obj = ipaddress.ip_address(target)
            if ip_obj.is_private or ip_obj.is_loopback:
                is_private_ip = True
                target_type = "PRIVATE IP"
            else:
                is_public_ip = True
                target_type = "PUBLIC IP"
        except ValueError:
            is_domain = True
            target_type = "DOMAIN"

        log_signal.emit(f"\n🎯 TARGET: {target}")
        log_signal.emit(f"📋 TYPE : {target_type}")

        if is_private_ip:
            log_signal.emit("🔒 MODE : Full Internal Scan (Device Discovery Enabled)")
        else:
            log_signal.emit("🌐 MODE : External Scan (Device Discovery Skipped)")

        ping_result = check_ping(target)
        log_signal.emit("\nPING TEST")
        log_signal.emit(ping_result)

        internet_signal.emit(
            "ONLINE" if "Reachable" in ping_result else "OFFLINE"
        )

        if "Reachable" in ping_result:
            uptime_signal.emit("100%")
        else:
            uptime_signal.emit("0%")

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

        if is_private_ip:
            try:
                cidr = get_cidr()

                network = ipaddress.ip_network(
                f"{local_ip}/{cidr}",
                strict=False
                )

                devices = get_arp_devices()
                
                current_devices = {}

                for device in devices:
                    ip = device["ip"]
                    mac = device["mac"]
                    vendor = device.get("vendor", "Unknown")
                    current_devices[ip] = vendor
                    
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

                new_devices = set(current_devices) - set(self.previous_devices)
                for ip in new_devices:
                    vendor = current_devices[ip]
                    log_signal.emit(f"[NEW DEVICE] {ip} ({vendor})")
                    save_device_event("NEW_DEVICE", ip, vendor)
                    
                lost_devices = set(self.previous_devices) - set(current_devices)
                for ip in lost_devices:
                    vendor = self.previous_devices[ip]
                    log_signal.emit(f"[DEVICE LOST] {ip} ({vendor})")
                    save_device_event("DEVICE_LOST", ip, vendor)
                    
                self.previous_devices = current_devices
                
                save_inventory(devices)

                log_signal.emit(f"\nTotal Devices Found: {len(devices)}")
                devices_signal.emit(str(len(devices)))
                hosts_signal.emit(str(len(devices)))

            except Exception as e:
                log_signal.emit(str(e))
        else:
            log_signal.emit("⏭ Skipped — Device Discovery only runs for Private/Internal IPs")
            log_signal.emit(f"  Reason: Target '{target}' is a {target_type}")
            devices_signal.emit("N/A")
            hosts_signal.emit("N/A")

        progress_signal.emit(65)

        log_signal.emit("\nSUBNET ANALYSIS")

        if is_private_ip:
            try:
                cidr = get_cidr()

                subnet = calculate_subnet(local_ip, cidr)

                log_signal.emit(f"Network ID : {subnet['network_id']}")
                log_signal.emit(f"Broadcast : {subnet['broadcast']}")
                log_signal.emit(f"Usable Hosts : {subnet['total_hosts']}")
                log_signal.emit(f"CIDR : {subnet['cidr']}")

            except Exception as e:
                log_signal.emit(str(e))
        else:
            log_signal.emit("⏭ Skipped — Subnet Analysis only runs for Private/Internal IPs")
            log_signal.emit(f"  Reason: Target '{target}' is a {target_type}")

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
