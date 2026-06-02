import sys
import os

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
from modules.traceroute import run_traceroute
from modules.subnet_calc import calculate_subnet


class NetworkScannerGUI(QWidget):

    def __init__(self):
        super().__init__()

        self.report_data = ""

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

        dashboard.addWidget(self.create_card("INTERNET", self.internet_value), 0, 0)
        dashboard.addWidget(self.create_card("DNS", self.dns_value), 0, 1)
        dashboard.addWidget(self.create_card("DEVICES", self.devices_value), 0, 2)
        dashboard.addWidget(self.create_card("HEALTH", self.score_value), 0, 3)

        main_layout.addLayout(dashboard)

        self.progress = QProgressBar()
        self.progress.setValue(0)
        main_layout.addWidget(self.progress)

        btn_layout = QHBoxLayout()

        self.scan_button = QPushButton("Run Full Scan")
        self.scan_button.clicked.connect(self.run_scan)

        self.export_button = QPushButton("Export Report")
        self.export_button.clicked.connect(self.export_report)

        btn_layout.addWidget(self.scan_button)
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

    def log(self, text):
        self.output_box.append(text)
        self.report_data += text + "\n"

    def run_scan(self):

        target = self.target_input.text().strip()

        if not target:
            target = get_gateway()

        self.output_box.clear()
        self.report_data = ""
        self.progress.setValue(0)

        self.log("=" * 60)
        self.log("JUST-JD NETWORK SCANNING TOOL v2.2")
        self.log("=" * 60)

        ping_result = check_ping(target)
        self.log("\nPING TEST")
        self.log(ping_result)

        self.internet_value.setText(
            "ONLINE" if "Reachable" in ping_result else "OFFLINE"
        )

        self.progress.setValue(10)

        if any(c.isalpha() for c in target):

            dns_result = resolve_domain(target)

        else:

            dns_result = "IP Target - DNS Skipped"
        self.log("\nDNS TEST")
        self.log(dns_result)

        if "->" in dns_result:

            self.dns_value.setText("OK")

        elif "Skipped" in dns_result:

            self.dns_value.setText("N/A")

        else:

            self.dns_value.setText("FAIL")

        self.progress.setValue(20)

        local_ip = get_local_ip()

        self.log("\nLOCAL IP")
        self.log(local_ip)

        self.progress.setValue(30)

        gateway = get_gateway()

        self.log("\nDEFAULT GATEWAY")
        self.log(gateway)

        self.progress.setValue(40)

        loss = packet_loss_test(target)

        self.log("\nPACKET LOSS TEST")
        self.log(f"Packet Loss: {loss}")

        self.progress.setValue(50)

        self.log("\nDEVICE DISCOVERY")

        try:
            network = ".".join(local_ip.split(".")[:3]) + ".0/24"
            devices = scan_network(network)

            for device in devices:
                self.log(f"IP: {device['ip']} | MAC: {device['mac']}")

            self.log(f"\nTotal Devices Found: {len(devices)}")
            self.devices_value.setText(str(len(devices)))

        except Exception as e:
            self.log(str(e))

        self.progress.setValue(65)

        self.log("\nSUBNET ANALYSIS")

        try:
            cidr = get_cidr()

            subnet = calculate_subnet(local_ip, cidr)

            self.log(f"Network ID : {subnet['network_id']}")
            self.log(f"Broadcast : {subnet['broadcast']}")
            self.log(f"Usable Hosts : {subnet['total_hosts']}")
            self.log(f"CIDR : {subnet['cidr']}")

        except Exception as e:
            self.log(str(e))

        self.progress.setValue(75)

        self.log("\nPORT SCAN")

        ports = [22, 80, 443, 445, 3389]
        open_ports = 0

        for port in ports:
            status = scan_port(target, port)

            self.log(f"Port {port}: {status}")

            if status == "OPEN":
                open_ports += 1

        self.log(f"\nOpen Ports Found: {open_ports}")

        self.progress.setValue(90)

        self.log("\nTRACEROUTE")

        trace = run_traceroute(target)

        if trace:
            self.log(trace[:5000])
        else:
            self.log("Traceroute Failed")

        self.progress.setValue(95)

        score = calculate_score(
            ping_result,
            dns_result,
            open_ports
        )

        self.log("\nNETWORK HEALTH SCORE")
        self.log(f"{score}/100")

        self.score_value.setText(f"{score}/100")

        self.progress.setValue(100)

    def export_report(self):

        os.makedirs("reports", exist_ok=True)

        path = "reports/scan_report.txt"

        with open(path, "w", encoding="utf-8") as f:
            f.write(self.report_data)

        self.log(f"\nReport Saved: {path}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetworkScannerGUI()
    window.show()
    sys.exit(app.exec())
