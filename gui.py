import sys
import os

from PyQt6.QtWidgets import (
    QApplication,
    QWidget,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QFrame,
    QProgressBar,
    QFileDialog
)

from modules.ping_test import check_ping
from modules.dns_test import resolve_domain
from modules.network_info import get_local_ip, get_gateway
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

        self.setWindowTitle("Just-JD Network Scanning Tool")
        self.resize(1200, 800)

        self.setStyleSheet("""
        QWidget {
            background-color: #1e1e1e;
            color: white;
        }

        QPushButton {
            background-color: #0078d7;
            color: white;
            padding: 10px;
            border-radius: 5px;
            font-size: 14px;
        }

        QPushButton:hover {
            background-color: #005fa3;
        }

        QTextEdit {
            background-color: #2b2b2b;
            color: white;
            font-family: Consolas;
            font-size: 12px;
        }

        QProgressBar {
            border: 1px solid #444;
            border-radius: 5px;
            text-align: center;
        }

        QProgressBar::chunk {
            background-color: #00aa55;
        }

        QFrame {
            background-color: #2b2b2b;
            border: 1px solid #444;
            border-radius: 10px;
        }
        """)

        main_layout = QVBoxLayout()

        title = QLabel("JUST-JD NETWORK SCANNING TOOL")
        title.setStyleSheet("""
            font-size:28px;
            font-weight:bold;
            color:#00aaff;
        """)
        main_layout.addWidget(title)

        # Dashboard Cards
        dashboard = QGridLayout()

        self.internet_value = QLabel("WAIT")
        self.dns_value = QLabel("WAIT")
        self.devices_value = QLabel("0")
        self.score_value = QLabel("0/100")

        dashboard.addWidget(
            self.create_card("INTERNET", self.internet_value),
            0, 0
        )

        dashboard.addWidget(
            self.create_card("DNS", self.dns_value),
            0, 1
        )

        dashboard.addWidget(
            self.create_card("DEVICES", self.devices_value),
            0, 2
        )

        dashboard.addWidget(
            self.create_card("HEALTH", self.score_value),
            0, 3
        )

        main_layout.addLayout(dashboard)

        # Progress Bar
        self.progress = QProgressBar()
        self.progress.setValue(0)
        main_layout.addWidget(self.progress)

        # Buttons
        button_layout = QHBoxLayout()

        self.scan_button = QPushButton("Run Full Scan")
        self.scan_button.clicked.connect(self.run_scan)

        self.export_button = QPushButton("Export Report")
        self.export_button.clicked.connect(self.export_report)

        button_layout.addWidget(self.scan_button)
        button_layout.addWidget(self.export_button)

        main_layout.addLayout(button_layout)

        # Output
        self.output_box = QTextEdit()
        self.output_box.setReadOnly(True)
        main_layout.addWidget(self.output_box)

        self.setLayout(main_layout)

    def create_card(self, title, value_label):

        card = QFrame()

        layout = QVBoxLayout()

        title_label = QLabel(title)
        title_label.setStyleSheet("""
            color:#00aaff;
            font-size:14px;
            font-weight:bold;
            border:none;
        """)

        value_label.setStyleSheet("""
            color:#00ff88;
            font-size:22px;
            font-weight:bold;
            border:none;
        """)

        layout.addWidget(title_label)
        layout.addWidget(value_label)

        card.setLayout(layout)

        return card

    def log(self, text):
        self.output_box.append(text)
        self.report_data += text + "\n"

    def run_scan(self):

        self.output_box.clear()
        self.report_data = ""

        self.progress.setValue(0)

        self.log("=" * 60)
        self.log("JUST-JD NETWORK SCANNING TOOL")
        self.log("=" * 60)

        # Ping
        ping_result = check_ping("8.8.8.8")

        self.log("\nPING TEST")
        self.log(ping_result)

        if "Reachable" in ping_result:
            self.internet_value.setText("ONLINE")
        else:
            self.internet_value.setText("OFFLINE")

        self.progress.setValue(10)

        # DNS
        dns_result = resolve_domain("google.com")

        self.log("\nDNS TEST")
        self.log(dns_result)

        if "->" in dns_result:
            self.dns_value.setText("OK")
        else:
            self.dns_value.setText("FAIL")

        self.progress.setValue(20)

        # Local IP
        self.log("\nLOCAL IP")
        self.log(get_local_ip())

        self.progress.setValue(30)

        # Gateway
        self.log("\nDEFAULT GATEWAY")
        self.log(get_gateway())

        self.progress.setValue(40)

        # Packet Loss
        loss = packet_loss_test("8.8.8.8")

        self.log("\nPACKET LOSS TEST")
        self.log(f"Packet Loss: {loss}")

        self.progress.setValue(50)

        # Devices
        self.log("\nDEVICE DISCOVERY")

        try:
            devices = scan_network("192.168.2.0/24")

            for device in devices:
                self.log(
                    f"IP: {device['ip']} | MAC: {device['mac']}"
                )

            self.log(
                f"\nTotal Devices Found: {len(devices)}"
            )

            self.devices_value.setText(
                str(len(devices))
            )

        except Exception as e:
            self.log(str(e))

        self.progress.setValue(60)

        # Subnet
        self.log("\nSUBNET ANALYSIS")

        subnet = calculate_subnet(
            "192.168.2.91",
            24
        )

        self.log(
            f"Network ID : {subnet['network_id']}"
        )

        self.log(
            f"Broadcast : {subnet['broadcast']}"
        )

        self.log(
            f"Usable Hosts : {subnet['total_hosts']}"
        )

        self.log(
            f"CIDR : {subnet['cidr']}"
        )

        self.progress.setValue(70)

        # Ports
        self.log("\nPORT SCAN")

        ports = [22, 80, 443, 445, 3389]

        open_ports = 0

        for port in ports:

            status = scan_port(
                "google.com",
                port
            )

            self.log(
                f"Port {port}: {status}"
            )

            if status == "OPEN":
                open_ports += 1

        self.log(
            f"\nOpen Ports Found: {open_ports}"
        )

        self.progress.setValue(85)

        # Traceroute
        self.log("\nTRACEROUTE")

        trace = run_traceroute("8.8.8.8")

        if "Trace complete" in trace:
            self.log(
                "Destination Reached Successfully"
            )
        else:
            self.log(
                "Traceroute Completed"
            )

        self.progress.setValue(95)

        # Health Score
        score = calculate_score(
            ping_result,
            dns_result,
            open_ports
        )

        self.log("\nNETWORK HEALTH SCORE")
        self.log(f"{score}/100")

        self.score_value.setText(
            f"{score}/100"
        )

        self.progress.setValue(100)

    def export_report(self):

        os.makedirs("reports", exist_ok=True)

        path = "reports/scan_report.txt"

        with open(path, "w", encoding="utf-8") as f:
            f.write(self.report_data)

        self.log(
            f"\nReport Saved: {path}"
        )


if __name__ == "__main__":

    app = QApplication(sys.argv)

    window = NetworkScannerGUI()
    window.show()

    sys.exit(app.exec())