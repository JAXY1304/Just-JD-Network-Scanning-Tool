import sys

from modules.ping_test import check_ping
from modules.dns_test import resolve_domain
from modules.network_info import get_local_ip
from modules.network_info import get_gateway
from modules.health_score import calculate_score
from modules.packet_loss import packet_loss_test
from modules.port_scan import scan_port
from modules.arp_scan import scan_network
from modules.traceroute import run_traceroute
from modules.subnet_calc import calculate_subnet

from PyQt6.QtWidgets import (
    QApplication,
    QWidget,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout
)


class NetworkScannerGUI(QWidget):

    def __init__(self):
        super().__init__()

        self.setWindowTitle("Just-JD Network Scanning Tool")
        self.resize(900, 600)

        layout = QVBoxLayout()

        title = QLabel("JUST-JD NETWORK SCANNING TOOL")
        title.setStyleSheet(
            "font-size:22px; font-weight:bold;"
        )

        self.scan_button = QPushButton("Run Full Scan")
        self.scan_button.clicked.connect(self.run_scan)

        self.output_box = QTextEdit()
        self.output_box.setReadOnly(True)

        layout.addWidget(title)
        layout.addWidget(self.scan_button)
        layout.addWidget(self.output_box)

        self.setLayout(layout)

    def run_scan(self):

        self.output_box.clear()

        self.output_box.append("JUST-JD NETWORK SCANNING TOOL")
        self.output_box.append("=" * 50)

        # Ping Test
        ping_result = check_ping("8.8.8.8")

        self.output_box.append("\nPING TEST")
        self.output_box.append(ping_result)

        # DNS Test
        dns_result = resolve_domain("google.com")

        self.output_box.append("\nDNS TEST")
        self.output_box.append(dns_result)

        # Local IP
        local_ip = get_local_ip()

        self.output_box.append("\nLOCAL IP")
        self.output_box.append(local_ip)

        # Gateway
        gateway = get_gateway()

        self.output_box.append("\nDEFAULT GATEWAY")
        self.output_box.append(gateway)

        # Packet Loss
        loss = packet_loss_test("8.8.8.8")

        self.output_box.append("\nPACKET LOSS TEST")
        self.output_box.append(f"Packet Loss: {loss}")

        # Device Discovery
        self.output_box.append("\nDEVICE DISCOVERY")

        try:
            devices = scan_network("192.168.2.0/24")

            for device in devices:
                self.output_box.append(
                    f"IP: {device['ip']} | MAC: {device['mac']}"
                )

            self.output_box.append(
                f"\nTotal Devices Found: {len(devices)}"
            )

        except Exception as e:
            self.output_box.append(str(e))

        # Subnet Analysis
        self.output_box.append("\nSUBNET ANALYSIS")

        subnet_info = calculate_subnet("192.168.2.91", 24)

        self.output_box.append(
            f"Network ID   : {subnet_info['network_id']}"
        )

        self.output_box.append(
            f"Broadcast IP : {subnet_info['broadcast']}"
        )

        self.output_box.append(
            f"Usable Hosts : {subnet_info['total_hosts']}"
        )

        self.output_box.append(
            f"CIDR         : {subnet_info['cidr']}"
        )

        # Port Scan
        self.output_box.append("\nPORT SCAN")

        ports = [22, 80, 443, 445, 3389]
        open_ports = 0

        for port in ports:

            status = scan_port("google.com", port)

            self.output_box.append(
                f"Port {port}: {status}"
            )

            if status == "OPEN":
                open_ports += 1

        self.output_box.append(
            f"\nOpen Ports Found: {open_ports}"
        )

        # Traceroute Summary
        self.output_box.append("\nTRACEROUTE")

        trace = run_traceroute("8.8.8.8")

        if "Trace complete" in trace:
            self.output_box.append(
                "Destination Reached Successfully"
            )
        else:
            self.output_box.append(
                "Traceroute Completed"
            )

        # Health Score
        score = calculate_score(
            ping_result,
            dns_result,
            open_ports
        )

        self.output_box.append("\nNETWORK HEALTH SCORE")
        self.output_box.append(f"{score}/100")


app = QApplication(sys.argv)

window = NetworkScannerGUI()
window.show()

sys.exit(app.exec())