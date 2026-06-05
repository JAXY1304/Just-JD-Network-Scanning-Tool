import socket
import ipaddress

from modules.ping_test import check_ping
from modules.dns_test import resolve_domain
from modules.network_info import get_local_ip
from modules.network_info import get_gateway
from modules.network_info import get_cidr
from modules.health_score import calculate_score
from modules.port_scan import scan_port
from modules.traceroute import run_traceroute
from modules.packet_loss import packet_loss_test
from modules.arp_scan import scan_network
from modules.subnet_calc import calculate_subnet

print("=" * 50)
print("JUST-JD NETWORK SCANNING TOOL v3.2")
print("=" * 50)

# Target = Gateway
target = get_gateway()

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

print(f"\n🎯 TARGET: {target}")
print(f"📋 TYPE : {target_type}")
if is_private_ip:
    print("🔒 MODE : Full Internal Scan (Device Discovery Enabled)")
else:
    print("🌐 MODE : External Scan (Device Discovery Skipped)")

# Ping Test
print("\nPING TEST")

result = check_ping(target)

print(result)

# DNS Test
print("\nDNS TEST")

try:
    socket.inet_aton(target)
    dns_result = "IP Target - DNS Skipped"

except:
    dns_result = resolve_domain(target)

print(dns_result)

# Local IP
print("\nLOCAL IP")

local_ip = get_local_ip()

print(local_ip)

# Gateway
print("\nDEFAULT GATEWAY")

gateway = get_gateway()

print(gateway)

# Traceroute
print("\nTRACEROUTE TEST")

trace_result = run_traceroute(target)

print(trace_result)

# Packet Loss
print("\nPACKET LOSS TEST")

loss = packet_loss_test(target)

print(f"Packet Loss: {loss}")

# Device Discovery
print("\nDEVICE DISCOVERY")

if is_private_ip:
    local_ip = get_local_ip()

    cidr = get_cidr()

    network = ipaddress.ip_network(
        f"{local_ip}/{cidr}",
        strict=False
    )

    devices = scan_network(str(network))

    for device in devices:

        print(
            f"IP: {device['ip']} | MAC: {device['mac']}"
        )

    # Permission denied handling
    if (
        len(devices) == 1
        and devices[0]["ip"] == "Permission Denied"
    ):
        device_count = 0

    else:
        device_count = len(devices)

    print(f"\nTotal Devices Found: {device_count}")
else:
    print("⏭ Skipped — Device Discovery only runs for Private/Internal IPs")
    print(f"  Reason: Target '{target}' is a {target_type}")
    device_count = 0

# Subnet Analysis
print("\nSUBNET ANALYSIS")

if is_private_ip:
    subnet_info = calculate_subnet(
        local_ip,
        cidr
    )

    print(f"Network ID   : {subnet_info['network_id']}")
    print(f"Broadcast IP : {subnet_info['broadcast']}")
    print(f"Usable Hosts : {subnet_info['total_hosts']}")
    print(f"CIDR         : {subnet_info['cidr']}")
else:
    print("⏭ Skipped — Subnet Analysis only runs for Private/Internal IPs")
    print(f"  Reason: Target '{target}' is a {target_type}")

# Port Scan
open_ports = 0

print("\nPORT SCAN")

ports = [22, 80, 443, 445, 3389]

for port in ports:

    status = scan_port(
        target,
        port
    )

    print(f"Port {port}: {status}")

    if status == "OPEN":
        open_ports += 1

print(f"\nOpen Ports Found: {open_ports}")

# Health Score
score = calculate_score(
    result,
    dns_result,
    open_ports
)

print("\nNETWORK HEALTH SCORE")
print(f"{score}/100")