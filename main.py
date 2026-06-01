from modules.ping_test import check_ping
from modules.dns_test import resolve_domain
from modules.network_info import get_local_ip
from modules.network_info import get_gateway
from modules.health_score import calculate_score
from modules.port_scan import scan_port
from modules.traceroute import run_traceroute
from modules.packet_loss import packet_loss_test
from modules.arp_scan import scan_network
from modules.subnet_calc import calculate_subnet

print("=" * 50)
print("JUST-JD NETWORK SCANNING TOOL")
print("=" * 50)

# Ping Test
result = check_ping("8.8.8.8")

print("\nPING TEST")
print(result)

# DNS Test
print("\nDNS TEST")
dns_result = resolve_domain("google.com")
print(dns_result)



# Local IP
print("\nLOCAL IP")
print(get_local_ip())

# Gateway
print("\nDEFAULT GATEWAY")
print(get_gateway())


print("\nTRACEROUTE TEST")

trace_result = run_traceroute("8.8.8.8")

print(trace_result)


print("\nPACKET LOSS TEST")

loss = packet_loss_test("8.8.8.8")

print(f"Packet Loss: {loss}")

print("\nDEVICE DISCOVERY")

devices = scan_network("192.168.2.0/24")

for device in devices:

    print(
        f"IP: {device['ip']} | MAC: {device['mac']}"
    )

print(f"\nTotal Devices Found: {len(devices)}")



print("\nSUBNET ANALYSIS")

subnet_info = calculate_subnet("192.168.2.91", 24)

print(f"Network ID   : {subnet_info['network_id']}")
print(f"Broadcast IP : {subnet_info['broadcast']}")
print(f"Usable Hosts : {subnet_info['total_hosts']}")
print(f"CIDR         : {subnet_info['cidr']}")













open_ports = 0

print("\nPORT SCAN")

ports = [22, 80, 443, 445, 3389]

for port in ports:

    status = scan_port("google.com", port)

    print(f"Port {port}: {status}")

    if status == "OPEN":
        open_ports += 1


print(f"\nOpen Ports Found: {open_ports}")

score = calculate_score(result, dns_result, open_ports)

print("\nNETWORK HEALTH SCORE")
print(f"{score}/100")