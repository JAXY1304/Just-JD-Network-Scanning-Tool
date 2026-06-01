import ipaddress

def calculate_subnet(ip, cidr=24):
    try:
        network = ipaddress.ip_network(f"{ip}/{cidr}", strict=False)

        return {
            "network_id": str(network.network_address),
            "broadcast": str(network.broadcast_address),
            "total_hosts": network.num_addresses - 2,
            "cidr": f"/{cidr}"
        }

    except Exception as e:
        return {"error": str(e)}