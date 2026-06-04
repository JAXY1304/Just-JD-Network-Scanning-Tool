import socket
from scapy.all import ARP, Ether, srp

def scan_network(network):

    arp = ARP(pdst=network)

    ether = Ether(
        dst="ff:ff:ff:ff:ff:ff"
    )

    packet = ether / arp

    try:

        result = srp(
            packet,
            timeout=2,
            verbose=0
        )[0]

    except PermissionError:

        return [
            {
                "ip": "Permission Denied",
                "mac": "Run as sudo/root"
            }
        ]

    except Exception as e:

        return [
            {
                "ip": "Error",
                "mac": str(e)
            }
        ]

    devices = []

    for sent, received in result:

        try:
            hostname = socket.gethostbyaddr(received.psrc)[0]
        except:
            hostname = "Unknown"

        devices.append(
            {
                "ip": received.psrc,
                "hostname": hostname,
                "mac": received.hwsrc
            }
        )

    return devices