from scapy.all import ARP, Ether, srp

def scan_network(network):

    arp = ARP(pdst=network)

    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = ether / arp

    result = srp(
        packet,
        timeout=2,
        verbose=False
    )[0]

    devices = []

    for sent, received in result:

        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })

    return devices