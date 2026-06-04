import subprocess
import re
import socket
from mac_vendor_lookup import MacLookup

lookup = MacLookup()

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

def get_vendor(mac):
    try:
        return lookup.lookup(mac)
    except:
        return "Unknown"

def get_arp_devices():

    devices = []

    output = subprocess.check_output(
        "arp -a",
        shell=True,
        text=True
    )

    pattern = r"(\d+\.\d+\.\d+\.\d+)\s+([a-f0-9\-]+)\s+dynamic"

    matches = re.findall(
        pattern,
        output,
        re.IGNORECASE
    )

    for ip, mac in matches:

        mac = mac.replace("-", ":")

        devices.append(
            {
                "ip": ip,
                "hostname": get_hostname(ip),
                "mac": mac,
                "vendor": get_vendor(mac)
            }
        )

    return devices