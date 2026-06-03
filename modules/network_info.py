import socket
import subprocess
import psutil
import re
import platform


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        s.connect(("8.8.8.8", 80))

        ip = s.getsockname()[0]

        s.close()

        return ip

    except:
        return "Unknown"


def get_gateway():
    # Try Windows preferred method first
    if platform.system() == "Windows":
        try:
            output = subprocess.check_output("route print 0.0.0.0", text=True)
            for line in output.splitlines():
                if "0.0.0.0" in line:
                    parts = line.split()
                    for item in parts:
                        if re.match(r"^\d+\.\d+\.\d+\.\d+$", item) and item != "0.0.0.0":
                            return item
        except:
            pass

    # Try scapy route (Linux/macOS or if scapy available)
    try:
        from scapy.all import conf
        gateway = conf.route.route("0.0.0.0")[2]
        if gateway and gateway != "0.0.0.0" and gateway != "127.0.0.1":
            return gateway
    except:
        pass

    # Windows fallback using ipconfig
    if platform.system() == "Windows":
        try:
            output = subprocess.check_output("ipconfig", text=True)
            lines = output.splitlines()
            for idx, line in enumerate(lines):
                if "Default Gateway" in line:
                    parts = line.split(":", 1)
                    val = parts[1].strip() if len(parts) > 1 else ""
                    if val and re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", val):
                        return val
                    for next_line in lines[idx+1:]:
                        next_line = next_line.strip()
                        if ":" in next_line and not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", next_line.split(":", 1)[0].strip()):
                            break
                        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", next_line):
                            return next_line
        except:
            pass

    # Linux/macOS fallback using ip route
    try:
        output = subprocess.check_output(["ip", "route"], text=True)
        for line in output.splitlines():
            if line.startswith("default"):
                parts = line.split()
                if len(parts) > 2:
                    return parts[2]
    except:
        pass

    return "Not Found"


def get_cidr():

    try:

        local_ip = get_local_ip()

        interfaces = psutil.net_if_addrs()

        for interface in interfaces:

            for addr in interfaces[interface]:

                if addr.family == socket.AF_INET:

                    if addr.address == local_ip:

                        mask = addr.netmask

                        cidr = sum(
                            bin(int(x)).count("1")
                            for x in mask.split(".")
                        )

                        return cidr

        return 24

    except:
        return 24