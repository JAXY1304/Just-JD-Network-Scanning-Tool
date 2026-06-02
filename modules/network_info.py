import socket
import subprocess
import psutil


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
    try:

        # Windows
        output = subprocess.check_output(
            "ipconfig",
            text=True
        )

        for line in output.splitlines():

            if "Default Gateway" in line:

                gateway = line.split(":")[-1].strip()

                if gateway:
                    return gateway

    except:
        pass

    try:

        # Linux / Ubuntu
        output = subprocess.check_output(
            ["ip", "route"],
            text=True
        )

        for line in output.splitlines():

            if line.startswith("default"):

                return line.split()[2]

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