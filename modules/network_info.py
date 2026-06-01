import socket
import subprocess

def get_local_ip():
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)

        return local_ip

    except:
        return "Unknown"
    


def get_gateway():
    try:
        output = subprocess.check_output(
            "ipconfig",
            text=True
        )

        for line in output.splitlines():

            if "Default Gateway" in line:

                gateway = line.split(":")[-1].strip()

                if gateway:
                    return gateway

        return "Not Found"

    except:
        return "Error"