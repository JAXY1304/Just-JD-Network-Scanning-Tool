import subprocess
import re
import platform

def packet_loss_test(host):

    try:

        if platform.system() == "Windows":

            command = [
                "ping",
                "-n",
                "10",
                host
            ]

            pattern = r"(\d+)% loss"

        else:

            command = [
                "ping",
                "-c",
                "10",
                host
            ]

            pattern = r"(\d+(?:\.\d+)?)% packet loss"

        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        output = result.stdout

        match = re.search(
            pattern,
            output
        )

        if match:

            return match.group(1) + "%"

        return "Unable to determine"

    except Exception as e:

        return str(e)