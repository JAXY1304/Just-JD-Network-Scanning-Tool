import subprocess
import re

def packet_loss_test(host):

    try:
        result = subprocess.run(
            ["ping", "-n", "10", host],
            capture_output=True,
            text=True
        )

        output = result.stdout

        match = re.search(r"(\d+)% loss", output)

        if match:
            return match.group(1) + "%"

        return "Unable to determine"

    except Exception as e:
        return str(e)