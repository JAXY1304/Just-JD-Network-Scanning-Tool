import subprocess
import platform

def run_traceroute(host):

    try:

        if platform.system() == "Windows":
            command = ["tracert", host]

        else:
            command = ["traceroute", host]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        return result.stdout

    except Exception as e:

        return f"Traceroute Error: {e}"