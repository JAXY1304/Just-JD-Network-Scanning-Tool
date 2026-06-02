import subprocess
import platform
import shutil


def run_traceroute(host):

    try:

        system = platform.system()

        if system == "Windows":

            command = ["tracert", host]

        else:

            if shutil.which("traceroute") is None:

                return (
                    "Traceroute not installed.\n"
                    "Ubuntu/Debian:\n"
                    "sudo apt install traceroute -y"
                )

            command = ["traceroute", host]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        return result.stdout

    except Exception as e:

        return f"Traceroute Error: {e}"