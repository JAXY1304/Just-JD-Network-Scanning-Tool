import subprocess

def run_traceroute(host):
    try:
        result = subprocess.run(
            ["tracert", host],
            capture_output=True,
            text=True
        )

        return result.stdout

    except Exception as e:
        return f"Traceroute Error: {e}"