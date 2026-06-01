from ping3 import ping

def check_ping(host):
    try:
        response = ping(host, timeout=2)

        if response:
            return f"{host} Reachable | RTT: {round(response * 1000, 2)} ms"
        else:
            return f"{host} Unreachable"

    except Exception as e:
        return f"Error: {e}"