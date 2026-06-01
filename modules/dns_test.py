import socket

def resolve_domain(domain):
    try:
        ip = socket.gethostbyname(domain)
        return f"{domain} -> {ip}"

    except Exception as e:
        return f"DNS Error: {e}"