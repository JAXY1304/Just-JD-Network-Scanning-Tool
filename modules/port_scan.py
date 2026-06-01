import socket

def scan_port(host, port):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)

    result = sock.connect_ex((host, port))

    sock.close()

    if result == 0:
        return "OPEN"

    return "CLOSED"