from modules.ping_test import check_ping

def monitor_host(host):

    result = check_ping(host)

    if "Reachable" in result:
        return True

    return False
