def calculate_score(ping_status, dns_status, open_ports):

    score = 0

    # Ping
    if "Reachable" in ping_status:
        score += 40

    # DNS
    if "->" in dns_status or "Skipped" in dns_status:
        score += 40

    # Ports
    if open_ports > 0:
        score += 20

    return score