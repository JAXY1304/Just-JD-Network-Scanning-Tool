RISKY_PORTS = {
    21: {
        "service": "FTP",
        "risk": "MEDIUM",
        "reason": "FTP transfers data in clear text."
    },

    22: {
        "service": "SSH",
        "risk": "LOW",
        "reason": "Secure remote administration."
    },

    80: {
        "service": "HTTP",
        "risk": "LOW",
        "reason": "Web service detected."
    },

    443: {
        "service": "HTTPS",
        "risk": "LOW",
        "reason": "Secure web service detected."
    },

    23: {
        "service": "TELNET",
        "risk": "HIGH",
        "reason": "Telnet is insecure."
    },

    445: {
        "service": "SMB",
        "risk": "WARNING",
        "reason": "SMB exposure increases attack surface."
    },

    3389: {
        "service": "RDP",
        "risk": "INFO",
        "reason": "Remote Desktop exposed."
    }
}


def analyze_port(port, status):

    if status != "OPEN":
        return None

    if port in RISKY_PORTS:
        return RISKY_PORTS[port]

    return {
        "service": "Unknown",
        "risk": "LOW",
        "reason": "No known risk detected."
    }
