def scan_func(name,status,severity,description,confidence):
    finding = {
        "name": name,
        "status": status,
        "severity": severity,
        "description": description,
        "confidence": confidence
    }
    return finding