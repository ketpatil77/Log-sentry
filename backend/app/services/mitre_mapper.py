MITRE = {
    "SSH Brute Force": ("T1110", "Brute Force"),
    "Credential Stuffing / Username Enumeration": ("T1110", "Brute Force"),
    "Web Reconnaissance / Enumeration": ("T1595", "Active Scanning"),
    "Suspicious HTTP Status Activity": ("T1595", "Active Scanning"),
    "SQL Injection Attempt": ("T1190", "Exploit Public-Facing Application"),
    "Path Traversal Attempt": ("T1190", "Exploit Public-Facing Application"),
}

def mapping(name: str):
    return MITRE[name]
