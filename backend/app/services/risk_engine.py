def severity(score: int) -> str:
    if score >= 80: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 30: return "MEDIUM"
    return "LOW"

def score_incident(attack_type: str, count: int, metadata: dict) -> int:
    base = {
        "SSH Brute Force": 40,
        "Credential Stuffing / Username Enumeration": 35,
        "Web Reconnaissance / Enumeration": 35,
        "Suspicious HTTP Status Activity": 30,
        "SQL Injection Attempt": 65,
        "Path Traversal Attempt": 60,
    }[attack_type]
    score = base
    if count > 25: score += 10
    if count > 50: score += 10
    if metadata.get("privileged"): score += 10
    if metadata.get("multiple_usernames"): score += 10
    if metadata.get("duration_minutes", 0) > 10: score += 10
    if metadata.get("high_confidence"): score += 10
    return min(score, 100)
