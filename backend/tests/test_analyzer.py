from app.services.analyzer import analyze_text
from app.services.risk_engine import severity

def test_auth_bruteforce_and_enumeration():
    users=["root","admin","ubuntu","test","oracle"]
    lines=[]
    for i in range(12):
        user=users[i%len(users)]
        lines.append(f"Sep  6 18:32:{i:02d} server sshd[123]: Failed password for {user} from 103.24.1.9 port 22 ssh2")
    kind,events,incidents=analyze_text("\n".join(lines))
    names={x.attack_type for x in incidents}
    assert kind=="linux_auth" and len(events)==12
    assert "SSH Brute Force" in names
    assert "Credential Stuffing / Username Enumeration" in names

def test_web_attack_patterns():
    lines=[]
    for i in range(25): lines.append(f'45.1.2.3 - - [06/Sep/2026:18:32:{i%60:02d} +0000] "GET /missing-{i} HTTP/1.1" 404 12')
    lines += [
      '45.1.2.3 - - [06/Sep/2026:18:33:01 +0000] "GET /.env HTTP/1.1" 404 12',
      '45.1.2.3 - - [06/Sep/2026:18:33:02 +0000] "GET /wp-admin HTTP/1.1" 404 12',
      '45.1.2.3 - - [06/Sep/2026:18:33:03 +0000] "GET /phpmyadmin HTTP/1.1" 404 12',
      '45.1.2.3 - - [06/Sep/2026:18:33:04 +0000] "GET /search?q=1%20UNION%20SELECT%20password%20FROM%20users HTTP/1.1" 403 12',
      '45.1.2.3 - - [06/Sep/2026:18:33:05 +0000] "GET /download?file=../../etc/passwd HTTP/1.1" 403 12',
    ]
    kind,events,incidents=analyze_text("\n".join(lines))
    names={x.attack_type for x in incidents}
    assert kind=="nginx_access"
    assert {"Web Reconnaissance / Enumeration","Suspicious HTTP Status Activity","SQL Injection Attempt","Path Traversal Attempt"} <= names

def test_severity_bands():
    assert severity(29)=="LOW" and severity(30)=="MEDIUM" and severity(60)=="HIGH" and severity(80)=="CRITICAL"
