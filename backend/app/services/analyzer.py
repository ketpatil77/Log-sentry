from app.parsers.auth_parser import AuthParser
from app.parsers.nginx_parser import NginxParser
from app.parsers.apache_parser import ApacheParser
from app.detection.brute_force import detect as brute_force, detect_username_enumeration
from app.detection.web_scanner import detect_web_scanning, detect_status_anomaly
from app.detection.sql_injection import detect as sql_injection
from app.detection.path_traversal import detect as path_traversal

PARSERS = [("linux_auth", AuthParser()), ("nginx_access", NginxParser()), ("apache_access", ApacheParser())]

def analyze_text(text: str):
    lines=[line for line in text.splitlines() if line.strip()]
    selected=None
    for name, parser in PARSERS:
        if parser.matches(lines): selected=(name,parser); break
    if not selected: return "unknown", [], []
    log_type,parser=selected
    events=[e for line in lines if (e:=parser.parse(line)) is not None]
    incidents=[]
    for detector in (brute_force, detect_username_enumeration, detect_web_scanning, detect_status_anomaly, sql_injection, path_traversal):
        incidents.extend(detector(events))
    dedup={}
    for i in incidents:
        key=(i.attack_type,i.source_ip)
        if key not in dedup or i.event_count > dedup[key].event_count: dedup[key]=i
    return log_type, events, list(dedup.values())
