from collections import defaultdict
from app.models.incident import IncidentCandidate
from app.services.mitre_mapper import mapping

PATHS=("/wp-admin","/.env","/phpmyadmin","/.git","/admin","/server-status","/config.php")

def detect_web_scanning(events):
    grouped=defaultdict(list)
    for e in events:
        if e.source_ip and e.path and any(p in e.path.lower() for p in PATHS): grouped[e.source_ip].append(e)
    out=[]
    for ip,items in grouped.items():
        if len(items)>=3:
            mid,mname=mapping("Web Reconnaissance / Enumeration")
            out.append(IncidentCandidate("Web Reconnaissance / Enumeration",ip,len(items),items[0].timestamp,items[-1].timestamp,mid,mname,"Rate-limit repeated probes, deny access to sensitive paths, remove exposed artifacts, and review WAF rules.",[(e.raw_log,e.timestamp) for e in items[:12]],{"high_confidence":len(items)>=10}))
    return out

def detect_status_anomaly(events):
    grouped=defaultdict(list)
    for e in events:
        if e.source_ip and e.status_code in {401,403,404}: grouped[e.source_ip].append(e)
    out=[]
    for ip,items in grouped.items():
        if len(items)>=20:
            mid,mname=mapping("Suspicious HTTP Status Activity")
            out.append(IncidentCandidate("Suspicious HTTP Status Activity",ip,len(items),items[0].timestamp,items[-1].timestamp,mid,mname,"Rate-limit the source, inspect requested paths, and review application/WAF logs for automated enumeration.",[(e.raw_log,e.timestamp) for e in items[:12]],{"high_confidence":len(items)>=100}))
    return out
