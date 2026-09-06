from collections import defaultdict
from datetime import timedelta
from app.models.incident import IncidentCandidate
from app.services.mitre_mapper import mapping

REMEDIATION = "Block or rate-limit the source IP; disable password SSH authentication; use SSH keys; prevent root SSH login; enable fail2ban."

def detect(events, window_minutes=5):
    failures = [e for e in events if e.event_type == "auth_failure" and e.source_ip]
    grouped = defaultdict(list)
    for e in failures: grouped[e.source_ip].append(e)
    out = []
    for ip, items in grouped.items():
        items.sort(key=lambda e: e.timestamp or __import__('datetime').datetime.min)
        for start in range(len(items)):
            end = start
            while end < len(items) and items[start].timestamp and items[end].timestamp and items[end].timestamp - items[start].timestamp <= timedelta(minutes=window_minutes):
                end += 1
            cluster = items[start:end]
            if len(cluster) >= 10:
                users = {e.username for e in cluster if e.username}
                first, last = cluster[0].timestamp, cluster[-1].timestamp
                mid, mname = mapping("SSH Brute Force")
                duration = ((last-first).total_seconds()/60) if first and last else 0
                out.append(IncidentCandidate("SSH Brute Force", ip, len(cluster), first, last, mid, mname, REMEDIATION, [(e.raw_log,e.timestamp) for e in cluster[:12]], {"privileged": bool(users & {"root","admin"}), "multiple_usernames": len(users)>1, "duration_minutes": duration, "users": sorted(users)}))
                break
    return out

def detect_username_enumeration(events, min_users=5):
    grouped = defaultdict(list)
    for e in events:
        if e.event_type == "auth_failure" and e.source_ip and e.username: grouped[e.source_ip].append(e)
    out=[]
    for ip, items in grouped.items():
        users={e.username for e in items}
        if len(users) >= min_users:
            mid,mname=mapping("Credential Stuffing / Username Enumeration")
            out.append(IncidentCandidate("Credential Stuffing / Username Enumeration",ip,len(items),items[0].timestamp,items[-1].timestamp,mid,mname,"Rate-limit authentication, review targeted accounts, enforce MFA where available, and block abusive sources.",[(e.raw_log,e.timestamp) for e in items[:12]],{"multiple_usernames":True,"users":sorted(users)}))
    return out
