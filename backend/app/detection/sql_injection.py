import re
from collections import defaultdict
from urllib.parse import unquote_plus
from app.models.incident import IncidentCandidate
from app.services.mitre_mapper import mapping

SQLI = re.compile(r"(?:union\s+(?:all\s+)?select|or\s+['\"0-9]+\s*=\s*['\"0-9]+|select\s+.+\s+from|information_schema|sleep\s*\(|benchmark\s*\()", re.I)

def detect(events):
    grouped=defaultdict(list)
    for e in events:
        if e.source_ip and e.path and SQLI.search(unquote_plus(e.path)): grouped[e.source_ip].append(e)
    out=[]
    for ip,items in grouped.items():
        mid,mname=mapping("SQL Injection Attempt")
        out.append(IncidentCandidate("SQL Injection Attempt",ip,len(items),items[0].timestamp,items[-1].timestamp,mid,mname,"Use parameterized queries, validate inputs, review vulnerable endpoints, and add WAF rules for confirmed malicious patterns.",[(e.raw_log,e.timestamp) for e in items[:12]],{"high_confidence":True}))
    return out
