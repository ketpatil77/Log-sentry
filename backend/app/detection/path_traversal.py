from collections import defaultdict
from urllib.parse import unquote_plus
from app.models.incident import IncidentCandidate
from app.services.mitre_mapper import mapping

TOKENS=("../","etc/passwd","windows/system32","%2e%2e")
def detect(events):
    grouped=defaultdict(list)
    for e in events:
        if not (e.source_ip and e.path): continue
        raw=e.path.lower(); decoded=unquote_plus(raw)
        if any(t in raw or t in decoded for t in TOKENS): grouped[e.source_ip].append(e)
    out=[]
    for ip,items in grouped.items():
        mid,mname=mapping("Path Traversal Attempt")
        out.append(IncidentCandidate("Path Traversal Attempt",ip,len(items),items[0].timestamp,items[-1].timestamp,mid,mname,"Normalize and validate paths, enforce allow-lists, keep file access outside user-controlled paths, and review affected endpoints.",[(e.raw_log,e.timestamp) for e in items[:12]],{"high_confidence":True}))
    return out
