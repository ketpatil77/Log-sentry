from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from fastapi import APIRouter, UploadFile, File, HTTPException
from app.db.database import SessionLocal, Analysis, Incident, Evidence
from app.services.analyzer import analyze_text
from app.services.risk_engine import score_incident, severity

router=APIRouter()
MAX_BYTES=10*1024*1024
ALLOWED={".log",".txt"}

@router.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    suffix=Path(file.filename or "").suffix.lower()
    if suffix not in ALLOWED: raise HTTPException(400,"Only .log and .txt files are accepted")
    data=await file.read(MAX_BYTES+1)
    if len(data)>MAX_BYTES: raise HTTPException(413,"File exceeds 10 MB limit")
    try: text=data.decode("utf-8", errors="strict")
    except UnicodeDecodeError: raise HTTPException(400,"Log must be UTF-8 text")
    log_type, events, candidates=analyze_text(text)
    if log_type=="unknown": raise HTTPException(422,"Unsupported or unrecognized log format")
    analysis_id=str(uuid4())
    now=datetime.now(timezone.utc).replace(tzinfo=None)
    db=SessionLocal()
    try:
        db.add(Analysis(id=analysis_id,filename=Path(file.filename or "upload.log").name,log_type=log_type,events_processed=len(events),created_at=now))
        for c in candidates:
            iid=str(uuid4()); score=score_incident(c.attack_type,c.event_count,c.metadata)
            db.add(Incident(id=iid,analysis_id=analysis_id,attack_type=c.attack_type,source_ip=c.source_ip,severity=severity(score),risk_score=score,event_count=c.event_count,first_seen=c.first_seen,last_seen=c.last_seen,mitre_id=c.mitre_id,mitre_name=c.mitre_name,recommendation=c.recommendation))
            for raw,ts in c.evidence: db.add(Evidence(incident_id=iid,raw_log=raw[:4000],timestamp=ts))
        db.commit()
    finally: db.close()
    return {"analysis_id":analysis_id,"events_processed":len(events),"incidents_found":len(candidates),"log_type":log_type}
