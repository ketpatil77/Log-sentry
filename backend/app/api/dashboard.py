from collections import Counter
from fastapi import APIRouter, HTTPException
from app.db.database import SessionLocal, Analysis, Incident
router=APIRouter()

@router.get("/analyses/{analysis_id}")
def analysis_summary(analysis_id:str):
    db=SessionLocal()
    try:
        a=db.get(Analysis,analysis_id)
        if not a: raise HTTPException(404,"Analysis not found")
        incidents=db.query(Incident).filter(Incident.analysis_id==analysis_id).all()
        threats=Counter(i.attack_type for i in incidents); severities=Counter(i.severity for i in incidents)
        ips={i.source_ip for i in incidents}
        return {"id":a.id,"filename":a.filename,"log_type":a.log_type,"events_processed":a.events_processed,"created_at":a.created_at,"security_incidents":len(incidents),"critical_incidents":severities.get("CRITICAL",0),"unique_suspicious_ips":len(ips),"threat_distribution":threats,"severity_distribution":severities}
    finally: db.close()

@router.delete("/analyses/{analysis_id}",status_code=204)
def delete_analysis(analysis_id:str):
    db=SessionLocal()
    try:
        a=db.get(Analysis,analysis_id)
        if not a: raise HTTPException(404,"Analysis not found")
        db.delete(a); db.commit()
    finally: db.close()
