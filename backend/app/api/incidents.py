from fastapi import APIRouter, HTTPException
from app.db.database import SessionLocal, Incident
router=APIRouter()

def serialize(i, detail=False):
    data={"id":i.id,"analysis_id":i.analysis_id,"attack_type":i.attack_type,"source_ip":i.source_ip,"severity":i.severity,"risk_score":i.risk_score,"event_count":i.event_count,"first_seen":i.first_seen,"last_seen":i.last_seen,"mitre_id":i.mitre_id,"mitre_name":i.mitre_name,"recommendation":i.recommendation}
    if detail: data["evidence"]=[{"raw_log":e.raw_log,"timestamp":e.timestamp} for e in i.evidence]
    return data

@router.get("/analyses/{analysis_id}/incidents")
def list_incidents(analysis_id:str):
    db=SessionLocal()
    try: return [serialize(i) for i in db.query(Incident).filter(Incident.analysis_id==analysis_id).order_by(Incident.risk_score.desc()).all()]
    finally: db.close()

@router.get("/incidents/{incident_id}")
def get_incident(incident_id:str):
    db=SessionLocal()
    try:
        i=db.get(Incident,incident_id)
        if not i: raise HTTPException(404,"Incident not found")
        return serialize(i,True)
    finally: db.close()
