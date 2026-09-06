import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.db.database import init_db
from app.api import upload, incidents, dashboard

app=FastAPI(title="LogSentry API",version="1.0.0",docs_url="/docs")
origins=[x.strip() for x in os.getenv("CORS_ORIGINS","http://localhost:5173").split(",") if x.strip()]
app.add_middleware(CORSMiddleware,allow_origins=origins,allow_credentials=False,allow_methods=["GET","POST","DELETE"],allow_headers=["*"])
app.include_router(upload.router,prefix="/api")
app.include_router(incidents.router,prefix="/api")
app.include_router(dashboard.router,prefix="/api")

@app.on_event("startup")
def startup(): init_db()

@app.get("/health")
def health(): return {"status":"ok"}
