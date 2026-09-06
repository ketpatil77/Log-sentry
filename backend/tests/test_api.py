import os
os.environ["DATABASE_URL"]="sqlite:///./test_logsentry.db"
from fastapi.testclient import TestClient
from app.main import app
client=TestClient(app)

def test_reject_extension():
    r=client.post('/api/analyze',files={'file':('x.exe',b'hello','text/plain')})
    assert r.status_code==400

def test_health():
    assert client.get('/health').json()=={'status':'ok'}
