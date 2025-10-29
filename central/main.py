# central/main.py
import os, base64, time
from fastapi import FastAPI, HTTPException, Depends, Body
from pydantic import BaseModel
import jwt, psycopg2, json
from sqlalchemy import create_engine, text
from datetime import datetime, timedelta

env = {k:v for k,v in os.environ.items()}
DATABASE_URL = os.environ.get("POSTGRES_URL")
JWT_SECRET = os.environ.get("JWT_SECRET", "devsecret")
AES_KEY_B64 = os.environ.get("AES_KEY_BASE64", "")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "adminpass")

app = FastAPI(title="Central Face Hub")

engine = create_engine(DATABASE_URL, future=True)

def admin_auth(user, pwd):
    return user == ADMIN_USER and pwd == ADMIN_PASS

def gen_token(node_id: str, hours: int = 24):
    payload = {"node_id": node_id, "exp": int(time.time()) + hours*3600}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

@app.post("/admin/login")
def admin_login(user: str = Body(...), pwd: str = Body(...)):
    if admin_auth(user, pwd):
        return {"ok": True}
    raise HTTPException(status_code=401, detail="Invalid admin creds")

# Publish batch of user templates (for sync)
@app.get("/sync/batch")
def get_batch():
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT rut, name, encode(embedding, 'base64') as embedding_b64 FROM users")).mappings().all()
        users = [{"rut": r["rut"], "name": r["name"], "embedding_b64": r["embedding_b64"]} for r in rows]
    return {"users": users, "ts": datetime.utcnow().isoformat()}

# Register node heartbeat
@app.post("/node/heartbeat")
def heartbeat(node_id: str = Body(...), info: dict = Body(default={})):
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO nodes (node_id, last_seen, info) 
            VALUES (:node_id, now(), :info)
            ON CONFLICT (node_id) DO UPDATE SET last_seen = now(), info = :info
        """), {"node_id": node_id, "info": json.dumps(info)})
    return {"ok": True}

@app.post("/admin/audit")
def audit(event: str = Body(...), details: str = Body(""), actor: str = Body(None)):
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO audit (event, details, actor) VALUES (:e, :d, :a)"),
                     {"e": event, "d": details, "a": actor})
    return {"ok": True}
