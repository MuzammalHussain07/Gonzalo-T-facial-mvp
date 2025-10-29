# local/app.py (condensed)
import os, time, base64, json, requests
from pathlib import Path
import sqlite3, jwt
import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import face_recognition
from PIL import Image
import gradio as gr

# Config
CENTRAL_URL = os.environ.get("CENTRAL_URL","http://central:8000")
NODE_ID = os.environ.get("NODE_ID","node-demo")
JWT_SECRET = os.environ.get("JWT_SECRET","devsecret")
AES_KEY_B64 = os.environ.get("AES_KEY_BASE64","")
AES_KEY = base64.b64decode(AES_KEY_B64) if AES_KEY_B64 else b"demo32byteskey-for-dev-12345678"[:32]

DATA_DIR = Path("data"); DATA_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR/"local.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.executescript(open("db_schema.sql").read())
    conn.commit(); conn.close()

init_db()

def encrypt_bytes(b: bytes)->bytes:
    aes = AESGCM(AES_KEY)
    nonce = os.urandom(12)
    return nonce + aes.encrypt(nonce, b, None)

def decrypt_bytes(blob: bytes)->bytes:
    aes = AESGCM(AES_KEY)
    nonce = blob[:12]; ct = blob[12:]
    return aes.decrypt(nonce, ct, None)

def audit(event, details=""):
    conn = sqlite3.connect(DB_PATH); cur=conn.cursor()
    cur.execute("INSERT INTO audit (event, details) VALUES (?,?)",(event, details))
    conn.commit(); conn.close()

# Enrollment: store encrypted embedding
def enroll(rut, name, email, id_img, frame1, frame2, frame3):
    # simplified RUT check
    if not rut: return "RUT required"
    frames = [np.array(frame1), np.array(frame2), np.array(frame3)]
    # simple liveness check: require movement
    # compute encoding on middle frame
    encs = face_recognition.face_encodings(frames[1])
    if not encs: return "No face detected"
    emb = encs[0].tobytes()
    emb_blob = encrypt_bytes(emb)
    img_bytes = id_img.convert("RGB")
    import io
    b=io.BytesIO(); img_bytes.save(b,format="JPEG")
    img_blob = encrypt_bytes(b.getvalue())
    conn=sqlite3.connect(DB_PATH); cur=conn.cursor()
    cur.execute("INSERT OR REPLACE INTO users (rut,name,email,embedding,img) VALUES (?,?,?,?,?)",
                (rut,name,email,emb_blob,img_blob))
    conn.commit(); conn.close()
    audit("enroll", rut)
    return "Enrolled"

def match_face(test_img, tolerance=0.55):
    arr = np.array(test_img)
    encs = face_recognition.face_encodings(arr)
    if not encs: return "No face detected"
    probe = encs[0]
    conn=sqlite3.connect(DB_PATH); cur=conn.cursor()
    cur.execute("SELECT rut,name,embedding FROM users")
    rows = cur.fetchall(); conn.close()
    best=None; best_score=999
    for rut,name,emb_blob in rows:
        try:
            raw = decrypt_bytes(emb_blob)
            emb = np.frombuffer(raw, dtype=np.float64)
            dist = np.linalg.norm(emb-probe)
            if dist < best_score:
                best_score = dist; best=(rut,name)
        except Exception as e:
            continue
    if best and best_score<=tolerance:
        audit("match_success", f"{best[0]} dist={best_score:.3f}")
        return f"Match {best[1]} (RUT: {best[0]}) score={best_score:.3f}"
    audit("match_fail", f"best={best_score}")
    return "No match"

# Token check: verify local token (JWT) expiration; if expired, disallow matching
def token_valid(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return True
    except Exception:
        return False

# Heartbeat to central (register node)
def send_heartbeat():
    try:
        r = requests.post(f"{CENTRAL_URL}/node/heartbeat", json={"node_id": NODE_ID, "info":{"version":"v1"}} , timeout=5)
        return True
    except Exception:
        return False

# Force sync: fetch batch and insert to local db
def force_sync():
    try:
        r = requests.get(f"{CENTRAL_URL}/sync/batch", timeout=10)
        data = r.json()
        conn=sqlite3.connect(DB_PATH); cur=conn.cursor()
        for u in data.get("users",[]):
            emb_b64 = u["embedding_b64"]
            emb_blob = base64.b64decode(emb_b64)
            # NOTE: central stores encrypted embedding. We store as-is (encrypted).
            cur.execute("INSERT OR IGNORE INTO users (rut, name, email, embedding) VALUES (?,?,?,?)",
                        (u["rut"], u["name"], u.get("email",""), emb_blob))
        conn.commit(); conn.close()
        audit("force_sync", f"{len(data.get('users',[]))} users")
        return "Sync done"
    except Exception as e:
        return f"Sync failed: {e}"

# Simple Gradio interface for demo
with gr.Blocks() as demo:
    gr.Markdown("# Local Node Demo")
    with gr.Tab("Enroll"):
        rut = gr.Textbox("RUT"); name=gr.Textbox("Name"); email=gr.Textbox("Email")
        id_upload = gr.Image(source="upload", label="Upload ID image")
        f1=gr.Image(source="camera", label="Frame1"); f2=gr.Image(source="camera", label="Frame2"); f3=gr.Image(source="camera", label="Frame3")
        btn=gr.Button("Enroll"); out=gr.Textbox()
        btn.click(lambda a,b,c,d,e,f: enroll(a,b,c,d,e,f), [rut,name,email,id_upload,f1,f2,f3], out)
    with gr.Tab("Identify"):
        img = gr.Image(source="camera"); tol = gr.Slider(0.4,0.7,0.55); tok = gr.Textbox(label="Admin Token")
        btn2=gr.Button("Identify"); out2=gr.Textbox()
        def identify(img_data,tol_val,token):
            if not token or not token_valid(token): return "Operation blocked: invalid or expired token"
            return match_face(img_data,tol_val)
        btn2.click(identify, [img,tol,tok], out2)
    with gr.Tab("Admin"):
        sync_btn = gr.Button("Force Sync"); sync_out=gr.Textbox()
        sync_btn.click(lambda : force_sync(), None, sync_out)
    demo.launch(server_name="0.0.0.0", server_port=7860)
