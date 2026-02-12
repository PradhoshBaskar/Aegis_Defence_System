import time
import uuid
import json
import secrets
import collections
import requests
import uvicorn
import numpy as np
from fastapi import FastAPI, Request, HTTPException, Header, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sklearn.ensemble import IsolationForest
import argparse
from database import aegis_db
import aegis_config
from tests.audit_runner import execute_full_audit
from crypto_utils import kyber_engine
import asyncio
from concurrent.futures import ThreadPoolExecutor

# ===================== CONFIGURATION =====================
app = FastAPI(title="Aegis-Shift Defense System")
templates = Jinja2Templates(directory="template")

N8N_WEBHOOK_URL = "http://localhost:5678/webhook-test/aegis-alert"
N8N_OTP_WEBHOOK_URL = "http://localhost:5678/webhook-test/send-otp"
API_SECRET = "aegis-hackathon-secret-2026"

PENDING_OTPS = {}

# ===================== AI BRAIN SETUP =====================
print("Initializing Aegis Defense Systems...")
print("Training AI Model (Isolation Forest)...")

X_train = np.array([
    [10, 500], [12, 550], [15, 600], [8, 480],
    [20, 1500], [18, 1600], [5, 400]
])

clf = IsolationForest(contamination=0.1, random_state=42)
clf.fit(X_train)
print("AI Model Armed & Ready.")

# ===================== RATE LIMITER =====================
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX = 10
_request_log = collections.defaultdict(list)

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Block IPs that exceed RATE_LIMIT_MAX requests to /api/login within the window."""
    if request.url.path == "/api/login" and request.method == "POST":
        client_ip = request.client.host
        now = time.time()
        _request_log[client_ip] = [
            ts for ts in _request_log[client_ip] if now - ts < RATE_LIMIT_WINDOW
        ]
        if len(_request_log[client_ip]) >= RATE_LIMIT_MAX:
            print(f"RATE LIMIT: {client_ip} blocked ({len(_request_log[client_ip])} requests in {RATE_LIMIT_WINDOW}s)")
            return JSONResponse(
                status_code=429,
                content={"status": "error", "message": "Too many requests. You have been rate-limited."}
            )
        _request_log[client_ip].append(now)
    return await call_next(request)

print("Rate Limiter Armed (10 req/min on /api/login).")

# ===================== GEO-IP & LOGIC =====================
def get_geo_location(ip):
    """Converts IP to City, Country using free API."""
    if ip == "127.0.0.1": return "Localhost (Internal)"
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        return f"{r.get('city', 'Unknown')}, {r.get('country', 'Unknown')}"
    except:
        return "Unknown Location"

def trigger_soar_alert(ip, threat, severity, details):
    """Sends Alert to n8n Orchestrator."""
    location = get_geo_location(ip)

    payload = {
        "alert_id": str(uuid.uuid4()),
        "timestamp": time.time(),
        "severity": severity,
        "threat_type": threat,
        "attacker_ip": ip,
        "attacker_location": location,
        "details": details
    }

    headers = {"X-Aegis-Auth": API_SECRET}

    try:
        print(f"SIGNAL SENT: {threat} from {location}")
        requests.post(N8N_WEBHOOK_URL, json=payload, headers=headers)
    except Exception as e:
        print(f"N8N CONNECTION FAILED: {e}")

# ===================== DEFENSE ENDPOINTS =====================

@app.get("/", response_class=RedirectResponse)
def home():
    return RedirectResponse(url="/login")

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/otp", response_class=HTMLResponse)
def otp_page(request: Request):
    return templates.TemplateResponse("otp.html", {"request": request})

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard_page(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.get("/admin-login", response_class=HTMLResponse)
def admin_login_page(request: Request):
    return templates.TemplateResponse("honeypot.html", {"request": request})

# ===================== AUTHENTICATION ENDPOINTS =====================

@app.post("/api/login")
async def api_login(username: str = Form(...), password: str = Form(...), phone: str = Form(...)):
    """Login endpoint - validates credentials and sends OTP."""
    if username != "admin" or password != "admin":
        return {"status": "error", "message": "Invalid credentials"}

    otp = str(secrets.randbelow(900000) + 100000)
    PENDING_OTPS[username] = otp

    try:
        payload = {"otp": otp, "user": username}
        headers = {"Content-Type": "application/json", "X-Aegis-Auth": API_SECRET}
        print(f"Sending 6-digit OTP to Discord via n8n Cloud...")
        requests.post(N8N_OTP_WEBHOOK_URL, json=payload, headers=headers, timeout=5)
    except Exception as e:
        print(f"N8N OTP Webhook Failed: {e}")

    return {"status": "success", "message": "OTP Sent"}

@app.post("/api/verify-otp")
async def api_verify_otp(username: str = Form(...), otp: str = Form(...)):
    """OTP verification endpoint."""
    if username in PENDING_OTPS and PENDING_OTPS[username] == otp:
        del PENDING_OTPS[username]
        return {"status": "success", "redirect": "/dashboard"}

    return {"status": "error", "message": "Invalid OTP"}

@app.get("/api/stats")
async def api_stats():
    """Dashboard stats endpoint - returns real-time data from MySQL."""
    try:
        logs = aegis_db.get_recent_logs(limit=50)

        total = len(logs)
        threats = sum(1 for log in logs if log.get('severity') in ['HIGH', 'CRITICAL'])
        legitimate = total - threats

        return {
            "status": "success",
            "ai_enabled": True,
            "logs": logs,
            "metrics": {
                "total": total,
                "legitimate": legitimate,
                "threats": threats,
                "scans": 0
            }
        }
    except Exception as e:
        print(f"Stats API Error: {e}")
        return {
            "status": "error",
            "message": str(e),
            "logs": [],
            "metrics": {"total": 0, "legitimate": 0, "threats": 0, "scans": 0}
        }

# ===================== HONEYPOT TRAP =====================

@app.post("/admin-login")
async def honeypot_trap(request: Request):
    """Honeypot trap - logs and alerts on access."""
    client_ip = request.client.host

    try:
        aegis_db.log_event(
            ip=client_ip,
            req_type="HONEYPOT_TRIGGERED",
            endpoint="/admin-login",
            size=0,
            confidence="100%",
            severity="CRITICAL"
        )
    except Exception as e:
        print(f"DB Write Failed: {e}")

    trigger_soar_alert(
        ip=client_ip,
        threat="HONEYPOT_TRIGGERED",
        severity="CRITICAL",
        details={"trap": "Attempted access to fake admin panel"}
    )

    return templates.TemplateResponse("honeypot.html", {"request": request})

# ===================== AI TRAFFIC ANALYSIS =====================

@app.post("/analyze-traffic")
def analyze(request: Request, req_freq: int, packet_size: int, x_aegis_auth: str = Header(None)):
    """AI-powered traffic analysis endpoint."""
    if x_aegis_auth != API_SECRET:
        raise HTTPException(status_code=403, detail="Access Denied")

    raw_score = clf.decision_function([[req_freq, packet_size]])[0]

    confidence = 0
    if raw_score < 0:
        confidence = min(abs(raw_score) * 200, 100)

    if raw_score < 0:
        client_ip = request.client.host
        print(f"Logging anomaly from {client_ip} to MySQL...")
        try:
            aegis_db.log_event(
                ip=client_ip,
                req_type="BEHAVIORAL_ANOMALY",
                endpoint="/analyze-traffic",
                size=packet_size,
                confidence=f"{confidence:.2f}%",
                severity="HIGH"
            )
        except Exception as e:
            print(f"DB Write Failed: {e}")
        trigger_soar_alert(
            ip=client_ip,
            threat="BEHAVIORAL_ANOMALY",
            severity="HIGH",
            details={
                "freq": req_freq,
                "size": packet_size,
                "ai_confidence": f"{confidence:.2f}%",
                "raw_score": float(raw_score)
            }
        )
        return {"status": "BLOCKED", "reason": f"Anomaly Detected ({confidence:.2f}%)"}

    return {"status": "ALLOWED", "reason": "Traffic Normal"}

# ===================== RED TEAM AUDIT =====================

@app.get("/api/audit")
async def run_audit():
    """Run the full Red Team security audit suite on demand."""
    try:
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor() as pool:
            report = await loop.run_in_executor(pool, execute_full_audit)
        return {"status": "success", "report": report}
    except Exception as e:
        print(f"Audit Error: {e}")
        return {"status": "error", "message": str(e)}

# ===================== QUANTUM SHIELD (Kyber768) =====================

class KyberLoginRequest(BaseModel):
    capsule: str
    iv: str
    payload: str

@app.get("/api/kyber/key")
def get_kyber_key():
    """Return the server's Kyber768 public key (Base64)."""
    pk = kyber_engine.get_public_key()
    if pk is None:
        raise HTTPException(status_code=503, detail="Kyber engine not available")
    return {"public_key": pk}

@app.post("/api/kyber/login")
def kyber_login(req: KyberLoginRequest):
    """Decrypt a Kyber+AES encrypted login payload."""
    if not kyber_engine.available:
        raise HTTPException(status_code=503, detail="Kyber engine not available")
    try:
        plaintext = kyber_engine.decrypt_payload(req.capsule, req.iv, req.payload)
        data = json.loads(plaintext)
        print(f"QUANTUM LOGIN: user={data.get('username', '?')} -- decrypted successfully")
        return {"status": "SUCCESS", "msg": "WELCOME TO AEGIS [QUANTUM SECURE]"}
    except Exception as e:
        print(f"QUANTUM LOGIN FAILED: {e}")
        raise HTTPException(status_code=401, detail=f"Decryption failed: {e}")

@app.get("/api/kyber/test")
def kyber_self_test():
    """Server-side self-test: keygen -> enc -> dec -> verify."""
    if not kyber_engine.available:
        return {"status": "FAIL", "msg": "Kyber engine not available"}
    try:
        from kyber_py.ml_kem import ML_KEM_768
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        import hashlib, base64

        shared_secret, capsule = ML_KEM_768.encaps(kyber_engine.ek)
        aes_key = hashlib.sha256(shared_secret).digest()

        test_data = b'{"test": "quantum_handshake"}'
        cipher = AES.new(aes_key, AES.MODE_CBC)
        ct = cipher.encrypt(pad(test_data, AES.block_size))

        result = kyber_engine.decrypt_payload(
            base64.b64encode(capsule).decode(),
            base64.b64encode(cipher.iv).decode(),
            base64.b64encode(ct).decode(),
        )
        ok = result == test_data.decode()
        return {
            "status": "PASS" if ok else "FAIL",
            "msg": "Kyber768 + AES-256-CBC handshake verified" if ok else "Decryption mismatch",
            "key_size": f"{len(kyber_engine.ek)}B",
        }
    except Exception as e:
        return {"status": "FAIL", "msg": str(e)}

# ===================== DEMO SIMULATION =====================

@app.post("/simulate-attack")
def demo_simulation(x_aegis_auth: str = Header(None)):
    if x_aegis_auth != API_SECRET:
        raise HTTPException(status_code=403, detail="Access Denied")

    trigger_soar_alert(
        ip="45.33.22.11",
        threat="SIMULATED_NMAP_SCAN",
        severity="CRITICAL",
        details={"tool": "Kali Linux Nmap", "scan_type": "SYN_ACK"}
    )
    return {"status": "Simulation Triggered"}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Aegis-Shift Core Server")
    parser.add_argument("--port", type=int, default=8000, help="Port to run the server on")
    args = parser.parse_args()
    print(f"Starting Aegis-Core on Port {args.port}...")
    uvicorn.run(app, host="0.0.0.0", port=args.port, timeout_keep_alive=3)