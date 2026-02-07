import time
import uuid
import requests
import uvicorn
import numpy as np
from fastapi import FastAPI, Request, HTTPException, Header
from pydantic import BaseModel
from sklearn.ensemble import IsolationForest

# ================= CONFIGURATION =================
app = FastAPI(title="Aegis-Shift Defense Core")

# 🔑 SECRETS (Replace with your actual Ngrok URL)
N8N_WEBHOOK_URL = "https://YOUR-NGROK-URL.ngrok-free.app/webhook/aegis-alert"
API_SECRET = "aegis-hackathon-secret-2026"

# ================= 🧠 AI BRAIN SETUP =================
print("⚙️  Initializing Aegis Defense Systems...")
print("🧠 Training AI Model (Isolation Forest)...")

# Dummy 'Normal' Traffic Data [Requests_Per_Min, Packet_Size_Bytes]
X_train = np.array([
    [10, 500], [12, 550], [15, 600], [8, 480], 
    [20, 1500], [18, 1600], [5, 400]
])

# Train the Anomaly Detector
clf = IsolationForest(contamination=0.1, random_state=42)
clf.fit(X_train)
print("✅ AI Model Armed & Ready.")

# ================= 🌍 GEO-IP & LOGIC =================
def get_geo_location(ip):
    """Converts IP to City, Country using free API"""
    if ip == "127.0.0.1": return "Localhost (Internal)"
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        return f"{r.get('city', 'Unknown')}, {r.get('country', 'Unknown')}"
    except:
        return "Unknown Location"

def trigger_soar_alert(ip, threat, severity, details):
    """Sends Alert to n8n Orchestrator"""
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
        print(f"🚀 SIGNAL SENT: {threat} from {location}")
        requests.post(N8N_WEBHOOK_URL, json=payload, headers=headers)
    except Exception as e:
        print(f"❌ N8N CONNECTION FAILED: {e}")

# ================= 🛡️ DEFENSE ENDPOINTS =================

@app.get("/")
def home():
    return {"status": "🛡️ Aegis-Shift System Online", "mode": "ACTIVE_DEFENSE"}

# 1. THE HONEYPOT 🍯 (Trap for hackers)
@app.get("/admin-login")
@app.post("/admin-login")
def honeypot_trap(request: Request):
    client_ip = request.client.host
    # INSTANT TRIGGER
    trigger_soar_alert(
        ip=client_ip,
        threat="HONEYPOT_TRIGGERED",
        severity="CRITICAL",
        details={"trap": "Attempted access to fake admin panel"}
    )
    # Fake error to confuse them
    raise HTTPException(status_code=500, detail="Internal Server Error Code: 0x99")

# 2. THE AI GUARD 🤖 (Traffic Analysis)
@app.post("/analyze-traffic")
def analyze(request: Request, req_freq: int, packet_size: int, x_aegis_auth: str = Header(None)):
    # Security Check
    if x_aegis_auth != API_SECRET:
        raise HTTPException(status_code=403, detail="Access Denied")

    # AI Prediction
    prediction = clf.predict([[req_freq, packet_size]])
    
    if prediction[0] == -1: # Anomaly
        client_ip = request.client.host
        trigger_soar_alert(
            ip=client_ip,
            threat="BEHAVIORAL_ANOMALY",
            severity="HIGH",
            details={"freq": req_freq, "size": packet_size, "ai_verdict": "Outlier"}
        )
        return {"status": "BLOCKED", "reason": "AI Detection"}
    
    return {"status": "ALLOWED", "reason": "Traffic Normal"}

# 3. THE DEMO BUTTON 🚨 (For Judges)
@app.post("/simulate-attack")
def demo_simulation(x_aegis_auth: str = Header(None)):
    if x_aegis_auth != API_SECRET:
        raise HTTPException(status_code=403, detail="Access Denied")
        
    trigger_soar_alert(
        ip="45.33.22.11", # Fake IP for demo
        threat="SIMULATED_NMAP_SCAN",
        severity="CRITICAL",
        details={"tool": "Kali Linux Nmap", "scan_type": "SYN_ACK"}
    )
    return {"status": "Simulation Triggered"}

if __name__ == "__main__":
    # Run on 0.0.0.0 so Ngrok can find it
    uvicorn.run(app, host="0.0.0.0", port=8000)