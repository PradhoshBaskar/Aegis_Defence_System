import requests
import time

# CONFIG
BASE_URL = "http://localhost:8000"
API_KEY = "aegis-hackathon-secret-2026"
HEADERS = {"X-Aegis-Auth": API_KEY}

def run_tests():
    print("🧪 STARTING AEGIS VALIDATION TESTS...\n")

    # Test 1: Legitimate Traffic (Should Pass)
    print("✅ Sending Normal Traffic...")
    try:
        resp = requests.post(
            f"{BASE_URL}/analyze-traffic", 
            params={"req_freq": 10, "packet_size": 500},
            headers=HEADERS
        )
        print(f"   Result: {resp.json()}")
    except: print("   Server Offline")

    time.sleep(1)

    # Test 2: Anomaly Traffic (Should Block)
    print("\n⚠️  Sending MASSIVE Packet (Anomaly)...")
    resp = requests.post(
        f"{BASE_URL}/analyze-traffic", 
        params={"req_freq": 100, "packet_size": 9999}, # HUGE packet
        headers=HEADERS
    )
    print(f"   Result: {resp.json()}")

    time.sleep(1)

    # Test 3: Honeypot (Should Trigger Critical Alert)
    print("\n🍯 Touching the Honeypot (/admin-login)...")
    resp = requests.get(f"{BASE_URL}/admin-login")
    print(f"   Result: {resp.status_code} (Expect 500)")

    print("\n🏁 Validation Complete. Check n8n Dashboard!")

if __name__ == "__main__":
    run_tests()