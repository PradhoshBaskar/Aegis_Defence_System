import requests
import time
import aegis_config

API_KEY = "aegis-hackathon-secret-2026"
HEADERS = {"X-Aegis-Auth": API_KEY}

def get_base_url():
    """Dynamically resolve the current TOTP port."""
    port = aegis_config.get_current_port()
    return f"http://localhost:{port}"

def run_tests():
    base_url = get_base_url()
    print("STARTING AEGIS VALIDATION TESTS...")
    print(f"Current TOTP Port: {base_url}\n")

    # Test 1: Legitimate Traffic (Should Pass)
    print("Sending Normal Traffic...")
    try:
        resp = requests.post(
            f"{base_url}/analyze-traffic",
            params={"req_freq": 10, "packet_size": 500},
            headers=HEADERS
        )
        print(f"   Result: {resp.json()}")
    except: print("   Server Offline")

    time.sleep(1)

    # Test 2: Anomaly Traffic (Should Block)
    print("\nSending MASSIVE Packet (Anomaly)...")
    try:
        base_url = get_base_url()
        resp = requests.post(
            f"{base_url}/analyze-traffic",
            params={"req_freq": 100, "packet_size": 9999},
            headers=HEADERS
        )
        print(f"   Result: {resp.json()}")
    except: print("   Server Offline")

    time.sleep(1)

    # Test 3: Honeypot (Should Trigger Critical Alert)
    print("\nTouching the Honeypot (/admin-login)...")
    try:
        base_url = get_base_url()
        resp = requests.get(f"{base_url}/admin-login")
        print(f"   Result: {resp.status_code} (Expect 200)")
    except: print("   Server Offline")

    print("\nValidation Complete. Check n8n Dashboard!")

if __name__ == "__main__":
    run_tests()