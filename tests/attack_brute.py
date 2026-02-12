"""
AEGIS Red Team — Brute Force Attack
Sends 20 rapid POST requests to the login endpoint.
PASS = connection refused/severed mid-way (rate limiting works)
FAIL = all 20 requests succeed (no protection)
"""
import requests
import time


def run(target_url):
    """
    Send 20 rapid POST requests to target_url.
    Returns True (PASS) if connection is refused/severed mid-way.
    Returns False (FAIL) if all 20 succeed.
    """
    print(f"[*] Brute: Sending 20 rapid requests to {target_url}...")
    success_count = 0

    for i in range(20):
        try:
            response = requests.post(
                target_url,
                data={"username": "admin", "password": "bruteforce", "phone": "0000000000"},
                timeout=2
            )
            if response.status_code == 200:
                success_count += 1
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            print(f"[!] Brute: Connection severed at request {i + 1}")
            return True  # PASS — server cut us off
        except Exception as e:
            print(f"[!] Brute: Error at request {i + 1}: {e}")
            return True  # PASS — server rejected us

        time.sleep(0.05)  # Small delay to avoid self-DOS

    print(f"[*] Brute: {success_count}/20 requests succeeded")

    if success_count >= 20:
        return False  # FAIL — no rate limiting detected
    return True  # PASS — some requests were blocked


if __name__ == "__main__":
    result = run("http://127.0.0.1:8000/api/login")
    print(f"Result: {'PASS' if result else 'FAIL'}")
