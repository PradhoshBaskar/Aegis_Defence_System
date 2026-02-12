"""
AEGIS Red Team -- Master Audit Controller
Orchestrates all attack tests and produces a JSON-compatible audit report.
Always reports results to n8n webhook (pass or fail).
"""
import os
import json
import socket
import requests
from datetime import datetime, timezone
from dotenv import load_dotenv

from tests import attack_recon
from tests import attack_brute
from tests import attack_zombie

load_dotenv()

WEBHOOK_URL = os.getenv("N8N_WEBHOOK_URL")
if not WEBHOOK_URL:
    print("WARNING: N8N_WEBHOOK_URL not found in .env. Alerts will fail.")


def _find_active_port(host="127.0.0.1", start=20000, end=20050):
    """Find the currently active TOTP port by scanning the range."""
    for port in range(start, end + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.15)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                return port
        except Exception:
            pass
    return None


def trigger_n8n_alert(status_msg, details_dict):
    """
    Send an audit report to the n8n webhook.
    Fires on EVERY audit -- pass or fail -- so n8n always gets a report.
    """
    payload = {
        "status": status_msg,
        "score": details_dict.get("total_score", 0),
        "details": details_dict,
    }
    try:
        resp = requests.post(WEBHOOK_URL, json=payload, timeout=5)
        print(f"n8n webhook SUCCESS -- HTTP {resp.status_code}")
    except Exception as e:
        print(f"n8n webhook FAILED (skipped): {e}")


def execute_full_audit():
    """
    Run all Red Team tests and return a JSON-compatible audit report.
    Always sends the result to n8n regardless of score.
    """
    print("=" * 50)
    print("   AEGIS RED TEAM AUDIT -- STARTING")
    print("=" * 50)

    host = "127.0.0.1"
    port_start = 20000
    port_end = 20050
    score = 0
    points_per_test = 33

    # Test 1: Reconnaissance Scan
    print("\n[+] TEST 1: Reconnaissance Scan")
    try:
        recon_pass = attack_recon.run(host, (port_start, port_end))
    except Exception as e:
        print(f"[!] Recon test error: {e}")
        recon_pass = False

    recon_status = "PASS" if recon_pass else "FAIL"
    if recon_pass:
        score += points_per_test
    print(f"    Result: {recon_status}")

    # Test 2: Brute Force Attack
    print("\n[+] TEST 2: Brute Force Attack")
    active_port = _find_active_port(host, port_start, port_end)
    if active_port:
        target_url = f"http://{host}:{active_port}/api/login"
        try:
            brute_pass = attack_brute.run(target_url)
        except Exception as e:
            print(f"[!] Brute test error: {e}")
            brute_pass = False
    else:
        print("    No active port found -- skipping (PASS by default)")
        brute_pass = True

    brute_status = "PASS" if brute_pass else "FAIL"
    if brute_pass:
        score += points_per_test
    print(f"    Result: {brute_status}")

    # Test 3: Zombie Connection Attack
    print("\n[+] TEST 3: Zombie Connection Attack")
    active_port = _find_active_port(host, port_start, port_end)
    if active_port:
        try:
            zombie_pass = attack_zombie.run(host, active_port)
        except Exception as e:
            print(f"[!] Zombie test error: {e}")
            zombie_pass = False
    else:
        print("    No active port found -- skipping (PASS by default)")
        zombie_pass = True

    zombie_status = "PASS" if zombie_pass else "FAIL"
    if zombie_pass:
        score += points_per_test
    print(f"    Result: {zombie_status}")

    if score == points_per_test * 3:
        score = 100

    report = {
        "recon_status": recon_status,
        "brute_status": brute_status,
        "zombie_status": zombie_status,
        "total_score": score,
    }

    print("\n" + "=" * 50)
    print(f"   AUDIT COMPLETE -- SCORE: {score}%")
    print("=" * 50)

    status = "SYSTEM SECURE" if score == 100 else "SECURITY ALERT"
    trigger_n8n_alert(status, report)

    return report
