"""
AEGIS Quantum Handshake -- Client Test Script
Simulates a full ML-KEM-768 (Kyber) + AES-256-CBC encrypted login against the running server.

Usage:
    python tests/test_kyber_login.py
"""
import sys
import json
import base64
import hashlib
import socket

import requests
from kyber_py.ml_kem import ML_KEM_768
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def find_active_port(host="127.0.0.1", start=20000, end=20050):
    for port in range(start, end + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.15)
            if s.connect_ex((host, port)) == 0:
                s.close()
                return port
            s.close()
        except Exception:
            pass
    return None


def main():
    print("=" * 55)
    print("   AEGIS QUANTUM HANDSHAKE TEST CLIENT")
    print("=" * 55)

    port = find_active_port()
    if not port:
        print("ERROR: No active Aegis server found on ports 20000-20050")
        sys.exit(1)

    base_url = f"http://127.0.0.1:{port}"
    print(f"\nServer found on port {port}")

    # Step 1: Fetch Server Public Key
    print("\n[1/4] Fetching server public key...")
    resp = requests.get(f"{base_url}/api/kyber/key", timeout=10)
    resp.raise_for_status()
    ek_b64 = resp.json()["public_key"]
    server_ek = base64.b64decode(ek_b64)
    print(f"RECEIVED SERVER PK: {ek_b64[:40]}... ({len(server_ek)} bytes)")

    # Step 2: Encapsulate -- Generate Shared Secret
    print("\n[2/4] Generating quantum tunnel key (ML_KEM_768.encaps)...")
    shared_secret, capsule = ML_KEM_768.encaps(server_ek)
    aes_key = hashlib.sha256(shared_secret).digest()
    print(f"GENERATED QUANTUM TUNNEL KEY: {aes_key.hex()[:32]}...")

    # Step 3: Encrypt Payload with AES-256-CBC
    print("\n[3/4] Encrypting login payload with AES-256-CBC...")
    login_data = json.dumps({
        "username": "admin",
        "password": "quantum_solace"
    }).encode("utf-8")

    cipher = AES.new(aes_key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(login_data, AES.block_size))

    package = {
        "capsule": base64.b64encode(capsule).decode("utf-8"),
        "iv": base64.b64encode(cipher.iv).decode("utf-8"),
        "payload": base64.b64encode(ciphertext).decode("utf-8"),
    }
    print(f"   Capsule : {package['capsule'][:40]}...")
    print(f"   IV      : {package['iv']}")
    print(f"   Payload : {package['payload'][:40]}...")

    # Step 4: Send Encrypted Packet
    print("\n[4/4] SENDING ENCRYPTED PACKET...")
    resp = requests.post(
        f"{base_url}/api/kyber/login",
        json=package,
        timeout=10,
    )

    print(f"\n{'=' * 55}")
    if resp.status_code == 200:
        data = resp.json()
        print(f"SUCCESS: {data}")
    else:
        print(f"SERVER REJECTED: HTTP {resp.status_code}")
        print(f"   Response: {resp.text}")
    print("=" * 55)


if __name__ == "__main__":
    main()
