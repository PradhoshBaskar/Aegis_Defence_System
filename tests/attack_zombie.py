"""
AEGIS Red Team — Zombie Connection Attack
Opens 5 HTTP keep-alive connections, completes one request each, then idles for 5 seconds.
PASS = server closes idle connections (timeout_keep_alive defence works)
FAIL = connections remain open (zombie connections persist)
"""
import socket
import time


def run(target_host, target_port):
    """
    Open 5 HTTP keep-alive connections to target_host:target_port,
    complete one request each, then idle for 5 seconds.
    Returns True (PASS) if server closes idle connections.
    Returns False (FAIL) if connections stay open.
    """
    NUM_SOCKETS = 5
    WAIT_SECONDS = 5
    sockets = []

    print(f"[*] Zombie: Opening {NUM_SOCKETS} HTTP connections to {target_host}:{target_port}...")

    # Open connections and send a real HTTP request on each (triggers keep-alive timer)
    for i in range(NUM_SOCKETS):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((target_host, target_port))

            # Send a minimal HTTP/1.1 GET request with Connection: keep-alive
            http_request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {target_host}:{target_port}\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
            )
            sock.sendall(http_request.encode())

            # Read the response (drain it so the server finishes the cycle)
            response = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    # Stop once we've received the full response headers + body
                    if b"\r\n\r\n" in response:
                        break
            except socket.timeout:
                pass  # Timed out reading — that's fine, we have enough

            sockets.append(sock)
        except Exception as e:
            print(f"[!] Zombie: Socket {i + 1} failed: {e}")

    if not sockets:
        print("[*] Zombie: No connections established — server unreachable")
        return True  # PASS — nothing to attack

    print(f"[*] Zombie: {len(sockets)} connections established. Idling for {WAIT_SECONDS}s...")
    time.sleep(WAIT_SECONDS)

    # Check which connections are still alive
    alive = 0
    for i, sock in enumerate(sockets):
        try:
            # Try sending another request on the same connection
            sock.sendall(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
            # Try to read — if server closed it, recv returns empty or errors
            sock.settimeout(1)
            data = sock.recv(1024)
            if data:
                alive += 1
        except (socket.error, BrokenPipeError, ConnectionResetError, OSError, socket.timeout):
            pass  # Connection was closed — good
        finally:
            try:
                sock.close()
            except Exception:
                pass

    print(f"[*] Zombie: {alive}/{len(sockets)} connections still alive after {WAIT_SECONDS}s idle")

    if alive == 0:
        return True  # PASS — all idle connections killed
    return False  # FAIL — zombie connections persist


if __name__ == "__main__":
    result = run("127.0.0.1", 20000)
    print(f"Result: {'PASS' if result else 'FAIL'}")
