"""
AEGIS Red Team — Reconnaissance Scan
Scans a range of ports on the target host.
PASS = 0 or 1 open port (stealth mode working)
FAIL = >1 open ports (port leakage detected)
"""
import socket


def run(target_host, port_range):
    """
    Scan ports on target_host within port_range (tuple: start, end).
    Returns True (PASS) if 0-1 ports found, False (FAIL) if >1.
    """
    start_port, end_port = port_range
    open_ports = []

    print(f"[*] Recon: Scanning {target_host} ports {start_port}-{end_port}...")

    for port in range(start_port, end_port + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            result = sock.connect_ex((target_host, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except Exception:
            pass

    found = len(open_ports)
    print(f"[*] Recon: Found {found} open port(s): {open_ports}")

    # PASS if 0 or 1 port visible — MTD is hiding the surface
    return found <= 1


if __name__ == "__main__":
    result = run("127.0.0.1", (20000, 20050))
    print(f"Result: {'PASS' if result else 'FAIL'}")
