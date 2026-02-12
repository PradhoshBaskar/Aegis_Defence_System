import requests
import time
import aegis_config
from colorama import init, Fore, Style

init(autoreset=True)

API_SECRET = "aegis-hackathon-secret-2026"
HEADERS = {"X-Aegis-Auth": API_SECRET}

def run_stream():
    success_count = 0
    fail_count = 0
    start_time = time.time()
    last_port = None

    print(f"{Fore.CYAN}{'='*55}")
    print(f"  AEGIS STREAMER -- Continuous Connection Tracker")
    print(f"{'='*55}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}  Shared Secret: {aegis_config.SHIFT_SECRET[:4]}...")
    print(f"  Time Step:     {aegis_config.INTERVAL_SECONDS}s")
    print(f"  Port Range:    20000-20049")
    print(f"{'='*55}\n")

    while True:
        try:
            port = aegis_config.get_current_port()
            time_remaining = aegis_config.get_time_remaining()
            url = f"http://localhost:{port}/"

            if last_port is not None and port != last_port:
                print(f"\n{Fore.MAGENTA}  SHIFT DETECTED: Port {last_port} -> {port}")
                print(f"     Next shift in {time_remaining}s\n")

            last_port = port

            resp = requests.get(url, headers=HEADERS, timeout=1)

            if resp.status_code == 200:
                success_count += 1
                elapsed = int(time.time() - start_time)
                print(
                    f"{Fore.GREEN}  [PASS] "
                    f"Port {port} | "
                    f"Status {resp.status_code} | "
                    f"Pings: {success_count} | "
                    f"Uptime: {elapsed}s | "
                    f"Next shift: {time_remaining}s"
                )
            else:
                fail_count += 1
                print(
                    f"{Fore.RED}  [FAIL] "
                    f"Port {port} | "
                    f"Status {resp.status_code} | "
                    f"Unexpected response"
                )

        except requests.exceptions.ConnectionError:
            fail_count += 1
            print(
                f"{Fore.YELLOW}  [WAIT] "
                f"Frequency Shift in Progress... "
                f"(Port {port} not ready, retrying in 0.5s)"
            )
            time.sleep(0.5)
            continue

        except requests.exceptions.Timeout:
            fail_count += 1
            print(
                f"{Fore.YELLOW}  [WAIT] "
                f"Request timed out on Port {port}... "
                f"(server may be rebooting)"
            )
            time.sleep(0.5)
            continue

        except KeyboardInterrupt:
            elapsed = int(time.time() - start_time)
            print(f"\n\n{Fore.CYAN}{'='*55}")
            print(f"  STREAM SESSION REPORT")
            print(f"{'='*55}")
            print(f"{Fore.GREEN}  Successful Pings:  {success_count}")
            print(f"{Fore.YELLOW}  Failed/Retries:    {fail_count}")
            print(f"{Fore.WHITE}  Total Uptime:      {elapsed}s")
            if success_count + fail_count > 0:
                rate = (success_count / (success_count + fail_count)) * 100
                print(f"  Success Rate:      {rate:.1f}%")
            print(f"{Fore.CYAN}{'='*55}{Style.RESET_ALL}")
            break

        time.sleep(1)

if __name__ == "__main__":
    run_stream()
