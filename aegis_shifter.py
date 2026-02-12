import subprocess
import time
import sys
import uvicorn
from fastapi import FastAPI
import asyncio
from contextlib import asynccontextmanager
import aegis_config

CORE_SCRIPT = "aegis_core.py"
SHIFTER_PORT = 9000

class AegisShifter:
    def __init__(self):
        self.process = None
        self.current_traffic_port = None
        self.last_shift_time = time.time()

    def start_core(self, port):
        """Launches the Aegis Core on a specific port."""
        print(f"SHIFTER: Deploying Core System on Port {port}...")
        self.process = subprocess.Popen([sys.executable, CORE_SCRIPT, "--port", str(port)])
        self.current_traffic_port = port
        self.last_shift_time = time.time()
        print(f"\n   Login:     http://localhost:{port}/login")
        print(f"   Dashboard: http://localhost:{port}/dashboard\n")

    def kill_core(self):
        """Terminates the current Core process."""
        if self.process:
            print(f"SHIFTER: Terminating Port {self.current_traffic_port}...")
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except:
                self.process.kill()

    def rotate(self, reason="AUTO"):
        """Performs a HOT-SWAP Port Shift -- new server starts BEFORE old one dies."""
        new_port = aegis_config.get_current_port()
        time_remaining = aegis_config.get_time_remaining()
        print(f"\nSHIFTER: Rotating To Port {new_port} | Reason: {reason} | Next shift in {time_remaining}s")

        print(f"SHIFTER: Deploying Core System on Port {new_port}...")
        old_process = self.process
        self.process = subprocess.Popen([sys.executable, CORE_SCRIPT, "--port", str(new_port)])

        time.sleep(2)

        if old_process:
            print(f"SHIFTER: Terminating old Port {self.current_traffic_port}...")
            old_process.terminate()
            try:
                old_process.wait(timeout=2)
            except:
                old_process.kill()

        self.current_traffic_port = new_port
        self.last_shift_time = time.time()
        print(f"\n   Login:     http://localhost:{new_port}/login")
        print(f"   Dashboard: http://localhost:{new_port}/dashboard\n")
        return new_port

@asynccontextmanager
async def lifespan(app: FastAPI):
    initial_port = aegis_config.get_current_port()
    print(f"TOTP Port Calculated: {initial_port} (Secret: {aegis_config.SHIFT_SECRET[:4]}...)")
    shifter.start_core(initial_port)
    timer_task = asyncio.create_task(auto_shift_timer())

    yield

    timer_task.cancel()
    shifter.kill_core()

app = FastAPI(lifespan=lifespan)
shifter = AegisShifter()

async def auto_shift_timer():
    """Background task that detects TOTP window changes and shifts port."""
    print("TOTP Auto-Shift active: Checking every second for port changes")
    while True:
        try:
            await asyncio.sleep(1)
            new_port = aegis_config.get_current_port()
            if new_port != shifter.current_traffic_port:
                print(f"\nTOTP window rolled over! Port {shifter.current_traffic_port} -> {new_port}")
                shifter.rotate(reason="TOTP_WINDOW_EXPIRED")
        except asyncio.CancelledError:
            break

@app.post("/trigger-shift")
def trigger_shift():
    new_port = shifter.rotate(reason="n8n_MANUAL_TRIGGER")
    return {"status": "shifted", "new_port": new_port}

@app.get("/current-port")
def current_port():
    """Returns the current active TOTP port."""
    return {
        "active_port": shifter.current_traffic_port,
        "totp_port": aegis_config.get_current_port(),
        "time_remaining": aegis_config.get_time_remaining()
    }

if __name__ == "__main__":
    print(f"Aegis Shifter Active. Listening for commands on Port {SHIFTER_PORT}...")
    uvicorn.run(app, host="0.0.0.0", port=SHIFTER_PORT)