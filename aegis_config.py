import os
import pyotp
import time
from dotenv import load_dotenv

load_dotenv()

SHIFT_SECRET = os.getenv("AEGIS_SECRET_KEY")
if not SHIFT_SECRET:
    raise ValueError("CRITICAL ERROR: AEGIS_SECRET_KEY is missing from .env file!")
INTERVAL_SECONDS = 30

def get_current_port():
    """
    Derives a deterministic port number between 20000-20050
    based on the current 30-second time window.
    """
    totp = pyotp.TOTP(SHIFT_SECRET, interval=INTERVAL_SECONDS)
    current_otp = totp.now()
    offset = int(current_otp) % 50
    return 20000 + offset

def get_time_remaining():
    """Returns seconds remaining until next shift."""
    return INTERVAL_SECONDS - (int(time.time()) % INTERVAL_SECONDS)