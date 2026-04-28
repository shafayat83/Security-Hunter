import os
import re
import ipaddress
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# --- Telegram Configuration ---
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

# Validate Token format to prevent injection/malformed requests
if TELEGRAM_BOT_TOKEN and not re.match(r"^\d+:[A-Za-z0-9_-]+$", TELEGRAM_BOT_TOKEN):
    print("[-] Warning: TELEGRAM_BOT_TOKEN format is invalid. Notifications disabled.")
    TELEGRAM_BOT_TOKEN = ""

# --- Network Sniffing Configuration ---
# If true, the sniffer will automatically generate synthetic traffic if it cannot access raw sockets (e.g. no Admin/Npcap)
SIMULATION_MODE_FALLBACK = True

# List of trusted IP addresses (e.g., local gateway, known servers)
# These IPs will be ignored by the sniffer.
_raw_whitelisted = [
    "127.0.0.1",
    "192.168.1.1",  # Common local gateway
    # Add other trusted IPs here
]

WHITELISTED_IPS = []
for ip in _raw_whitelisted:
    try:
        valid_ip = str(ipaddress.ip_address(ip))
        WHITELISTED_IPS.append(valid_ip)
    except ValueError:
        print(f"[-] Warning: Invalid IP in whitelist ignored: {ip}")

# --- ML Model Configuration ---
# Duration in seconds for the initial auto-learning phase where the model learns "normal" traffic
# Set to 600 (10 minutes) for production. Lower for testing.
AUTO_LEARNING_DURATION = 600

# The threshold for anomaly scoring. Lower values mean more strict (more anomalies detected).
# Scikit-learn's Isolation Forest usually handles this via 'contamination' parameter,
# but we can also use decision_function threshold.
ANOMALY_THRESHOLD = -0.1

# --- Database Configuration ---
# Use absolute path to prevent Path Traversal or DLL Hijacking issues
DB_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "sentinel_logs.db"))
