import requests
import time
import ipaddress
from config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID

# Rate Limiting State
_alert_history = []
MAX_ALERTS_PER_MINUTE = 10

def get_geo_info(ip_address):
    """Fetches Geo-IP information securely for a given IP address."""
    try:
        ip_obj = ipaddress.ip_address(ip_address)
        if ip_obj.is_private or ip_obj.is_loopback:
             return "Local/Private IP"
    except ValueError:
        return "Invalid IP"
         
    try:
        # Upgraded to HTTPS API to prevent MitM attacks
        response = requests.get(f"https://ipwho.is/{ip_obj}", timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data.get("success"):
                return f"{data.get('city', 'Unknown')}, {data.get('country', 'Unknown')} (ISP: {data.get('connection', {}).get('isp', 'Unknown')})"
        return "Unknown Location"
    except Exception as e:
        print(f"[-] Error fetching Geo-IP: {e}")
        return "Unknown Location"

def send_telegram_alert(src_ip, dst_ip, src_port, dst_port, payload_size, confidence_score):
    """Sends a formatted alert message via Telegram with rate limiting."""
    global _alert_history
    
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("[-] Telegram bot token or chat ID not configured or invalid. Skipping alert.")
        return

    # Rate Limiting: Prevent DoS by capping alerts
    current_time = time.time()
    # Keep only alerts from the last 60 seconds
    _alert_history = [t for t in _alert_history if current_time - t < 60]
    
    if len(_alert_history) >= MAX_ALERTS_PER_MINUTE:
        print("[-] Rate limit exceeded for Telegram alerts. Suppressing message.")
        return "Rate Limited"
        
    _alert_history.append(current_time)

    geo_location = get_geo_info(src_ip)

    message = (
        "🚨 *SentinelX-Hunter Anomaly Alert* 🚨\n\n"
        "⚠️ *Alert Type*: Suspicious Network Activity Detected\n"
        f"🌐 *Source IP*: `{src_ip}`\n"
        f"📍 *Source Location*: {geo_location}\n"
        f"🎯 *Destination IP*: `{dst_ip}`\n"
        f"🚪 *Ports*: Src: `{src_port}` -> Dst: `{dst_port}`\n"
        f"📊 *Payload Size*: `{payload_size} bytes`\n"
        f"🤖 *AI Confidence Score*: `{confidence_score:.4f}`"
    )

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }

    try:
        response = requests.post(url, json=payload, timeout=5)
        if response.status_code != 200:
            print(f"[-] Failed to send Telegram alert: {response.text}")
        else:
            print("[+] Telegram alert sent successfully.")
    except Exception as e:
        print(f"[-] Exception while sending Telegram alert: {e}")
    
    return geo_location # return to save in DB
