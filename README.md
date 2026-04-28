# 🛡️ SentinelX-Hunter

**SentinelX-Hunter** is an advanced, Python-based network monitoring and anomaly detection tool. It actively sniffs network traffic, uses Machine Learning (Isolation Forest) to establish a baseline of "normal" behavior, and triggers real-time Telegram alerts with geolocation data when suspicious activity is detected.

## 🌟 Key Features

- **Real-Time Packet Sniffing**: Uses `scapy` to capture IP packets.
- **AI-Powered Threat Detection**: Leverages `scikit-learn`'s Isolation Forest to identify anomalies such as port scans, data exfiltration, or unauthorized connections.
- **Instant Telegram Alerts**: Sends detailed alert messages containing Source/Destination IPs, Ports, Payload Size, Geolocation (ISP/City/Country), and AI Confidence Scores.
- **Simulation Mode**: A fallback mode that generates synthetic traffic, allowing you to test the AI model and alerting system without requiring administrative privileges or raw socket access.
- **Secure by Design**: Built with defense-in-depth principles. Features strict input validation, absolute path resolution, and secure HTTPS API communication to prevent SSRF, Path Traversal, and MitM attacks. Includes rate limiting to prevent notification spam.
- **SQLite Logging**: Maintains a secure local database of captured packets and flagged anomalies for later forensic analysis.

## 🛠️ Prerequisites

- **Python 3.10+**
- **Npcap / WinPcap** (Windows only): Required for actual network sniffing. [Download Npcap](https://npcap.com/) and install it with "WinPcap API-compatible Mode" enabled.
- **Administrative Privileges**: The script must be run as Administrator (Windows) or root (Linux/macOS) to access raw network sockets.

## 🚀 Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/SentinelX-Hunter.git
   cd SentinelX-Hunter
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Environment Setup:**
   Create a `.env` file in the root directory and add your Telegram bot credentials:
   ```env
   TELEGRAM_BOT_TOKEN=your_bot_token_here
   TELEGRAM_CHAT_ID=your_chat_id_here
   ```

## ⚙️ Configuration

You can tweak the behavior of SentinelX-Hunter in `config.py`:
- `WHITELISTED_IPS`: Add your local gateway or trusted servers to bypass scanning.
- `AUTO_LEARNING_DURATION`: Duration (in seconds) for the ML model to learn normal traffic patterns before actively alerting.
- `SIMULATION_MODE_FALLBACK`: Set to `True` to allow the script to simulate traffic if it cannot access raw sockets.

## 🚦 Usage

Run the script with administrative privileges:

```bash
python main.py
```

### Execution Phases:
1. **Auto-Learning Phase**: The tool will passively collect data to train the Isolation Forest model.
2. **Monitoring Phase**: Once trained, it will monitor live traffic and immediately send Telegram alerts upon detecting anomalies.

## 🛡️ Security Considerations

SentinelX-Hunter is hardened for secure operation:
- **Rate Limiting**: Telegram alerts are capped at 10 per minute to prevent DoS via alert spam.
- **Strict Validation**: All network inputs (IPs, Ports) are rigorously validated and cast to prevent injection vulnerabilities.
- **Data Protection**: The local SQLite database permissions are locked down (read/write by owner only).

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
