import time
import sys
from config import AUTO_LEARNING_DURATION, ANOMALY_THRESHOLD
from sniffer import PacketSniffer
from ml_engine import MLEngine
from logger import log_packet, log_anomaly
from notifier import send_telegram_alert

def main():
    print("=======================================")
    print("      SentinelX-Hunter Started         ")
    print("=======================================")

    sniffer = PacketSniffer()
    ml_engine = MLEngine()

    # 1. Start packet sniffer
    sniffer.start()

    # 2. Auto-Learning Phase
    print(f"\n[*] Starting Auto-Learning Phase for {AUTO_LEARNING_DURATION} seconds...")
    learning_end_time = time.time() + AUTO_LEARNING_DURATION
    training_data = []

    try:
        while time.time() < learning_end_time:
            if sniffer.error:
                print(f"\n[!] Aborting: Sniffer encountered an error: {sniffer.error}")
                print("[!] Please ensure Npcap is installed and you are running as Administrator.")
                return

            packet = sniffer.get_packet(timeout=0.5)
            if packet:
                training_data.append(packet)
                # Log normal packet to DB
                log_packet(
                    packet['src_ip'], packet['dst_ip'], 
                    packet['src_port'], packet['dst_port'], 
                    packet['payload_size'], is_anomaly=0
                )
            
            # Simple progress indicator
            remaining = int(learning_end_time - time.time())
            sys.stdout.write(f"\r[*] Auto-learning time remaining: {remaining}s | Packets collected: {len(training_data)}")
            sys.stdout.flush()

        print("\n[*] Auto-Learning Phase completed.")

        # 3. Train the ML Model
        if len(training_data) > 0:
            ml_engine.train(training_data)
        else:
            print("[-] Warning: No network traffic captured during learning phase. Model will use default settings.")
            # Depending on strictness, we might want to exit here, but we'll continue for now.

        # 4. Monitoring Phase
        print("\n[*] Entering Monitoring Phase (Real-Time Threat Detection)...")
        while True:
            if sniffer.error:
                print(f"\n[!] Aborting: Sniffer encountered an error: {sniffer.error}")
                print("[!] Please ensure Npcap is installed and you are running as Administrator.")
                return

            packet = sniffer.get_packet(timeout=1.0)
            if not packet:
                continue

            # Predict anomaly
            is_anomaly, score = ml_engine.predict(packet)

            # We can use the configured ANOMALY_THRESHOLD if we want more strict control,
            # or rely on Scikit-Learn's default boolean output.
            # Here we will use the boolean output but check the threshold as an alternative:
            # if score < ANOMALY_THRESHOLD: ...
            
            if is_anomaly or score < ANOMALY_THRESHOLD:
                print(f"\n[!] ANOMALY DETECTED! IP: {packet['src_ip']} -> {packet['dst_ip']} | Score: {score:.4f}")
                
                # Send alert via Telegram
                geo_loc = send_telegram_alert(
                    packet['src_ip'], packet['dst_ip'], 
                    packet['src_port'], packet['dst_port'], 
                    packet['payload_size'], score
                )

                # Log to anomalies table
                log_anomaly(
                    packet['src_ip'], packet['dst_ip'], 
                    packet['src_port'], packet['dst_port'], 
                    packet['payload_size'], score, geo_loc or "Unknown"
                )
            else:
                # Optionally log normal packets during monitoring (commented out to save DB space)
                # log_packet(packet['src_ip'], packet['dst_ip'], packet['src_port'], packet['dst_port'], packet['payload_size'], 0)
                pass

    except KeyboardInterrupt:
        print("\n[*] Shutting down SentinelX-Hunter...")
    except Exception:
        # Catch all exceptions to prevent sensitive stack trace leakage
        print("\n[-] A critical execution error occurred. Shutting down securely.")
    finally:
        sniffer.stop()
        print("[+] Exit complete.")

if __name__ == "__main__":
    main()
