import pandas as pd
from sklearn.ensemble import IsolationForest

class MLEngine:
    def __init__(self):
        # We use contamination='auto' for default, but can be adjusted.
        self.model = IsolationForest(n_estimators=100, contamination='auto', random_state=42)
        self.is_trained = False

    def train(self, data_list):
        """
        Trains the Isolation Forest model on the collected normal traffic.
        data_list: List of dictionaries containing packet features.
        """
        if not data_list:
            print("[-] No data collected for training. ML engine cannot be initialized properly.")
            return False

        print(f"[*] Training ML model with {len(data_list)} packets...")
        
        # Convert to DataFrame
        df = pd.DataFrame(data_list)
        
        # Select numeric features for training and strictly typecast to int to prevent injection
        features = df[['src_port', 'dst_port', 'payload_size']].fillna(0).astype(int)
        
        # Fit the model
        self.model.fit(features)
        self.is_trained = True
        print("[+] ML model training completed.")
        return True

    def predict(self, packet_data):
        """
        Predicts if a packet is an anomaly.
        Returns:
            is_anomaly (bool): True if anomaly, False otherwise.
            score (float): Anomaly score (lower means more anomalous).
        """
        if not self.is_trained:
            # If not trained, we can't reliably predict, assume normal
            return False, 0.0

        # Prepare feature with strict type enforcement
        try:
            features = pd.DataFrame([{
                'src_port': int(packet_data.get('src_port', 0)),
                'dst_port': int(packet_data.get('dst_port', 0)),
                'payload_size': int(packet_data.get('payload_size', 0))
            }]).fillna(0).astype(int)
        except (ValueError, TypeError):
            # If data is completely malformed and cannot be cast, assume it's highly anomalous
            return True, -1.0

        # Predict returns 1 for normal, -1 for anomaly
        prediction = self.model.predict(features)[0]
        
        # decision_function returns anomaly score (negative is anomaly)
        score = self.model.decision_function(features)[0]

        is_anomaly = (prediction == -1)
        return is_anomaly, score
