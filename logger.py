import sqlite3
import datetime
import os
from config import DB_FILE

def init_db():
    """Initializes the SQLite database and creates tables if they don't exist."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Table for normal traffic logs (used mostly during training, or for general auditing)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            payload_size INTEGER,
            is_anomaly INTEGER
        )
    ''')

    # Table specifically for alerts
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            payload_size INTEGER,
            confidence_score REAL,
            geo_location TEXT
        )
    ''')

    conn.commit()
    conn.close()
    
    # Restrict permissions to owner only (Read/Write)
    try:
        os.chmod(DB_FILE, 0o600)
    except Exception as e:
        print(f"[-] Warning: Failed to set strict file permissions on DB: {e}")

def log_packet(src_ip, dst_ip, src_port, dst_port, payload_size, is_anomaly=0):
    """Logs a packet to the database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    timestamp = datetime.datetime.now().isoformat()
    
    cursor.execute('''
        INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, payload_size, is_anomaly)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, src_ip, dst_ip, src_port, dst_port, payload_size, is_anomaly))
    
    conn.commit()
    conn.close()

def log_anomaly(src_ip, dst_ip, src_port, dst_port, payload_size, confidence_score, geo_location):
    """Logs an anomalous event specifically to the anomalies table."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    timestamp = datetime.datetime.now().isoformat()
    
    cursor.execute('''
        INSERT INTO anomalies (timestamp, src_ip, dst_ip, src_port, dst_port, payload_size, confidence_score, geo_location)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, src_ip, dst_ip, src_port, dst_port, payload_size, confidence_score, geo_location))
    
    conn.commit()
    conn.close()

# Initialize DB when module is imported
init_db()
