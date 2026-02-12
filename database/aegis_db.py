import mysql.connector
from mysql.connector import Error

DB_CONFIG = {
    "host": "localhost",
    "user": "Pradhosh",
    "password": "root1",
    "database": "aegis_db"
}

def get_connection():
    """Returns a fresh MySQL connection object."""
    try:
        return mysql.connector.connect(**DB_CONFIG)
    except Error as e:
        print(f"DB Connection Error: {e}")
        return None

def log_event(ip, req_type, endpoint, size, confidence, severity):
    """Inserts raw traffic data into traffic_logs table."""
    conn = get_connection()
    if conn:
        try:
            cursor = conn.cursor()
            query = """INSERT INTO traffic_logs
                       (source_ip, request_type, endpoint, payload_size, ai_confidence, severity)
                       VALUES (%s, %s, %s, %s, %s, %s)"""
            cursor.execute(query, (ip, req_type, endpoint, size, confidence, severity))
            conn.commit()
            print(f"SQL Success: Logged {req_type}")
        except Error as e:
            print(f"DB Write Error: {e}")
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close()

def get_recent_logs(limit=50):
    """Retrieves the last X logs for the API/Dashboard."""
    conn = get_connection()
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM traffic_logs ORDER BY timestamp DESC LIMIT %s", (limit,))
            return cursor.fetchall()
        finally:
            cursor.close()
            conn.close()
    return []