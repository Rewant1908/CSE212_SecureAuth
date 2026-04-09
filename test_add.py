from dotenv import load_dotenv
import os
load_dotenv(os.path.join(os.path.dirname(__file__), 'config', '.env'))

from backend.database import get_connection, execute

def test_add():
    conn = get_connection()
    print("Connected to:", os.getenv('DB_TYPE'))
    try:
        cur = execute(conn, "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)", 
                      ("testuser", "test@d.com", "fakehash", "user"))
        conn.commit()
        print("Success")
    except Exception as e:
        print("Error:", e)

if __name__ == '__main__':
    test_add()
