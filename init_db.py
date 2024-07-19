import os
import psycopg2
from urllib.parse import urlparse

# Get the DATABASE_URL from environment variable
DATABASE_URL = os.environ.get('DATABASE_URL')

# Parse the URL to add sslmode=require if it's not localhost
url = urlparse(DATABASE_URL)
if url.hostname != 'localhost':
    DATABASE_URL = f"{DATABASE_URL}?sslmode=require"

def init_db():
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    try:
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(80) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                emergency_message TEXT,
                emergency_contacts TEXT,
                alert_message TEXT,
                share_token VARCHAR(36) UNIQUE NOT NULL
            )
        ''')
        conn.commit()
        print("Database initialized successfully")
    except Exception as e:
        print(f"An error occurred: {e}")
        conn.rollback()
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    init_db()
    