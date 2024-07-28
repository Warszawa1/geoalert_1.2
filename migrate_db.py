import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv('DATABASE_URL')

def migrate_db():
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    try:
        # Check if columns exist before adding them
        cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name='users'")
        existing_columns = [col[0] for col in cur.fetchall()]

        if 'is_diabetic' not in existing_columns:
            cur.execute("ALTER TABLE users ADD COLUMN is_diabetic BOOLEAN DEFAULT FALSE")
        if 'uses_dexcom' not in existing_columns:
            cur.execute("ALTER TABLE users ADD COLUMN uses_dexcom BOOLEAN DEFAULT FALSE")
        if 'dexcom_username' not in existing_columns:
            cur.execute("ALTER TABLE users ADD COLUMN dexcom_username VARCHAR(80)")
        if 'dexcom_password' not in existing_columns:
            cur.execute("ALTER TABLE users ADD COLUMN dexcom_password VARCHAR(120)")

        conn.commit()
        print("Database migration completed successfully")
    except psycopg2.Error as e:
        print(f"An error occurred during migration: {e}")
        conn.rollback()
    finally:
        cur.close()
        conn.close()

if __name__ == '__main__':
    migrate_db()