import os
import psycopg2
from psycopg2.extras import RealDictCursor
import logging

DATABASE_URL = os.getenv('DATABASE_URL')

def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL)
    return conn, conn.cursor(cursor_factory=RealDictCursor)

def init_db():
    conn, cur = get_db_connection()
    try:
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(80) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                emergency_message TEXT,
                emergency_contacts TEXT,
                alert_message TEXT,
                share_token VARCHAR(36) UNIQUE NOT NULL,
                is_diabetic BOOLEAN DEFAULT FALSE,
                uses_dexcom BOOLEAN DEFAULT FALSE,
                dexcom_username VARCHAR(80),
                dexcom_password VARCHAR(120),
                emergency_token VARCHAR(36),
                emergency_contact_phone VARCHAR(20),
                enable_sms_alerts BOOLEAN DEFAULT FALSE
            )
        ''')
        conn.commit()
        logging.info("Database initialized successfully")
    except psycopg2.Error as e:
        logging.error(f"An error occurred while initializing the database: {e}")
        conn.rollback()
    finally:
        cur.close()
        conn.close()


def create_user(username, password, share_token):
    conn, cur = get_db_connection()
    try:
        cur.execute(
            "INSERT INTO users (username, password, share_token) VALUES (%s, %s, %s)",
            (username, password, share_token)
        )
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        raise ValueError("Username already exists")
    except psycopg2.Error as e:
        conn.rollback()
        raise ValueError(f"Database error: {str(e)}")
    finally:
        cur.close()
        conn.close()


def get_user(username):
    conn, cur = get_db_connection()
    try:
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        return user
    finally:
        cur.close()
        conn.close()


def get_user_by_id(user_id):
    conn, cur = get_db_connection()
    try:
        cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cur.fetchone()
        return user
    finally:
        cur.close()
        conn.close()


def update_user(user_id, **kwargs):
    conn, cur = get_db_connection()
    try:
        update_fields = []
        update_values = []
        for key, value in kwargs.items():
            update_fields.append(f"{key} = %s")
            update_values.append(value)
        
        update_query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = %s"
        update_values.append(user_id)
        
        cur.execute(update_query, update_values)
        conn.commit()
        logging.info(f"User {user_id} updated successfully")
    except Exception as e:
        conn.rollback()
        logging.error(f"Error updating user {user_id}: {str(e)}")
        raise
    finally:
        cur.close()
        conn.close()