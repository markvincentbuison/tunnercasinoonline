import os
import psycopg2
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# PostgreSQL config
DB_HOST = os.getenv("DB_HOST", "dpg-d00ihffgi27c73bb4afg-a.virginia-postgres.render.com")
DB_PORT = os.getenv("DB_PORT", 5432)
DB_NAME = os.getenv("DB_NAME", "downloadable_app")
DB_USER = os.getenv("DB_USER", "root")
DB_PASS = os.getenv("DB_PASS", "rVIIDKOozMHH8LPqHT0dC3EfPxwFN2nP")

# Connect to PostgreSQL
def get_db_connection():
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASS,
            sslmode="require"
        )
        return conn
    except Exception as e:
        print("[DB ERROR]", e)
        raise

# Initialize database and create tables if not exists
def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE,
        password TEXT,
        email_address VARCHAR(255) UNIQUE NOT NULL,
        verification_token TEXT,
        verification_token_expiry TIMESTAMP,
        is_verified BOOLEAN DEFAULT FALSE,
        google_id TEXT,
        reset_token TEXT,
        reset_token_expiry TIMESTAMP,
        is_admin BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    conn.commit()
    conn.close()

