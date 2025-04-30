import psycopg2
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def get_db_connection():
    try:
        db_url = os.getenv("DATABASE_URL")
        if db_url:
            conn = psycopg2.connect(db_url, sslmode='require')
            print("Connected successfully using DATABASE_URL")
            return conn
        else:
            print("DATABASE_URL not found. Falling back to individual credentials.")
            conn = psycopg2.connect(
                host=os.getenv("DB_HOST"),
                database=os.getenv("DB_NAME"),
                user=os.getenv("DB_USER"),
                password=os.getenv("DB_PASSWORD"),
                port=os.getenv("DB_PORT"),
                sslmode='require'
            )
            print("Connected successfully using individual credentials")
            return conn
    except Exception as e:
        print("PostgreSQL Connection Error:", e)
        return None
