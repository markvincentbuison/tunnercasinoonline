from psycopg2 import connect, OperationalError
from psycopg2.extras import RealDictCursor
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def get_db_connection():
    try:
        # First try full DATABASE_URL
        database_url = os.getenv("DATABASE_URL")
        if database_url:
            print("Attempting to connect using DATABASE_URL...")
            return connect(
                dsn=database_url,
                cursor_factory=RealDictCursor
            )
        else:
            raise ValueError("DATABASE_URL not set")
    except Exception as e:
        print("Failed with DATABASE_URL, falling back to individual variables. Error:", e)
        try:
            print("Attempting to connect using individual parameters...")
            # For debugging, avoid printing the password here
            print(f"Connecting to database at host: {os.getenv('DB_HOST')}, port: {os.getenv('DB_PORT')}, database: {os.getenv('DB_NAME')}")
            return connect(
                host=os.getenv("DB_HOST"),
                port=os.getenv("DB_PORT"),
                dbname=os.getenv("DB_NAME"),
                user=os.getenv("DB_USER"),
                password=os.getenv("DB_PASSWORD"),
                cursor_factory=RealDictCursor
            )
        except OperationalError as e2:
            print(f"PostgreSQL Connection Error (individual params): {e2}")
            return None