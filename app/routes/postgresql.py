import logging
from psycopg2 import connect
from psycopg2.extras import RealDictCursor
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_db_connection():
    # Try DATABASE_URL first
    database_url = os.getenv("DATABASE_URL")
    if database_url and "sslmode=" not in database_url:
        database_url += "?sslmode=require"

    try:
        if database_url:
            logger.info(f"Trying DATABASE_URL connection: {database_url}")
            return connect(
                dsn=database_url,
                cursor_factory=RealDictCursor
            )
    except Exception as e:
        logger.warning(f"Primary DATABASE_URL connection failed: {e}")

    # Fallback to individual DB variables
    try:
        logger.info(f"Falling back to individual DB vars (host: {os.getenv('DB_HOST')})")
        return connect(
            host=os.getenv("DB_HOST"),
            port=os.getenv("DB_PORT"),
            dbname=os.getenv("DB_NAME"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            sslmode='require',
            cursor_factory=RealDictCursor
        )
    except Exception as e2:
        logger.error(f"PostgreSQL Fallback Connection Error: {e2}")
        return None
