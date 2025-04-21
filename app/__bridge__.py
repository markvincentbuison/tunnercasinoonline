import os
from flask import Flask
from dotenv import load_dotenv
from app.routes.routes import google_bp  # ✅ Corrected import
from datetime import timedelta
#---------------------------------------------------------------------------------------------------
# Load environment variables from .env
load_dotenv()
#---------------------------------------------------------------------------------------------------
def create_app():
    app = Flask(__name__)
    app.secret_key = os.getenv("SECRET_KEY", "your_random_secret_key")  # Default value for development
    app.register_blueprint(google_bp)
    
    # Session cookie configuration
    app.config.update(
        SESSION_COOKIE_SECURE=True,  # Ensures the session cookie is only sent over HTTPS
        SESSION_COOKIE_HTTPONLY=True,  # Prevents JavaScript access to session cookie
        SESSION_COOKIE_SAMESITE='None',  # Necessary for cross-origin cookies
        SESSION_COOKIE_DOMAIN='.127.0.0.1',  # Set the domain to include both IPs for local testing
        PERMANENT_SESSION_LIFETIME=timedelta(days=31),  # Optional: set session expiration
    )
    
    
  #---------------------------------------------------------------------------------------------------
  
    return app

