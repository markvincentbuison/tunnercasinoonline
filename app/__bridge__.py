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

    # Detect environment (set FLASK_ENV=development in .env if needed)
    env = os.getenv("FLASK_ENV", "production")

    # Set the redirect URI based on the environment (local or production)
    if env == "development":
        app.config['GOOGLE_OAUTH_REDIRECT_URI'] = 'http://127.0.0.1:5000/callback'
    else:
        app.config['GOOGLE_OAUTH_REDIRECT_URI'] = 'https://tunnercasinoonline.onrender.com/callback'

    # Session cookie configuration
    if env == "development":
        app.config.update(
            SESSION_COOKIE_SECURE=False,  # Allow HTTP for local dev
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_SAMESITE='Lax',  # 'Lax' works better for local testing
            PERMANENT_SESSION_LIFETIME=timedelta(days=31),
        )
    else:
        app.config.update(
            SESSION_COOKIE_SECURE=True,  # HTTPS only
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_SAMESITE='None',  # Required for cross-site in production
            # SESSION_COOKIE_DOMAIN='.yourdomain.com',  # Optional for prod with custom domain
            PERMANENT_SESSION_LIFETIME=timedelta(days=31),
        )

    #---------------------------------------------------------------------------------------------------
    return app
