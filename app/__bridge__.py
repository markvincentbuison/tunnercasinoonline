import os
from flask import Flask
from dotenv import load_dotenv
from datetime import timedelta
from app.extensions.mail import mail
from app.routes.routes import routes
from flask_dance.contrib.google import make_google_blueprint
from flask import Blueprint

#───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# Load environment variables from .env
#───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
load_dotenv()

#───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# OAuth transport configuration (safe for local only)
#───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # ONLY for local dev, not for production

#───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
def create_app():
    app = Flask(__name__)
    app.register_blueprint(routes)
    app.config['SECURITY_PASSWORD_SALT'] = 'your_unique_salt_value'
    app.secret_key = os.getenv("SECRET_KEY", "asdasdasdasdasdasd")  # Default value for development

    # Detect environment
    env = os.getenv("FLASK_ENV", "production")

    # Session config
    if env == "development":
        app.config.update(
            SESSION_COOKIE_SECURE=False,
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_SAMESITE='Lax',
            PERMANENT_SESSION_LIFETIME=timedelta(days=31),
        )
    else:
        app.config.update(
            SESSION_COOKIE_SECURE=True,
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_SAMESITE='None',
            PERMANENT_SESSION_LIFETIME=timedelta(days=31),
        )

    # Set session expiration
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

    # Flask-Mail configuration
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

    app.config['UPLOAD_FOLDER'] = 'static/background/'
    app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

    # Initialize Flask-Mail
    mail.init_app(app)

    #────────────────────────────────────────────────────────────────────────────
    # Google OAuth setup
    #────────────────────────────────────────────────────────────────────────────
    REDIRECT_URI = "https://tunnercasinoonline.onrender.com/callback" if env == "production" else "https://127.0.0.1:5000/callback"

    google_bp = make_google_blueprint(
        client_id=os.getenv("GOOGLE_CLIENT_ID"),
        client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
        redirect_url=REDIRECT_URI,
        scope=["profile", "email"]
    )
    app.register_blueprint(google_bp, url_prefix="/login")

    return app
