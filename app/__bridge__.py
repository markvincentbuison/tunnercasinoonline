import os
from flask import Flask
from dotenv import load_dotenv
from datetime import timedelta
from app.extensions.mail import mail
from app.routes.routes import routes
from flask_dance.contrib.google import make_google_blueprint

#───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# Load environment variables from .env
#───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
load_dotenv()

#───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# OAuth transport configuration (safe for local only)
#───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # ONLY for local development

#───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
def create_app():
    app = Flask(__name__)
    app.register_blueprint(routes)
    app.config['SECURITY_PASSWORD_SALT'] = 'your_unique_salt_value'
    app.secret_key = os.getenv("SECRET_KEY", "asdasdasdasdasdasd")

    # Detect environment (default: production)
    env = os.getenv("FLASK_ENV", "production")

    # Session configuration
    app.config.update(
        SESSION_COOKIE_SECURE=(env == "production"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='None' if env == "production" else 'Lax',
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    )

    # Flask-Mail configuration
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_USERNAME')

    # File upload configuration
    app.config['UPLOAD_FOLDER'] = 'static/background/'
    app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

    # Initialize Flask-Mail
    mail.init_app(app)

    #────────────────────────────────────────────────────────────────────────────
    # Google OAuth setup with dynamic redirect URL
    #────────────────────────────────────────────────────────────────────────────
    redirect_uri = (
        "https://tunnercasinoonline.onrender.com/callback"
        if env == "production"
        else "https://127.0.0.1:5000/callback"
    )

    google_bp = make_google_blueprint(
        client_id=os.getenv("GOOGLE_CLIENT_ID"),
        client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
        redirect_url=redirect_uri,
        scope=["profile", "email"]
    )
    app.register_blueprint(google_bp, url_prefix="/login")

    return app
