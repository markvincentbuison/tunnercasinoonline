import random
import string
import re
import bcrypt
from flask_mail import Message
from flask import url_for
from app.extensions.mail import mail
import secrets

# ============================================
# Helper Functions
# ============================================

def generate_token(length=32):
    """Generates a secure random token of specified length."""
    return secrets.token_urlsafe(length)


def send_email(subject, body, recipient_email):
    """Sends an email with the given subject, body, and recipient."""
    msg = Message(subject=subject, recipients=[recipient_email])
    msg.body = body
    try:
        mail.send(msg)
        print(f"[✓] Email sent to {recipient_email}")
    except Exception as e:
        print(f"[!] Failed to send email to {recipient_email}: {e}")

# =============================================================================================================
def send_verification_email(email, token, username):
    subject = "Verify Your Email - TunNer"
    verification_link = f"https://tunnercasinoonline.onrender.com/verify-email/{token}"

    body = f"""
Hi {username},

🎉 Welcome to TunNer! We're excited to have you on board.

To complete your registration, please verify your email address by clicking the link below:
🔗 {verification_link}

This link will expire in 1 hour. If you didn’t sign up for TunNer, please ignore this email.

Cheers,  
✨ The TunNer Team
"""
    send_email(subject, body, email)
# =============================================================================================================
def send_reset_email(email, token, username):
    """Sends a password reset email with a reset token."""
    reset_link = url_for('routes.reset_password', token=token, _external=True)
    subject = "Password Reset Request"
    body = f"""Hi {username},

You requested a password reset. Click the link below to reset your password:

{reset_link}

If you did not request this, you can safely ignore this email.

Best regards,
TunNer Team
"""
    send_email(subject, body, email)
# =============================================================================================================

def validate_username(username):
    """Validates the username based on length and allowed characters."""
    if len(username) < 3 or len(username) > 11:
        return "Username must be between 3 and 11 characters."
    if not re.match("^[A-Za-z0-9]*$", username):
        return "Username can only contain letters and numbers."
    return None


def hash_password(password):
    """Hashes the password using bcrypt and returns the hashed password."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)


def verify_password(password, hashed_password):
    """Verifies the provided password against the stored hashed password."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)


def get_user_by_email(email):
    """Fetches the user from the database by email."""
    # Replace with actual DB query to get the user by email.
    pass

def create_user(name, email, hashed_password, verified=False):
    """Creates a new user in the database."""
    # Replace with actual DB logic to create the user.
    pass

def verify_user_by_token(token):
    """Verifies the token for email verification or reset."""
    # Implement actual token verification logic.
    pass

def update_user_verification_status(email):
    """Updates the user’s verification status in the database."""
    # Implement logic to update the user's verified status.
    pass

def update_user_password(email, hashed_password):
    """Updates the user’s password in the database."""
    # Implement logic to update the user's password.
    pass



def get_serializer():
    return URLSafeTimedSerializer(routes.config['SECRET_KEY'])

def confirm_token(token, expiration=3600):
    serializer = get_serializer()
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=expiration)
    except Exception as e:
        print(f"Token confirmation error: {e}")
        return None
    return email