import os
import pathlib
from flask import Blueprint, redirect, session, request, abort
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
from google.auth.transport.requests import Request
from dotenv import load_dotenv
from functools import wraps
from flask import make_response
from app.routes.postgresql import get_db_connection
from flask import render_template
from flask import session
from flask import current_app
import mysql.connector
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_mail import Message
from flask_dance.contrib.google import google
from app.extensions.mail import mail
from app.utils import (generate_token, send_email, send_verification_email, send_reset_email)
import bcrypt
import re
from datetime import datetime, timedelta
import logging
import psycopg2.extras
from flask import current_app as app
from itsdangerous import URLSafeTimedSerializer
from flask import render_template, request, redirect, url_for, flash, session
# =====this below for for render connecting 24/7=====================
import threading
import time
import requests
# =====Upload Picture============================================================================================================
from flask import Flask, request, redirect, url_for, session, render_template
import os
from werkzeug.utils import secure_filename
#--------------------------------------------------------------------------------------------------
# Load environment variables from .env file
load_dotenv()
#--------------------------------------------------------------------------------------------------
# Blueprint setup for Google OAuth routes
routes = Blueprint('routes', __name__)
#--------------------------------------------------------------------------------------------------
# Determine if running in production
IS_PRODUCTION = os.getenv("FLASK_ENV") == "production"
#--------------------------------------------------------------------------------------------------
# Load Google OAuth Client ID from environment
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_OAUTH_CLIENT_ID")
#--------------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------------
# Define CLIENT_SECRETS_FILE globally by using a helper function
def get_client_secrets_file():
    host = request.host
    if "localhost" in host or "127.0.0.1" in host or "192.168." in host or "ngrok" in host:
        return os.path.join(
            pathlib.Path(__file__).parent.parent.parent, 'certs', 'client_secret_dev.json'
        )
    return os.path.join(
        pathlib.Path(__file__).parent.parent.parent, 'certs', 'client_secret_prod.json'
    )
#--------------------------------------------------------------------------------------------------
# Get the redirect URI. Always use the Render callback URL for production.
def get_redirect_uri():
    if IS_PRODUCTION:
        return "https://tunnercasinoonline.onrender.com/callback"
    return "http://127.0.0.1:5000/callback"
#--------------------------------------------------------------------------------------------------
# Login required decorator to ensure user is logged in
def login_is_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Unauthorized if user is not logged in
        return f(*args, **kwargs)
    return decorated_function
#--------------------------------------------------------------------------------------------------
@routes.route("/login/google")
def login_google():
    deployed_url = "tunnercasinoonline.onrender.com"

    # Avoid redirect loop on non-allowed hosts
    if deployed_url not in request.host and "127.0.0.1" not in request.host and "192.168." not in request.host:
        print("Blocked: OAuth login only allowed on deployed or localhost.")
        session.clear()

        # Return a response with expired cookie headers
        response = make_response("Google login not allowed from this host. Please use the official deployed link.")
        response.set_cookie('session', '', expires=0)
        return response

    redirect_uri = get_redirect_uri()
    print(f"Redirect URI being used: {redirect_uri}")

    flow = Flow.from_client_secrets_file(
        client_secrets_file=get_client_secrets_file(),
        scopes=[
            "https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/userinfo.email",
            "openid"
        ],
        redirect_uri=redirect_uri
    )

    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )

    session['state'] = state
    return redirect(authorization_url)
#--------------------------------------------------------------------------------------------------
# Google OAuth callback route
@routes.route("/callback")
def callback():
    print("Google OAuth callback triggered.")
    redirect_uri = get_redirect_uri()
    print(f"Using redirect URI: {redirect_uri}")

    # Debug: Full URL received from Google
    print(f"Authorization Response URL: {request.url}")

    # ✅ Insert ALLOWED_HOSTS check here
    ALLOWED_HOSTS = ["127.0.0.1", "192.168.", "tunnercasinoonline.onrender.com"]
    if not any(host in request.host for host in ALLOWED_HOSTS):
        print("Unauthorized callback host detected. Clearing session and blocking.")
        session.clear()
        response = make_response("OAuth callback not allowed from this host. Please use the official deployed URL.")
        response.set_cookie('session', '', expires=0)
        return response

    try:
        flow = Flow.from_client_secrets_file(
            client_secrets_file=get_client_secrets_file(),
            scopes=[
                "https://www.googleapis.com/auth/userinfo.profile",
                "https://www.googleapis.com/auth/userinfo.email",
                "openid"
            ],
            redirect_uri=redirect_uri
        )

        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials

        print("Verifying ID token...")
        request_obj = Request()
        id_info = id_token.verify_oauth2_token(
            credentials._id_token,
            request_obj,
            GOOGLE_CLIENT_ID
        )
        print("ID token verified!")

        # Store Google user data in session
        session["google_id"] = id_info.get("sub")
        session["name"] = id_info.get("name", "Guest")
        session["email"] = id_info.get("email")
        session["picture"] = id_info.get("picture", "")

        print(f"Logged in as: {session['email']}")

        # Insert user data into PostgreSQL if not already in the database
        from app.routes.postgresql import get_db_connection
        conn = get_db_connection()
        cur = conn.cursor()

        # Check if user already exists by Google ID
        cur.execute("SELECT id FROM users WHERE google_id = %s", (session["google_id"],))
        existing_user = cur.fetchone()

        if not existing_user:
            cur.execute("""
                INSERT INTO users (username, email_address, google_id, picture, is_verified)
                VALUES (%s, %s, %s, %s, %s)
            """, (session["name"], session["email"], session["google_id"], session["picture"], True))
            conn.commit()

        cur.close()
        conn.close()

        # Redirect user to dashboard after successful login
        return redirect("/dashboard")

    except Exception as e:
        print(f"Error during Google login callback: {e}")
        abort(500, f"OAuth callback failed: {e}")
#======================================================================================================================
# ===================== 24/7 Render Keep-Alive ==========================
def ping_self():
    while True:
        try:
            time.sleep(300)  # every 20 minutes
            requests.get("https://tunnercasinoonline.onrender.com/")
        except Exception as e:
            print(f"[Keep-Alive Ping Error] {e}")

keep_alive_thread = threading.Thread(target=ping_self)
keep_alive_thread.daemon = True
keep_alive_thread.start()
#--------------------------------------------------------------------------------------------------
# Logout route to clear the session
@routes.route("/logout")
def logout():
    session.clear()  # Clear the session to log out the user
    return redirect("/")
#--------------------------------------------------------------------------------------------------
# Index route (for demonstration purposes)
@routes.route("/")
def index():
    if "google_id" in session:
        return redirect("/dashboard")
    response = make_response(render_template("index.html"))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response
#--------------------------------------------------------------------------------------------------
# Protected area route (for logged-in users)
@routes.route("/dashboard")
@login_is_required
def dashboard():
    # Get the session data (name, email, etc.)
    name = session.get("name")
    email = session.get("email")
    picture = session.get("picture")
    
    # Check the email verification status from the database
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # First: fetch verification status for the current email
        cursor.execute("SELECT is_verified FROM users WHERE email_address = %s", (email,))
        verification_status = cursor.fetchone()

        # Optional: fetch columns info for debug
        cursor.execute("SELECT * FROM users LIMIT 1")
        columns = [desc[0] for desc in cursor.description]
        print(f"Columns in the users table: {columns}")

    finally:
        cursor.close()
        conn.close()

    # Handle verification status safely
    if verification_status:
        is_verified = verification_status['is_verified']  # <-- fix here
    else:
        is_verified = False  # Default if no result found

    # Pass everything to the template
    return render_template("user_dashboard.html", name=name, email=email, picture=picture, is_verified=is_verified)
#--------------------------------------------------------------------------------------------------
@routes.route('/test-db')
def test_db():
    conn = get_db_connection()
    if conn:
        return "PostgreSQL connected successfully!"
    return "Connection failed."
#--------------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------------
# =================================================================================================================
def validate_username(username):
    if len(username) < 3 or len(username) > 16:
        return "Username must be between 3 and 16 characters."
    if not re.match("^[A-Za-z0-9]*$", username):
        return "Username can only contain letters and numbers."
    return None
#============== Manual Login Dashboard =============================================================================================
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
#============== Manual Login Dashboard =============================================================================================
@routes.route('/login', methods=['POST'])
def login():
    # Prevent logged-in users from going back to login page
    if 'user_id' in session:
        return redirect(url_for('routes.manual_login'))  # Redirect to dashboard if already logged in

    username = request.form['username']
    password = request.form['password']

    # Try creating a connection using get_db_connection
    conn = get_db_connection()
    if conn is None:
        flash('Failed to connect to the database.', 'danger')
        return redirect(url_for('routes.index'))

    try:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()
    except Exception as e:
        print("[DB ERROR]", e)
        flash('Database error occurred.', 'danger')
        return redirect(url_for('routes.index'))
    finally:
        if conn:
            conn.close()

    if user:
        try:
            stored_hash = user[2]  # Assuming 3rd column is password hash
            if stored_hash and isinstance(stored_hash, str):
                stored_hash = stored_hash.encode('utf-8')
                if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                    session['user_id'] = user[0]
                    session['username'] = user[1]
                    session['is_admin'] = user[-2]
                    return redirect(url_for('routes.manual_login'))
                else:
                    flash('Incorrect password.', 'danger')
            else:
                flash('Invalid password format in the database.', 'danger')
        except ValueError as e:
            print("Bcrypt error:", e)
            flash('Invalid password hash. Please contact support.', 'danger')
    else:
        flash('User not found.', 'danger')

    return redirect(url_for('routes.index'))
#=============Manual Login Dashboard==============================================================================================
@routes.route('/dashboard-manual_login')
def manual_login():
    if 'user_id' not in session:
        flash('You need to login to access the system', 'warning')
        return redirect(url_for('routes.index'))
    conn = get_db_connection()
    if not conn:
        flash('Failed to connect to the database', 'danger')
        return redirect(url_for('routes.index'))
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)   
    try:
        cursor.execute("SELECT username, email_address, is_admin, is_verified FROM users WHERE id=%s", (session['user_id'],))
        user = cursor.fetchone()
        if not user:
            flash('No user found. Please log in again.', 'danger')
            return redirect(url_for('routes.logout'))
        username, email, is_admin, is_verified = user
        session['is_admin'] = is_admin
        session['is_verified'] = is_verified
        session['email'] = email
        print(f"User found: {username}, is_admin: {is_admin}, is_verified: {is_verified}, email: {email}")
        if is_verified:
            print(f"User {username} is verified.")
        else:
            print(f"User {username} is not verified. Please check your email.")
        if is_admin:
            print(f"Rendering admin dashboard for {username}")
            return render_template('admin_dashboard.html', username=username, is_verified=is_verified, email=email)
        else:
            picture = 'background/bp1.png'
            print(f"Rendering user dashboard for {username}")
            return render_template('user_dashboard.html', username=username, is_verified=is_verified, email=email, profile_picture=picture)
    except Exception as e:
        print(f"Error: {str(e)}")
        flash('An error occurred while fetching your data. Please try again later.', 'danger')
        return redirect(url_for('routes.index'))
    finally:
        cursor.close()
        conn.close()
#=======================================================================================================================
#=======================================================================================================================
#=======================================================================================================================
#=======================================================================================================================
#=============================================== SIGN UP ===============================================================
#=======================================================================================================================
#=======================================================================================================================
#=======================================================================================================================
#=======================================================================================================================
#=======================================================================================================================
# Signup route
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
import bcrypt
import re
from datetime import datetime, timedelta
from app.utils import generate_token, send_verification_email
import psycopg2.extras

@routes.route('/signup', methods=['POST'])
def signup():
    username = request.form.get('username')
    password = request.form.get('password')
    email_address = request.form.get('email_address')
    confirmation_password = request.form.get('confirm_password')

    # Check if email is provided
    if not email_address:
        flash('Email address is required.', 'danger')
        return redirect(url_for('routes.index'))
    # Validate username
    if (err := validate_username(username)):
        flash(err, 'danger')
        return redirect(url_for('routes.index'))
    # Check if passwords match
    if password != confirmation_password:
        flash('Passwords do not match.', 'danger')
        return redirect(url_for('routes.index'))
    # Password strength validation (example: minimum length of 8 characters)
    if len(password) < 8:
        flash('Password must be at least 8 characters long.', 'danger')
        return redirect(url_for('routes.index'))
    conn = None
    cursor = None
    try:
        # Hash password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        # Generate verification token
        verification_token = generate_token()
        verification_expiry = datetime.utcnow() + timedelta(hours=1)
        conn = get_db_connection()
        cursor = conn.cursor()
        # Check if username or email already exists
        cursor.execute("SELECT * FROM users WHERE username=%s OR email_address=%s", (username, email_address))
        if cursor.fetchone():
            flash('Username or Email already exists.', 'danger')
            return redirect(url_for('routes.index'))
        # Set default profile picture
        default_profile_picture = 'background/bp1.png'
        # Insert new user into database
        cursor.execute("""
            INSERT INTO users (username, password, email_address, verification_token, verification_token_expiry, is_verified, picture)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (username, hashed_password, email_address, verification_token, verification_expiry, False, default_profile_picture))
        conn.commit()
        # Send verification email
        send_verification_email(email_address, verification_token, username)
        flash('Signup successful. Check your email to verify your account.', 'success')
    except Exception as e:
        print(f"Signup error: {e}")
        flash('An error occurred during signup. Please try again.', 'danger')
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
    return redirect(url_for('routes.index'))
#======================================================================================================================
#======================================================================================================================
#======================================================================================================================
#======================================================================================================================
#======================================================================================================================
from flask import render_template, flash, redirect, url_for
from datetime import datetime
from app.utils import confirm_token
from app.routes.routes import get_db_connection  # Adjust the import path if needed
from app.utils import confirm_token, generate_token, send_email
from flask import Blueprint, request, redirect, url_for, flash
from itsdangerous import URLSafeTimedSerializer

@routes.route('/verify-email/<token>')
def verify_email(token):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM users WHERE verification_token=%s", (token,))
        user = cursor.fetchone()
        if user:
            cursor.execute("""
                UPDATE users
                SET is_verified=TRUE, verification_token=NULL
                WHERE verification_token=%s
            """, (token,))
            conn.commit()
            flash("Email verified successfully.", 'success')
            return redirect(url_for('routes.reset_dashboard'))
        else:
            flash("Invalid or expired verification link.", 'danger')
    except Exception as e:
        print(f"Error verifying email: {e}")
        import traceback; traceback.print_exc()
        conn.rollback()
        flash("An error occurred while verifying your email.", 'danger')
    finally:
        cursor.close()
        conn.close()
    return redirect(url_for('routes.index'))

#=======================================================================================================================
@routes.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    print(f"Received token: {token}")  # Debugging
    email = confirm_token(token)
    
    # Debugging to check token validation
    print(f"Email after token confirmation: {email}")  # Debugging
    
    if not email:
        flash("Invalid or expired verification link.", "danger")
        return redirect(url_for('routes.index'))  # Redirect if token is invalid or expired

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # Check if passwords match
        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('routes.reset_password', token=token))  # Stay on the page if passwords don't match

        # Hash the new password before saving it to the database
        hashed_password = hash_password(new_password)

        # Proceed to update the password in the database
        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Debugging SQL execution
            print(f"Executing query to update password for {email}")

            # Update the password for the user
            cursor.execute("""
                UPDATE users
                SET password = %s
                WHERE email_address = %s
            """, (hashed_password, email))
            conn.commit()

            flash("Your password has been reset successfully!", "success")
            return redirect(url_for('routes.index'))  # Redirect to login or home page

        except Exception as e:
            print(f"Password reset error: {e}")
            flash("Something went wrong while resetting the password.", "danger")
            return redirect(url_for('routes.index'))  # Redirect to home if error occurs
        
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    # Render the reset password page with the token to allow password reset
    return render_template('reset_password.html', token=token)

#=======================================================================================================================






















#=======================================================================================================================
#=======================================================================================================================
#=======================================================================================================================
#===========FORGOT PASSWORD PANEL=======================================================================================
#============================FORGOT PASSWORD============================================================================