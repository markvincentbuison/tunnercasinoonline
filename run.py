from dotenv import load_dotenv
import os
from app.__bridge__ import create_app
import sys
sys.stdout.reconfigure(encoding='utf-8')  # Ensures UTF-8 output for emojis/symbols

# Load environment variables from .env file
load_dotenv()

# Create the Flask app
app = create_app()

if __name__ == "__main__":
    # Check if we're running on Render (production)
    if os.getenv('RENDER') is None:  # Local development
        cert_path = os.path.join(os.getcwd(), 'certs', 'server.crt')
        key_path = os.path.join(os.getcwd(), 'certs', 'server.key')

        if os.path.exists(cert_path) and os.path.exists(key_path):
            print("SSL certificates found. Starting app with SSL.")
            app.run(debug=True, host='0.0.0.0', port=5000, ssl_context=(cert_path, key_path))
        else:
            print("SSL certificates not found. Starting app without SSL.")
            app.run(debug=True, host='0.0.0.0', port=5000)
    else:
        print("Running on Render. Starting app without manual SSL.")
        app.run(debug=True, host='0.0.0.0', port=5000)
