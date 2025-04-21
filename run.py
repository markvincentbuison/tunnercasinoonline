from app.__bridge__ import create_app

# Create the app and run it
app = create_app()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000, ssl_context=('certs/server.crt', 'certs/server.key'))
