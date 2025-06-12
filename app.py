from flask import Flask
from flask_jwt_extended import JWTManager

from routes.auth import auth_bp
from routes.booking import booking_bp # Assuming booking_bp is in routes/booking.py
import os # Import os to potentially get secret key from env vars

app = Flask(__name__)

# Configure Flask-JWT-Extended
app.config["JWT_SECRET_KEY"] = os.environ.get('JWT_SECRET_KEY', 'your_super_secret_jwt_key_please_change') # Change this!
jwt = JWTManager(app)

app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(booking_bp, url_prefix='/api') # Or any other desired prefix

@app.route('/')
def index():
    return "Backend para salón de uñas en funcionamiento"

if __name__ == '__main__':
    app.run(debug=True)