from flask import Blueprint, request, jsonify
import bcrypt
import jwt
from models.user import User
from flask_jwt_extended import jwt_required, get_jwt_identity
from config.database import db

# You'll need a secret key for JWT.  It's recommended to store this in environment variables.
# For now, a placeholder is used. REPLACE THIS IN PRODUCTION.
SECRET_KEY = "your_super_secret_key_replace_me"

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({"error": "Username already exists"}), 409

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    new_user = User(username=username, password=hashed_password.decode('utf-8'))

    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        token = jwt.encode({'user_id': user.id}, SECRET_KEY, algorithm='HS256')
        return jsonify({"token": token}), 200
    else:
        return jsonify({"error": "Invalid credentials"}), 401

@auth_bp.route('/points', methods=['GET'])
@jwt_required()
def get_points():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if user:
        return jsonify({"username": user.username, "points": user.points}), 200
    else:
        return jsonify({"message": "User not found"}), 404

@auth_bp.route('/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json()
    password = data.get('password')

    # Simple password check for the admin
    if password == 'nebula07':  # Use the specific admin password
        # Generate a JWT token indicating admin status
        admin_token = jwt.encode({'is_admin': True}, SECRET_KEY, algorithm='HS256')
        return jsonify({"admin_token": admin_token}), 200
    else:
        return jsonify({"error": "Invalid admin credentials"}), 401