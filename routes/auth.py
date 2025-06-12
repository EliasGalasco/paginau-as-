from flask import Blueprint, request, jsonify, make_response
import bcrypt
import jwt
from models.user import User
from flask_jwt_extended import jwt_required, get_jwt_identity
from config.database import db
from flask_jwt_extended import get_jwt # Import get_jwt to access claims
from functools import wraps # Import wraps for creating decorators

# You'll need a secret key for JWT.  It's recommended to store this in environment variables.
# For now, a placeholder is used. REPLACE THIS IN PRODUCTION.
SECRET_KEY = "your_super_secret_key_replace_me"

# Decorator to require administrator access
def admin_required(fn):
    @wraps(fn)
    @jwt_required() # Ensure JWT is valid
    def wrapper(*args, **kwargs):
        claims = get_jwt()
        if claims.get('is_admin') is True:
            return fn(*args, **kwargs)
        else:
            return make_response(jsonify({"msg": "Administrator access required"}), 403)
    return wrapper

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

@auth_bp.route('/admin/users/<int:user_id>', methods=['GET'])
@admin_required() # Solo accesible para administradores
def get_user(user_id):
    """Admin route to get a specific user by ID."""
    user = User.query.get(user_id)
    if user:
        return jsonify(user.to_dict()), 200
    else:
        return jsonify({"message": "User not found"}), 404

@auth_bp.route('/admin/users/<int:user_id>', methods=['PUT'])
@admin_required() # Solo accesible para administradores
def update_user(user_id):
    """Admin route to update a specific user by ID."""
    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404

    data = request.get_json()
    # Puedes actualizar los campos que quieras permitir al administrador modificar
    if 'username' in data:
        # Opcional: Añadir validación para username único si permites cambiarlo
        user.username = data['username']
    if 'points' in data:
        # Asegúrate de que los puntos sean un número entero
        try:
            user.points = int(data['points'])
        except (ValueError, TypeError):
            return jsonify({"message": "Invalid points value"}), 400

    # Si permites cambiar la contraseña, NECESITAS HASHEARLA aquí
    # if 'password' in data:
    #     user.password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    db.session.commit()
    return jsonify({"message": "User updated successfully", "user": user.to_dict()}), 200

@auth_bp.route('/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required() # Solo accesible para administradores
def delete_user(user_id):
    """Admin route to delete a specific user by ID."""
    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404

    # Opcional: Decide qué hacer con las reservas de este usuario (eliminarlas, reasignarlas, etc.)
    # Si usas `cascade='all, delete-orphan'` en la relación del modelo User con Booking,
    # eliminar al usuario eliminará automáticamente sus reservas.

    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User deleted successfully"}), 200