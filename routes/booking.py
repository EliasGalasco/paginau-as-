from flask import Blueprint, request, jsonify, g
from routes.auth import admin_required
from flask_jwt_extended import jwt_required, get_jwt_identity
from models.booking import Booking
from models.user import User # Import User model
from config.database import db
from datetime import datetime
# You might need dateutil if your time format is complex
# from dateutil import parser


booking_bp = Blueprint('booking', __name__)
# Assuming you will protect booking routes with JWT
# @booking_bp.route('/bookings', methods=['POST'])
# @jwt_required()
# def create_booking():
    # Basic booking creation logic goes here later
    # current_user_id = get_jwt_identity()
    # data = request.get_json()
    # Example: start_time = data.get('start_time'), end_time = data.get('end_time')
    # return jsonify({"message": "Booking creation endpoint (under development)"}), 201

# @booking_bp.route('/bookings', methods=['GET'])
# @jwt_required()
# def get_all_bookings():
    # Basic logic to get all bookings goes here later
    # return jsonify({"message": "Get all bookings endpoint (under development)"}), 200

# @booking_bp.route('/users/<int:user_id>/bookings', methods=['GET'])
# @jwt_required()
# def get_user_bookings(user_id):
    # Basic logic to get bookings for a specific user goes here later
    # return jsonify({"message": f"Get bookings for user {user_id} endpoint (under development)"}), 200

@booking_bp.route('/bookings', methods=['POST'])
@jwt_required() # Require JWT for this route
def create_booking():
    data = request.get_json()
    start_time_str = data.get('start_time')
    end_time_str = data.get('end_time')

    if not start_time_str or not end_time_str:
        return jsonify({"message": "Start time and end time are required"}), 400

    try:
        # Assuming ISO 8601 format (e.g., "2023-10-27T10:00:00")
        start_time = datetime.fromisoformat(start_time_str)
        end_time = datetime.fromisoformat(end_time_str)
        # If using dateutil:
        # start_time = parser.parse(start_time_str)
        # end_time = parser.parse(end_time_str)
    except ValueError:
        return jsonify({"message": "Invalid time format. Use ISO 8601 format."}), 400

    # Check for overlapping bookings
    overlapping_bookings = Booking.query.filter(
        (Booking.start_time < end_time) & (Booking.end_time > start_time)
    ).first()

    if overlapping_bookings:
        return jsonify({"message": "Booking time slot is not available"}), 409

    current_user_id = get_jwt_identity() # Get user ID from JWT

    # Create new booking
    new_booking = Booking(user_id=current_user_id, start_time=start_time, end_time=end_time)

    db.session.add(new_booking)
    db.session.commit()

    print(f"New booking created by user {current_user_id} for {start_time} to {end_time}") # Basic notification

    # Add points to the user
    user = User.query.get(current_user_id)
    if user:
        user.points += 10
        db.session.commit()
        print(f"User {current_user_id} points updated to {user.points}") # Basic notification for points

    return jsonify({"message": "Booking created successfully"}), 201
@booking_bp.route('/bookings', methods=['GET'])
@admin_required()
@jwt_required()
def get_all_bookings():
    # In a real application, you would likely add administrator checks here
    bookings = Booking.query.all()
    # You'll need a way to serialize booking objects to JSON
    # For example, add a .to_dict() method to the Booking model
    return jsonify([booking.to_dict() for booking in bookings]), 200
@booking_bp.route('/users/<int:user_id>/bookings', methods=['GET'])
@jwt_required()
def get_user_bookings(user_id):
    current_user_id = get_jwt_identity()
    # In a real application, you would add administrator checks here
    if current_user_id != user_id:
        return jsonify({"message": "Unauthorized to view these bookings"}), 403
    bookings = Booking.query.filter_by(user_id=user_id).all()
    return jsonify([booking.to_dict() for booking in bookings]), 200