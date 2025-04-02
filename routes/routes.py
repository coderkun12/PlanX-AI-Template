from flask import Blueprint, request, jsonify, send_from_directory, session
from controller.user_functions import signup_logic, login_logic, check_auth_logic
import os
import mysql.connector
from config.connection import DATABASE_CONFIG  # Import database config
import secrets

routes_bp = Blueprint('routes', __name__)

#JWT_SECRET = os.environ.get("JWT_SECRET_KEY")
JWT_SECRET = secrets.token_hex(32)
# Database Connection
try:
    db_connection = mysql.connector.connect(
        host=DATABASE_CONFIG["host"],
        user=DATABASE_CONFIG["user"],
        password=DATABASE_CONFIG["password"],
        database=DATABASE_CONFIG["database"]
    )
    db_cursor = db_connection.cursor(dictionary=True) # dictionary to get the result as a dict
    print("MySQL connection successful")
except Exception as e:
    print(f"MySQL connection error: {e}")
    db_connection = None
    db_cursor = None

@routes_bp.route('/')
def serve():
    if 'jwt_token' not in session:
        return send_from_directory("static", "index.html")
    return send_from_directory("static", "index.html")

@routes_bp.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    result, status_code = signup_logic(db_cursor, data) # pass the cursor
    if status_code == 201:
        db_connection.commit()
    return jsonify(result), status_code

@routes_bp.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    result, status_code = login_logic(db_cursor, data, JWT_SECRET) #pass the cursor
    if status_code == 200:
        session['jwt_token'] = result['token']
    return jsonify(result), status_code

@routes_bp.route('/api/check-auth', methods=['GET'])
def check_auth():
    token = session.get('jwt_token')
    result, status_code = check_auth_logic(db_cursor, token, JWT_SECRET) #pass the cursor
    if status_code != 200:
        session.pop('jwt_token', None)
    return jsonify(result), status_code
