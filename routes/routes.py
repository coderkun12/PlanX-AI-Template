from flask import Blueprint, request, jsonify, send_from_directory, session
from controller.user_controller import signup_logic, login_logic, generate_message,check_auth_logic
import os
import secrets
import jwt

routes_bp = Blueprint('routes', __name__) # integrates a modular set of routes and resources (a blueprint) into a flask application.

#JWT_SECRET = os.environ.get("JWT_SECRET_KEY")
JWT_SECRET = secrets.token_hex(32) # generate a secret key for the jwt tokens.

@routes_bp.route('/')
def serve():
    if 'jwt_token' not in session:
        return send_from_directory("static", "index.html")
    return send_from_directory("static", "index.html")

@routes_bp.route('/api/signup', methods=['POST']) # api for sign-up. 
def signup():
    data = request.get_json()
    result, status_code = signup_logic(data)
    return jsonify(result), status_code

@routes_bp.route('/api/login', methods=['POST']) #api for log in.
def login():
    data = request.get_json()
    result, status_code = login_logic(data, JWT_SECRET) 
    if status_code == 200:
        session['jwt_token'] = result['token'] # stores the jwt token ID in session.
    return jsonify(result), status_code

@routes_bp.route('/api/check-auth', methods=['GET']) # api to verify the user before starting the actual process.
def check_auth():
    token = session.get('jwt_token')
    result, status_code = check_auth_logic(token, JWT_SECRET)
    if status_code != 200:
        session.pop('jwt_token', None) # if authentication fails, remove the token.
    return jsonify(result), status_code

@routes_bp.route("/api/sessions/<session_id>/messages",methods=["POST"])
def send_message():
    qa=generate_message(JWT_SECRET)
    return qa 
