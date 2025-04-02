from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import re
import jwt

def signup_logic(db_cursor, data):
    if db_cursor is None:
        return {"error": "Database not available"}, 500

    if not data or not data.get('email') or not data.get('password'):
        return {"error": "Email and password are required"}, 400

    email = data['email']
    password = data['password']

    email_pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    if not re.match(email_pattern, email):
        return {"error": "Invalid email format"}, 400

    if len(password) < 8:
        return {"error": "Password must be at least 8 characters long"}, 400

    try:
        existing_user_query = "SELECT * FROM Users WHERE email = %s"
        db_cursor.execute(existing_user_query, (email,))
        existing_user = db_cursor.fetchone()

        if existing_user:
            return {"error": "Email already registered"}, 409

        hashed_password = generate_password_hash(password)
        insert_user_query = "INSERT INTO users (email, password_hash) VALUES (%s, %s)"
        db_cursor.execute(insert_user_query, (email, hashed_password))

        return {"message": "User registered successfully"}, 201

    except Exception as e:
        return {"error": str(e)}, 500


def login_logic(db_cursor, data, jwt_secret):
    if db_cursor is None:
        return {"error": "Database not available"}, 500

    if not data or not data.get('email') or not data.get('password'):
        return {"error": "Email and password are required."}, 400

    email = data['email']
    password = data['password']

    try:
        user_query = "SELECT * FROM Users WHERE email = %s"
        db_cursor.execute(user_query, (email,))
        user = db_cursor.fetchone()

        if not user:
            return {"verified": False, "error": "User not found."}, 401

        if not check_password_hash(user['password_hash'], password):
            return {"verified": False, "error": "Invalid password"}, 401

        expiration_time = datetime.utcnow() + timedelta(days=1)
        payload = {
            "email": user["email"],
            "exp": expiration_time
        }
        jwt_token = jwt.encode(payload, jwt_secret, algorithm="HS256")

        return {
            "verified": True,
            "message": "Login Successful",
            "token": jwt_token,
            "user": {
                "email": user["email"],
                "created_at": user['created_at']
            }
        }, 200

    except Exception as e:
        return {"verified": False, "error": str(e)}, 500


def check_auth_logic(db_cursor, token, jwt_secret):
    if db_cursor is None:
        return {"error": "Database not available"}, 500

    if not token:
        return {"authenticated": "False", "error": "User not authenticated"}, 401

    try:
        payload = jwt.decode(token, jwt_secret, algorithms=["HS256"])
        user_email = payload["email"]

        user_query = "SELECT * FROM Users WHERE email = %s"
        db_cursor.execute(user_query, (user_email,))
        user = db_cursor.fetchone()

        if user:
            return {"authenticated": True, "email": user_email}, 200
        else:
            return {"authenticated": False, "error": "User not found."}, 401

    except jwt.ExpiredSignatureError:
        return {"authenticated": False, "error": "Token expired"}, 401
    except jwt.InvalidTokenError:
        return {"authenticated": False, "error": "Invalid token"}, 401
