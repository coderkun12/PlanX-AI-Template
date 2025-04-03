from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import re
from langchain_core.messages import HumanMessage, BaseMessage, AIMessage
from flask import request, jsonify,current_app
import jwt
from services.lllm_service import  run_langgraph
import datetime
import uuid
from sqlalchemy.exc import IntegrityError, NoResultFound
import jwt
from services.database_service import session
from models.schema import User
from flask import request

def save_message(session_id, message, sender,user_email): # added user_email
    # ... (JWT decoding remains the same) ...

    update_data = {
        "$push": {"messages": {"sender": sender, "content": message, "timestamp": datetime.utcnow()}},
        "$set": {"last_updated": datetime.utcnow()}
    }

    # Add user_email to the document if available
    if user_email:
        update_data["$set"]["user_email"] = user_email

    chat_collection.update_one(
        {"session_id": session_id},
        update_data,
        upsert=True
    )

def generate_bot_response(session_id, user_input):
    history = []
    history.append(HumanMessage(content=user_input))

    # Generate response
    val, langgraph_app = run_langgraph()
    state = {'messages': history}
    response = langgraph_app.invoke(
        state,
        config={"configurable": {"thread_id": session_id}}
    )
    answer = response['messages'][-1].content if response['messages'] else "No response"
    formatted_answer = answer.replace("\u2022", "\n•")

    return formatted_answer

def signup_logic(data):
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
        existing_user= session.query(User).filter_by(email=email).first()

        if existing_user:
            return {"error": "Email already registered"}, 409

        hashed_password = generate_password_hash(password)
        new_user=User(email=email,password_hash=hashed_password)
        session.add(new_user)
        session.commit()

        return {"message": "User registered successfully"}, 201

    except IntegrityError:
        session.rollback()
        return {"error":"Email already registered."}, 500
    except Exception as e:
        session.rollback()
        return {"error":str(e)},500


def login_logic(data, jwt_secret):
    if not data or not data.get('email') or not data.get('password'):
        return {"error": "Email and password are required."}, 400

    email = data['email']
    password = data['password']

    try:
        user=session.query(User).filter_by(email=email).first()

        if not user:
            return {"verified": False, "error": "User not found."}, 401

        if not check_password_hash(user.password_hash, password):
            return {"verified": False, "error": "Invalid password"}, 401

        expiration_time = datetime.utcnow() + timedelta(days=1)
        payload = {
            "email": user.email,
            "exp": expiration_time
        }
        jwt_token = jwt.encode(payload, jwt_secret, algorithm="HS256")

        return {
            "verified": True,
            "message": "Login Successful",
            "token": jwt_token,
            "user": {
                "email": user.email,
                "created_at": user.created_at
            }
        }, 200

    except Exception as e:
        return {"verified": False, "error": str(e)}, 500


def check_auth_logic(token, jwt_secret):
    if not token:
        return {"authenticated": "False", "error": "User not authenticated"}, 401

    try:
        payload = jwt.decode(token, jwt_secret, algorithms=["HS256"])
        user_email = payload["email"]

        user=session.query(User).filter_by(email=user_email).one()

        if user:
            return {"authenticated": True, "email": user_email}, 200
        else:
            return {"authenticated": False, "error": "User not found."}, 401

    except jwt.ExpiredSignatureError:
        return {"authenticated": False, "error": "Token expired"}, 401
    except jwt.InvalidTokenError:
        return {"authenticated": False, "error": "Invalid token"}, 401
    except NoResultFound:
        return {"authenticated":False,"error":"User not found."}, 401
    except Exception as e:
        return {"authenticated":False,"error":str(e)},500 
    


def generate_message(jwt_secret):
    data = request.json
    user_input = data.get('message')
    session_id = data.get('session_id')  # Get session_id from request

    if not user_input:
        return jsonify({'error': "No Message provided"}), 400

    # Extract JWT Token and Decode
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split('Bearer ')[1]
    else:
        token = None

    user_email = None
    if token:
        try:
            decoded_token = jwt.decode(token, jwt_secret, algorithms=['HS256'])
            user_email = decoded_token.get('email')
        except jwt.ExpiredSignatureError:
            return jsonify({'error': "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': "Invalid token"}), 401

    # Generate Session ID (if not provided)
    if not session_id:
        session_id = str(uuid.uuid4())

    # Save User Message
    save_message(session_id, user_input, 'user', user_email)

    # Generate Bot Response
    bot_response = generate_bot_response(session_id, user_input)

    # Save Bot Response
    save_message(session_id, bot_response, 'bot', jwt_secret, user_email)

    return jsonify({
        'user_message': user_input,
        'bot_message': bot_response,
        'session_id': session_id  
    }), 200


"""
BELOW  IS THE SAMPLE CREATION OF THE VECTOR DATABASE AND 
HOW CAN WE EMBED OUR DATA AND HOW WE CAN QUERY THE DATA AND STORE EMBEDDED DATA IN IT. 

from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS

#   'embedder' is used to create vector embedding of the query. 
embedder=HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
query="What is name of the president?"
embedded_query=embedder.embed_query(query) # Not required if below approach used.

# ----- To search the database ------

# 1. Store the data in the FAISS database.
docs=[] # Actually expected to be the document you wish to store in your vectorDB.
db=FAISS.from_documents(docs,embedder)

# 2. TO query the database:
db.similarity_search(query)"

"""
