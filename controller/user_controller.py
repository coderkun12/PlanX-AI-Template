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

def save_message(session_id, message, sender,user_email):
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
    ) # Push the data onto database with the data from current session which includes the user and bot response. Helpful as it allows the llm to have a long term memory when fetched from database.     

def generate_bot_response(session_id, user_input):
    history = [] # History is a list where we can store the the chats and then generate the response from the bot.
    history.append(HumanMessage(content=user_input))

    # Generate response
    val, langgraph_app = run_langgraph() # run_langraph returns the created LLM which we can access for our functionality of chatbot.
    state = {'messages': history} 
    response = langgraph_app.invoke(
        state,
        config={"configurable": {"thread_id": session_id}}
    ) # Get the response from the chatbot. We need the session_id as it allows us to create a database entry of user oriented chats.
    answer = response['messages'][-1].content if response['messages'] else "No response" # Extract the LLM answer.
    formatted_answer = answer.replace("\u2022", "\n•") # This is not important and can be made better. The purpose is to make sure that points go onto new line.
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
        existing_user= session.query(User).filter_by(email=email).first() # Check if the user already exists. 

        if existing_user:
            return {"error": "Email already registered"}, 409 # If user already exists return error.

        hashed_password = generate_password_hash(password)
        new_user=User(email=email,password_hash=hashed_password)
        session.add(new_user) # Add the new user to the database.
        session.commit() # Confirm the change to the database.

        return {"message": "User registered successfully"}, 201

    except IntegrityError:
        session.rollback() # Roll back if there is a error in case of the integrity.
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
        user=session.query(User).filter_by(email=email).first() # Get the details of user trying to login from the database.

        if not user:
            return {"verified": False, "error": "User not found."}, 401 # Return a error if the user doesn't exist.

        if not check_password_hash(user.password_hash, password):
            return {"verified": False, "error": "Invalid password"}, 401 # Try to match the password if that fails returns a error.

        expiration_time = datetime.utcnow() + timedelta(days=1) # Creates a time period of 24 hours to keep the token alive.
        payload = {
            "email": user.email,
            "exp": expiration_time
        } # Create the payload for the JWT token.
        jwt_token = jwt.encode(payload, jwt_secret, algorithm="HS256") # Encode the payload using the secret key and the specified algorithm.

        return {
            "verified": True,
            "message": "Login Successful",
            "token": jwt_token,
            "user": {
                "email": user.email,
                "created_at": user.created_at
            }
        }, 200 # Return to the user that login was successful and associated details.

    except Exception as e:
        return {"verified": False, "error": str(e)}, 500


def check_auth_logic(token, jwt_secret):
    if not token: # Check if token is none meaning the user log-in sessionw wasn't created.
        return {"authenticated": "False", "error": "User not authenticated"}, 401

    try:
        payload = jwt.decode(token, jwt_secret, algorithms=["HS256"]) # Decode the token to get the user-email.
        user_email = payload["email"]

        user=session.query(User).filter_by(email=user_email).one()

        if user:
            return {"authenticated": True, "email": user_email}, 200 # If user exists authenticate him/her.
        else:
            return {"authenticated": False, "error": "User not found."}, 401 # If user doesnt exist return a error.
 
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
    user_input = data.get('message') # Get the message.
    session_id = data.get('session_id')  # Get session_id from request

    if not user_input:
        return jsonify({'error': "No Message provided"}), 400

    # Extract JWT Token and Decode
    auth_header = request.headers.get('Authorization') # Get the token from the JWT payload sotaht user can be authenticated.
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split('Bearer ')[1]
    else:
        token = None

    user_email = None # Define the variable user_token. 
    if token:
        try:
            decoded_token = jwt.decode(token, jwt_secret, algorithms=['HS256']) # Decode the token to be able to fetch the user email.
            user_email = decoded_token.get('email')
            
        except jwt.ExpiredSignatureError:
            return jsonify({'error': "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': "Invalid token"}), 401

    # Generate Session ID (if not provided)
    if not session_id:
        session_id = str(uuid.uuid4())

    save_message(session_id, user_input, 'user', user_email) # Save User Message
    bot_response = generate_bot_response(session_id, user_input) # Generate Bot Response
    save_message(session_id, bot_response, 'bot', jwt_secret, user_email) # Save Bot Response

    return jsonify({
        'user_message': user_input,
        'bot_message': bot_response,
        'session_id': session_id  
    }), 200 # Return the query and response.


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
