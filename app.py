""""
---------- Flask Routes for Login and Signup ----------
"""

from flask import Flask, render_template, request, jsonify, send_from_directory,session,url_for
import re
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

users_collection=[] #In reality it would be the 'user' list fetched from the database.

app=Flask(__name__)

@app.route('/')
def serve():
    if 'user_email' not in session:
        return send_from_directory(app.static_folder,"index.html")
    return send_from_directory(app.static_folder,"index.html")

#   API for Signup
@app.route('/api/signup',methods=['POST'])
def signup():
    data=request.get_json()
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({"error":"Email and password are required"}),400
    
    email=data['email']
    password=data['password']

    email_pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    if not re.match(email_pattern, email):
        return jsonify({"error": "Invalid email format"}), 400
    
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters long"}), 400
    
    try:
        existing_user=users_collection.find_one({"email":email})
        if existing_user:
            return jsonify({"error":"Email aready registered"}),409
        hashed_password=generate_password_hash(password)
        users_collection.insert_one({
            "email":email,
            "password":hashed_password,
            "created_at":datetime.utcnow()
        })
        session['user_email']=email
        return jsonify({"message":"User registered successfully"}),201
    except Exception as e:
        return jsonify({"error":str(e)}),500

# API to handle user login
@app.route("/api/login",methods=["POST"])
def login():
    data=request.get_json()
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({"error":"Email and password are required."}),400
    email=data['email']
    password=data['password']

    try:
        user=users_collection.findone({"email":email})

        if not user:
            return jsonify({"verified":False,"error":"User not found."}),401
        
        if not check_password_hash(user['password'],password):
            return jsonify({"verified":False,"error":"Invalid password"}),401
        
        session['user_email']=email
        return jsonify({
            "verified":True,
            "message":"Login Sucessful",
            "user":{
                "email":user["email"],
                "created_at":user['created_at']
            }        
            }),200
    except Exception as e:
        return jsonify({"verified":False,"error":str(e)}),500

# API route to authenticate the user. 
@app.route("/api/check-auth",methods=["GET"])
def check_auth():
    user_email=session.get('user_email')
    if not user_email:
        return jsonify({"authenticated":"False","error":"User not authenticated"}),401
    user=users_collection.find_one({"email":user_email})
    if user:
        return jsonify({"authenticated":True,"email":user_email}),200
    else:
        session.pop('user_email',None)
        return jsonify({"authenticated":False,"error":"User not found."}), 401



"""
---------- Vectorization and Vector database ----------
"""
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.vectorstores import FAISS
#   'embedder' is used to create vector embedding of the query. 
embedder=HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
query="What is name of the president?"
embedded_query=embedder.embed_query(query) # Not required if below approach used.
# To search the database:
# 1. Store the data in the FAISS database.
docs=[] # Actually expected to be the document you wish to store in your vectorDB.
db=FAISS.from_documents(docs,embedder)
# 2. TO query the database:
db.similarity_search(query)


"""
---------- MySQL Connection ----------
"""
import mysql.connector
mydb=mysql.connector.connect(
    host="",
    username="",
    password=""
)
dbcursor=mydb.cursor()
dbcursor.execute("QUERY")


"""
---------- Langchain & Langgraph Setup ----------
"""
from langchain_core.messages import HumanMessage, BaseMessage, AIMessage
from langchain.chat_models import init_chat_model
from langchain_core.prompts import ChatMessagePromptTemplate,MessagesPlaceholder
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import START,StateGraph
from langgraph.graph.message import add_messages
from typing import Sequence
from typing_extensions import Annotated, TypedDict
import os

os.environ["GROQ_API_KEY"]="YOUR_GROQ_API_KEY"
model=init_chat_model("llama3-8b-8192",model_provider="groq")
prompt_template=ChatMessagePromptTemplate.from_messages([
    ("system",
     ""),
     MessagesPlaceholder(variable_name="messages")
])
class State(TypedDict):
    messages: Annotated[Sequence[BaseMessage], add_messages]

workflow = StateGraph(state_schema=State)

def call_model(state: State):
    prompt = prompt_template.invoke({"messages": state["messages"]})
    response = model.invoke(prompt)
    return {"messages": [response]}

workflow.add_node("model", call_model)
workflow.add_edge(START, "model")
memory = MemorySaver()
langgraph_app = workflow.compile(checkpointer=memory)