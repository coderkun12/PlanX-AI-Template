""" 
---------- Flask Routes for Login and Signup ----------
"""
from flask import Flask
from routes.routes import routes_bp
import os
import secrets
import random

random.seed(42)
app=Flask(__name__)
app.secret_key=secrets.token_hex(32)
app.register_blueprint(routes_bp)

if __name__=="__main__":
    app.run(debug=True)

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