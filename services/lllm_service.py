# services/langgraph_service.py
from langchain_core.messages import HumanMessage, BaseMessage, AIMessage
from langchain.chat_models import init_chat_model
from langchain_core.prompts import ChatMessagePromptTemplate, MessagesPlaceholder
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import START, StateGraph
from langgraph.graph.message import add_messages
from typing import Sequence
from typing_extensions import Annotated, TypedDict
import os
from dotenv import load_dotenv

def run_langgraph(user_input: str):
    """
    Runs the LangGraph model, loading it each time.
    """
    
    load_dotenv()  # Load variables from .env

    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        raise ValueError("GROQ_API_KEY environment variable not set.")
  # Replace with your actual API key

    model = init_chat_model("llama3-8b-8192", model_provider="groq")
    prompt_template = ChatMessagePromptTemplate.from_messages([
        ("system", "You are a wise assistant which answers the user questions with honesty and composure.s"),
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
    llm = workflow.compile(checkpointer=memory)

    inputs = {"messages": [HumanMessage(content=user_input)]}
    for output in llm.stream(inputs):
        for key, value in output.items():
            if key == "model":
                return value["messages"][0].content
    return None,llm
