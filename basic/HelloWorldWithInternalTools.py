
import asyncio

from agents import Agent, Runner, SQLiteSession, WebSearchTool

from openai.types.responses import ResponseTextDeltaEvent

from typing import Optional
from uuid import uuid4

"""
This script demonstrates an OpenAI Agent that uses an internal tool (WebSearchTool) to answer user questions with up-to-date information.
The agent maintains conversation context using a session ID.

Notes:
1. The agent will use the WebSearchTool when it needs current information from the web.
2. The session ID allows the conversation to persist across multiple user turns.

Usage:
    python HelloWorldWithInternalTools.py

Example:
    User: What is the latest news in AI research?
    Output: (Agent uses the WebSearchTool to provide up-to-date information.)

    User: Who won the FIFA World Cup in 2022?
    Output: (Agent uses the WebSearchTool to answer.)

    User: Tell me about the weather in New York today.
    Output: (Agent uses the WebSearchTool to provide current weather info.)
"""

async def main(user_input: str, session: SQLiteSession):
    agent = Agent(
            name="Assistant",
            instructions=("You are a helpful assistant. Be concise in answering questions (under 500 words). "
                "Use the WebSearchTool tool when you need up-to-date information."),
            tools=[WebSearchTool()],
            model="gpt-4o-mini"
        )
    
    print(f"Continuing conversation with session ID: {session.session_id}")
    result = Runner.run_streamed(
            agent, 
            user_input,
            session=session
        )
        
    async for event in result.stream_events():
        if event.type == "raw_response_event" and isinstance(event.data, ResponseTextDeltaEvent):
            print(event.data.delta, end="", flush=True)

    print("\n")


if __name__ == "__main__":
    user_input = input("How Can I help you today? ")
    session_id = uuid4().hex  # Generate a new session ID
    session = SQLiteSession(session_id=session_id)
    while user_input.lower() != "exit":
        if user_input.strip() == "":
            print("Please enter a valid input.")
        else:
            asyncio.run(main(user_input, session))
        user_input = input("Is there anything else I can help? (Type 'exit' to quit) ")
    
# How to run this file:
#python HelloWorldWithInternalTools.py

#Example:
#    User: What is the latest news in AI research?
#    Output: (Agent uses the WebSearchTool to provide up-to-date information.)
#
#    User: Who won the FIFA World Cup in 2022?
#    Output: (Agent uses the WebSearchTool to answer.)
#
#    User: Tell me about the weather in New York today.
#    Output: (Agent uses the WebSearchTool to provide current weather info.)
