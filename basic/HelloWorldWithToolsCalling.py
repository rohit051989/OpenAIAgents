"""
This script demonstrates an OpenAI Agent that uses tool calling to fetch a user's favourite city and suggest a vacation plan.
The agent uses a function tool to look up the favourite city based on username, and maintains conversation context using a session ID.

Notes:
1. The agent will use the tool to fetch the favourite city if the username is provided.
2. If the username is not available, the agent will ask the user for their favourite city.
3. The session ID allows the conversation to persist across multiple user turns.

Usage:
    python HelloWorldWithToolsCalling.py

Example:
    User: My username is Rohit. Can you suggest a vacation plan?
    Output: (Agent uses the tool to fetch 'NewYork' and suggests a plan.)

    User: My username is Kusum. Where should I go for vacation?
    Output: (Agent uses the tool to fetch 'Washington DC' and suggests a plan.)

    User: Can you help me plan a vacation?
    Output: (Agent asks for your favourite city if username is not provided.)
"""

import asyncio

from agents import Agent, Runner, SQLiteSession, function_tool

from openai.types.responses import ResponseTextDeltaEvent

from typing import Optional
from uuid import uuid4

@function_tool
def fetchFavouriteCity(username: str) -> Optional[str]:

    """Fetch favourite city based on username."""
    if username in "Rohit": 
        return("NewYork")
    elif username in "Kusum":
        return("Washington DC")

async def main(user_input: str, session: SQLiteSession):
    agent = Agent(
            name="Assistant",
            instructions="You are a expert vacation planner." \
            " Use tools to identify the user's favourite city and then suggest a vacation plan based on that." \
            " In case you don't have the username available, Gently ask user about its favourite city.",
            tools=[fetchFavouriteCity],
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
#   python HelloWorldWithToolsCalling.py
# Example 1:
#   User: My username is Rohit. Can you suggest a vacation plan?
#   Output: (Agent uses the tool to fetch 'NewYork' and suggests a plan.)
# Example 2:
#   User: My username is Kusum. Where should I go for vacation?
#   Output: (Agent uses the tool to fetch 'Washington DC' and suggests a plan.)
# Example 3:
#   User: Can you help me plan a vacation?
#   Output: (Agent asks for your favourite city if username is not provided.)
