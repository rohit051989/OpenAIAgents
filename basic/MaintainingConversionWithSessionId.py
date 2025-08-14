"""
This demonstrates usage of the `session` parameter (with a session ID) to continue a conversation using persistent storage.
The session object allows the agent to maintain conversation history across multiple user turns, using a SQLite-backed session.

Notes:
1. This approach is useful for long-running or multi-turn conversations, as the session state is stored in a database.
2. Each session is identified by a unique session ID (UUID).
3. The session can be reused across multiple runs to maintain context.

Usage:
    python MaintainingConversionWithSessionId.py

Example:
    User: How Can I help you today?
    Output: (Assistant responds, and conversation continues with context preserved.)
"""
import asyncio

from agents import Agent, Runner, SQLiteSession

from openai.types.responses import ResponseTextDeltaEvent



from typing import Optional
from uuid import uuid4

async def main(user_input: str, session: SQLiteSession):
    agent = Agent(
            name="Assistant",
            instructions="You are a helpful assistant. Be Concise in anwering your question, please complete your answers in less than 500 words." \
            " Please do research on internet to answer the question if you are not sure about the answer.",
        )
    if session:
        print(f"Continuing conversation with previous session ID: {session.session_id}")
        result = Runner.run_streamed(
                agent, 
                user_input,
                session=session
            )
    else:
        print(f"Starting a new conversation for session ID: {session.session_id}")
        result = Runner.run_streamed(agent, user_input)
        

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
    
    