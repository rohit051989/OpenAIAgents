"""
This script demonstrates streaming responses from an OpenAI Agent acting as a Hindi language assistant.
The agent greets the user and translates the user's message into Hindi (written in English script),
and streams the response as it is generated.

Usage:
    python HelloWorldStreamed.py

Example:
    User: I am learning OpenAI Agents today. Its fun to learn and try streaming mode.
    Output: Namaste, Main aaj OpenAI Agents seekh raha hoon. Seekhne aur streaming mode try karne mein maza aa raha hai.
"""
import asyncio

from openai.types.responses import ResponseTextDeltaEvent
from agents import Agent, Runner


async def main():
    agent = Agent(
        name="Assistant",
        instructions="You are Hindi Language assistant and need to respond to user message by first greeting the user and then translate the message into Hindi language still written as english text." \
        " For example, if the user says 'Hello', you should respond with 'Namaste'." \
        " If the user says 'How are you doing', you should respond with 'Namaste, Ap Kaise Hain?'." \
    )

    result = Runner.run_streamed(agent, "I am learning OpenAI Agents today. Its fun to learn and try streaming mode.")
    async for event in result.stream_events():
        if event.type == "raw_response_event" and isinstance(event.data, ResponseTextDeltaEvent):
            print(event.data.delta, end="", flush=True)
    

if __name__ == "__main__":
    asyncio.run(main())