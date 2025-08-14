import asyncio

from agents import Agent, Runner

from openai.types.responses import ResponseTextDeltaEvent

"""This demonstrates usage of the `previous_response_id` parameter to continue a conversation.
The second run passes the previous response ID to the model, which allows it to continue the
conversation without re-sending the previous messages.

Notes:
1. This only applies to the OpenAI Responses API. Other models will ignore this parameter.
2. Responses are only stored for 30 days as of this writing, so in production you should
store the response ID along with an expiration date; if the response is no longer valid,
you'll need to re-send the previous conversation history.
"""


from typing import Optional

async def main(user_input: str, response_id: Optional[str] = None):
    agent = Agent(
            name="Assistant",
            instructions="You are a helpful assistant. Be Concise in anwering your question, please complete your answers in less than 500 words.",
            model="gpt-4o-mini"
        )
    if response_id:
        print(f"Continuing conversation with previous response ID: {response_id}")
        result = Runner.run_streamed(
                agent, 
                user_input,
                previous_response_id=response_id
            )
    else:
        print("Starting a new conversation.")
        result = Runner.run_streamed(agent, user_input)    

    async for event in result.stream_events():
        if event.type == "raw_response_event" and isinstance(event.data, ResponseTextDeltaEvent):
            print(event.data.delta, end="", flush=True)

    print()
    result_id = result.last_response_id
    return result_id


if __name__ == "__main__":
    user_input = input("How Can I help you today?")
    response_id = None
    while user_input.lower() != "exit":
        if user_input.strip() == "":
            print("Please enter a valid input.")
        else:
            response_id = asyncio.run(main(user_input, response_id))
        user_input = input("Is there anything else I can help? (Type 'exit' to quit) ")
    
# How to run this file:
#   python MaintainingConversionWithResponseId.py
# Example 1:
#   User: What is the capital of France?
#   Output: (Assistant answers, and conversation continues with context.)
# Example 2:
#   User: Tell me a must have place to visit.
#   Output: (Assistant answers, using previous context.)
# Example 3:
#   User: exit
#   Output: (Exits the conversation.) 