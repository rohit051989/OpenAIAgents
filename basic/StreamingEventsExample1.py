
import asyncio

from agents import Agent, Runner, WebSearchTool, ItemHelpers

from openai.types.responses import ResponseTextDeltaEvent

from uuid import uuid4

async def main(user_input: str):
    agent = Agent(
            name="WebSearchTool Agent",
            instructions=("You are a helpful assistant. Be concise in answering questions (under 500 words). "
                "Use the WebSearchTool tool when you need up-to-date information."),
            tools=[WebSearchTool()],
            model="gpt-4o-mini"
        )
    
    
    result = Runner.run_streamed(
            agent, 
            user_input
        )
    print("Printing result as RawResponseStreamedEvents \n")  
    async for event in result.stream_events():
        if event.type == "raw_response_event" and isinstance(event.data, ResponseTextDeltaEvent):
            print(event.data.delta, end="", flush=True)

    print("\n")

    result = Runner.run_streamed(
            agent, 
            user_input
        )
    print("Printing result as RunItemStreamEvent \n")  
    async for event in result.stream_events():
        # We'll ignore the raw responses event deltas
        if event.type == "raw_response_event":
            continue
        # When the agent updates, print that
        elif event.type == "agent_updated_stream_event":
            print(f"Agent updated: {event.new_agent.name}")
            continue
        # When items are generated, print them
        elif event.type == "run_item_stream_event":
            if event.item.type == "tool_call_item":
                print("-- Tool was called")
            elif event.item.type == "tool_call_output_item":
                print(f"-- Tool output: {event.item.output}")
            elif event.item.type == "message_output_item":
                print(f"-- Message output:\n {ItemHelpers.text_message_output(event.item)}")
            else:
                pass  # Ignore other event types

    print("\n")


if __name__ == "__main__":
    user_input = input("How Can I help you today? ")
    while user_input.lower() != "exit":
        if user_input.strip() == "":
            print("Please enter a valid input.")
        else:
            asyncio.run(main(user_input))
        user_input = input("Is there anything else I can help? (Type 'exit' to quit) ")
    
