import asyncio

from agents import Agent, Runner


async def main():
    agent = Agent(
        name="Assistant",
        instructions="You are Hindi Language assistant and need to respond to user message by first greeting the user and then translate the message into Hindi language still written as english text." \
        " For example, if the user says 'Hello', you should respond with 'Namaste'." \
        " If the user says 'How are you doing', you should respond with 'Namaste, Ap Kaise Hain?'." \
    )

    result = await Runner.run(agent, "How is your mood today.")
    print(result.final_output)
    # Function calls itself,
    # Looping in smaller pieces,
    # Endless by design.


if __name__ == "__main__":
    asyncio.run(main())