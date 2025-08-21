"""
This script demonstrates how to use OpenAI Agents with Azure OpenAI Service.
It sets up the Azure OpenAI client in a separate function and runs a Hindi language assistant agent.

Usage:
    python HelloWorldAzureOpenAI.py

Example:
    User: How is your mood today.
    Output: Namaste, Apka aaj ka mood kaisa hai?

How it works:
    1. The Azure OpenAI client is configured using environment variables in a setup function.
    2. The agent is created and run as usual using the OpenAI Agents SDK.
Azure Setup Steps:
------------------
1. Create an Azure AI Foundry Resource:
   - Go to https://ai.azure.com/allResources
   - Click 'Create New' → Azure AI Foundry resource.
   - Select your subscription, resource group, and region.
   - Resource creation is free.

2. Deploy a Model:
   - Go to 'Model + endpoints' → '+ Deploy Model'.
   - Select the model (e.g., gpt-4o, gpt-4o-mini, llama-3).
   - Deployment is free; you are only billed for usage (per token).

3. Get Access Credentials:
   - Navigate to the deployed model.
   - Note the following:
       - Endpoint URL: https://<your-resource-name>.openai.azure.com/
       - API Key
       - API Version (e.g., 2024-08-01-preview)

4. Set the following environment variables (in your shell or .env file):
   - AZURE_OPENAI_API_KEY
   - OPENAI_API_VERSION
   - AZURE_OPENAI_ENDPOINT
   - AZURE_OPENAI_DEPLOYMENT

"""

import os
import asyncio
from dotenv import load_dotenv
from openai import AsyncAzureOpenAI
from agents import Agent, Runner, set_default_openai_client, OpenAIChatCompletionsModel, set_tracing_disabled

# Step 1: Load environment variables
load_dotenv()

def get_env_var(name: str) -> str:
    value = os.getenv(name)
    if value is None:
        raise ValueError(f"Environment variable '{name}' is not set.")
    return value

def setup_azure_openai_client() -> AsyncAzureOpenAI:
    openai_client = AsyncAzureOpenAI(
        # Below environment key variable need to be setup for this to work
        #api_key=get_env_var("AZURE_OPENAI_API_KEY"),
        #api_version=get_env_var("OPENAI_API_VERSION"),
        #azure_endpoint=get_env_var("AZURE_OPENAI_ENDPOINT"),
        #azure_deployment=get_env_var("AZURE_OPENAI_DEPLOYMENT")
    )
    set_default_openai_client(openai_client)
    set_tracing_disabled(True)
    return openai_client

async def main():
    # Set up the Azure OpenAI client before using agents
    openai_client = setup_azure_openai_client()
    agent = Agent(
        name="Assistant",
        instructions="You are Hindi Language assistant and need to respond to user message by first greeting the user and then translate the message into Hindi language still written as english text." \
        " For example, if the user says 'Hello', you should respond with 'Namaste'." \
        " If the user says 'How are you doing', you should respond with 'Namaste, Ap Kaise Hain?'.",
        model=OpenAIChatCompletionsModel(
            model="gpt-4.1-mini",
            openai_client=openai_client,
        )
    )

    result = await Runner.run(agent, "How is your mood today.")
    print(result.final_output)


if __name__ == "__main__":
    
    asyncio.run(main())

# How to run this file:
#   python HelloWorld.py
# Example 1:
#   User: How is your mood today.
#   Output: Namaste, Apka aaj ka mood kaisa hai?
# Example 2:
#   User: Hello
#   Output: Namaste
# Example 3:
#   User: How are you doing
#   Output: Namaste, Ap Kaise Hain?