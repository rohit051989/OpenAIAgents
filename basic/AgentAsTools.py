import asyncio
from agents import Agent, Runner

from agents import function_tool



# Specialized agents

# Tools for billing agent
@function_tool
def get_invoice(user_id: str) -> str:
    """Return a dummy invoice for the given user ID."""
    return f"Invoice for user {user_id}: $123.45, due 2025-09-01."

@function_tool
def process_refund(user_id: str, amount: float) -> str:
    """Process a dummy refund for the given user ID and amount."""
    return f"Refund of ${amount:.2f} processed for user {user_id}."

@function_tool
def get_user_id(user_name: str) -> str:
    """Return a dummy user ID for the given user name."""
    return f"user_{user_name}"

billing_agent = Agent(
    name="BillingAgent",
    instructions="You are a billing specialist. Use your tools to answer billing-related questions, such as invoices, payments, and refunds.",
    handoff_description="Handles billing and payment queries.",
    tools=[get_invoice, process_refund],
    model="gpt-4o-mini"
)


# Tools for tech support agent
@function_tool
def troubleshoot_error(error_code: str) -> str:
    """Return a dummy troubleshooting step for the given error code."""
    return f"For error code {error_code}: Please restart the app and try again."

@function_tool
def check_system_status() -> str:
    """Return a dummy system status."""
    return "All systems are operational. No known outages."

tech_support_agent = Agent(
    name="TechSupportAgent",
    instructions="You are a technical support specialist. Use your tools to answer technical support questions, such as troubleshooting, errors, and setup.",
    handoff_description="Handles technical support queries.",
    tools=[troubleshoot_error, check_system_status],
    model="gpt-4o-mini",

)

# Central support agent using agents as tools
support_agent = Agent(
    name="SupportAgent",
    instructions=(
        "You are a customer support assistant. "
        "You never answer questions directly. "
        "You always use the provided tools to answer the user's question. "
        "Use the BillingAgent for billing questions and the TechSupportAgent for technical support questions."
    ),
    tools=[
        billing_agent.as_tool(
            tool_name="ask_billing",
            tool_description="Use this tool for billing, payment, or invoice questions."
        ),
        tech_support_agent.as_tool(
            tool_name="ask_tech_support",
            tool_description="Use this tool for technical support or troubleshooting questions."
        ),
    ],
    model="gpt-4o-mini"
)

async def main(user_input: str):
    result = await Runner.run(support_agent, user_input)
    print(result.final_output)

if __name__ == "__main__":
    # How to run this file:
    #   python AgentAsTools.py
    # Example 1:
    #   User: I need a copy of my last invoice.
    #   Output: (SupportAgent uses BillingAgent to answer.)
    # Example 2:
    #   User: My app keeps crashing on startup.
    #   Output: (SupportAgent uses TechSupportAgent to answer.)
    user_input = input("How Can I help you today?")
    while user_input.lower() != "exit":
        if user_input.strip() == "":
            print("Please enter a valid input.")
        else:
            asyncio.run(main(user_input))
        user_input = input("Is there anything else I can help? (Type 'exit' to quit) ")