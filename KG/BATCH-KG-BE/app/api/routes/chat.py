"""Chat API route — the main agentic endpoint (non-streaming)."""

import logging

from fastapi import APIRouter, Depends, HTTPException

from app.agents.orchestrator import LangGraphOrchestrator
from app.api.schemas import ChatRequest, ChatResponse
from app.core.security import require_auth
from app.llm.factory import LLMFactory
from app.mcp.client import MCPClient
from app.services.session_service import SessionStore, get_session_store
from config.settings import get_settings

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("", response_model=ChatResponse, summary="Run agentic chat (blocking)")
async def chat(
    request: ChatRequest,
    _: None = Depends(require_auth),
    store: SessionStore = Depends(get_session_store),
) -> ChatResponse:
    """Process a user question through the LangGraph multi-agent workflow.

    The endpoint:
    1. Creates the LLM via the factory.
    2. Creates an MCPClient for the provided MCP server URL.
    3. Fetches available tools and KG schema from the MCP server.
    4. Runs the LangGraph orchestrator (blocks until complete).
    5. Persists the turn to the session store (when session_id is supplied).
    6. Returns the answer with execution log and plan.

    For real-time feedback, use ``POST /api/v1/chat/stream`` instead.
    """
    # Use default MCP URL from settings if not provided
    settings = get_settings()
    mcp_url = request.mcp_url or settings.mcp_server_url
    llm_provider = request.llm_provider or settings.llm_provider

    logger.info(
        "chat question=%s provider=%s mcp_url=%s session_id=%s",
        request.question[:80],
        llm_provider,
        mcp_url,
        request.session_id,
    )

    try:
        llm = LLMFactory.create_llm(llm_provider)
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=400, detail=f"LLM configuration error: {exc}") from exc

    mcp_client = MCPClient(mcp_url)

    try:
        available_tools = await mcp_client.list_tools(exclude=["execute_cypher_query"])
        kg_schema = await mcp_client.get_schema()
    except Exception as exc:  # noqa: BLE001
        logger.exception("Failed to connect to MCP server: %s", mcp_url)
        raise HTTPException(status_code=502, detail=f"Cannot reach MCP server: {exc}") from exc

    # Load history from session when session_id is provided
    session_id = request.session_id
    history = request.history

    if session_id:
        session = store.get(session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="Session not found or expired.")
        history = session.history()

    orchestrator = LangGraphOrchestrator(
        mcp_client=mcp_client,
        llm=llm,
        checkpointer=store.checkpointer if session_id else None,
    )

    try:
        result = await orchestrator.run(
            question=request.question,
            mcp_server_url=mcp_url,
            available_tools=available_tools,
            kg_schema=kg_schema,
            conversation_history=history,
            thread_id=session_id,
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("Orchestrator failed")
        raise HTTPException(status_code=500, detail=f"Agent error: {exc}") from exc

    # Persist turn to session
    if session_id:
        try:
            store.add_message(session_id, "user", request.question)
            store.add_message(session_id, "assistant", result["answer"])
        except KeyError:
            logger.warning("session.add_message: session %s not found", session_id)

    return ChatResponse(**result, session_id=session_id)
