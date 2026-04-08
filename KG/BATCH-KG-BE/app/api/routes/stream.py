"""SSE (Server-Sent Events) streaming endpoint.

``POST /api/v1/chat/stream``

Maps backend :class:`~app.models.events.AgentEvent` objects to SSE frames
consumed by the React ``agentService.streamChatMessage()`` function.

SSE wire format::

    data: {"type":"plan_generated","session_id":"…","plan":{…}}\n\n
    data: {"type":"step_started",…}\n\n
    data: {"type":"step_completed",…}\n\n
    data: {"type":"done","answer":"…"}\n\n
    data: [DONE]\n\n

The ``[DONE]`` sentinel tells the browser the stream has ended so the
frontend can close the reader.

Auth
----
Controlled by the ``require_auth`` dependency (see ``app.core.security``).
When ``API_KEY`` is unset in the environment, auth is bypassed.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse

from app.agents.orchestrator import LangGraphOrchestrator
from app.api.schemas import ChatRequest
from app.core.security import require_auth
from app.llm.factory import LLMFactory
from app.mcp.client import MCPClient
from app.models.events import ErrorEvent
from app.services.session_service import SessionStore, get_session_store
from config.settings import get_settings

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post(
    "/stream",
    summary="Streaming agentic chat (Server-Sent Events)",
    description=(
        "Runs the LangGraph multi-agent workflow and streams typed events as SSE. "
        "Each ``data:`` frame is a JSON-encoded ``AgentEvent`` object. "
        "The stream terminates with a ``data: [DONE]`` sentinel."
    ),
)
async def chat_stream(
    request: ChatRequest,
    _: None = Depends(require_auth),
    store: SessionStore = Depends(get_session_store),
) -> StreamingResponse:
    # ── LLM ────────────────────────────────────────────────────────────────
    # Use default provider from settings if not provided
    settings = get_settings()
    llm_provider = request.llm_provider or settings.llm_provider

    try:
        llm = LLMFactory.create_llm(llm_provider)
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=400, detail=f"LLM configuration error: {exc}") from exc

    # ── MCP ────────────────────────────────────────────────────────────────
    # Use default MCP URL from settings if not provided
    mcp_url = request.mcp_url or settings.mcp_server_url

    mcp_client = MCPClient(mcp_url)
    try:
        available_tools = await mcp_client.list_tools(exclude=["execute_cypher_query"])
        kg_schema = await mcp_client.get_schema()
    except Exception as exc:  # noqa: BLE001
        logger.exception("MCP connect failed url=%s", mcp_url)
        raise HTTPException(status_code=502, detail=f"Cannot reach MCP server: {exc}") from exc

    # ── Session / history ──────────────────────────────────────────────────
    session_id = request.session_id
    history = request.history

    if session_id:
        session = store.get(session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="Session not found or expired.")
        history = session.history()

    # ── Orchestrator ───────────────────────────────────────────────────────
    orchestrator = LangGraphOrchestrator(
        mcp_client=mcp_client,
        llm=llm,
        checkpointer=store.checkpointer if session_id else None,
    )

    # ── SSE generator ──────────────────────────────────────────────────────
    async def _generate():
        final_answer: str | None = None
        done_received = False

        try:
            async for event in orchestrator.stream_run(
                question=request.question,
                mcp_server_url=mcp_url,
                available_tools=available_tools,
                kg_schema=kg_schema,
                conversation_history=history,
                thread_id=session_id,
            ):
                yield f"data: {event.model_dump_json()}\n\n"

                if event.type == "done":
                    final_answer = event.answer  # type: ignore[union-attr]
                    done_received = True

        except Exception as exc:  # noqa: BLE001
            err = ErrorEvent(
                session_id=session_id or "",
                error_code="STREAM_ERROR",
                message=str(exc),
                recoverable=False,
            )
            yield f"data: {err.model_dump_json()}\n\n"
        finally:
            yield "data: [DONE]\n\n"

            # Persist user question + answer to session store
            if session_id and done_received and final_answer is not None:
                try:
                    store.add_message(session_id, "user", request.question)
                    store.add_message(session_id, "assistant", final_answer)
                except KeyError:
                    logger.warning("session.add_message: session %s not found", session_id)

    return StreamingResponse(
        _generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # prevent nginx proxy buffering
        },
    )
