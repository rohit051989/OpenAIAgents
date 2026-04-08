"""Session management REST endpoints.

Endpoints
---------
POST   /api/v1/sessions            — create a new session
GET    /api/v1/sessions            — list active sessions
GET    /api/v1/sessions/{id}       — fetch session with full message history
DELETE /api/v1/sessions/{id}       — delete session and its LangGraph checkpoints
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.schemas import SessionCreate, SessionMessageOut, SessionOut
from app.core.security import require_auth
from app.services.session_service import Session, SessionStore, get_session_store

logger = logging.getLogger(__name__)
router = APIRouter()


def _to_out(session: Session, include_messages: bool = False) -> SessionOut:
    return SessionOut(
        id=session.id,
        created_at=session.created_at.isoformat(),
        updated_at=session.updated_at.isoformat(),
        message_count=len(session.messages),
        messages=(
            [SessionMessageOut(**m.to_dict()) for m in session.messages]
            if include_messages
            else []
        ),
    )


@router.post(
    "",
    response_model=SessionOut,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new conversation session",
)
async def create_session(
    payload: SessionCreate,
    _: None = Depends(require_auth),
    store: SessionStore = Depends(get_session_store),
) -> SessionOut:
    session = store.create(metadata=payload.metadata)
    logger.info("session.create id=%s", session.id)
    return _to_out(session)


@router.get(
    "",
    response_model=list[SessionOut],
    summary="List all active sessions",
)
async def list_sessions(
    _: None = Depends(require_auth),
    store: SessionStore = Depends(get_session_store),
) -> list[SessionOut]:
    return [_to_out(s) for s in store.list_all()]


@router.get(
    "/{session_id}",
    response_model=SessionOut,
    summary="Get session with full message history",
)
async def get_session(
    session_id: str,
    _: None = Depends(require_auth),
    store: SessionStore = Depends(get_session_store),
) -> SessionOut:
    session = store.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found or expired.")
    return _to_out(session, include_messages=True)


@router.delete(
    "/{session_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a session",
)
async def delete_session(
    session_id: str,
    _: None = Depends(require_auth),
    store: SessionStore = Depends(get_session_store),
) -> None:
    removed = store.delete(session_id)
    if not removed:
        raise HTTPException(status_code=404, detail="Session not found.")
    logger.info("session.delete id=%s", session_id)
