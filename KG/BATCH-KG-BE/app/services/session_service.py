"""In-memory session store with LangGraph MemorySaver integration.

Design goals
------------
- Zero external dependencies — starts without any database configuration.
- Thread-safe via a single ``threading.Lock``.
- LangGraph checkpoints are scoped by ``thread_id == session.id`` so an
  interrupted workflow can be resumed on the next request to the same session.
- The store is intentionally replaceable: subclass :class:`SessionStore` and
  swap it in ``app/main.py`` ``lifespan()`` to add Redis / Postgres persistence.

Session lifecycle
-----------------
1. ``POST /api/v1/sessions``    → ``create()``
2. ``POST /api/v1/chat``       → ``get()`` / ``add_message()``
3. ``GET  /api/v1/sessions/{id}`` → ``get()`` with full history
4. ``DELETE /api/v1/sessions/{id}`` → ``delete()``
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from langgraph.checkpoint.memory import MemorySaver


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SessionMessage:
    role: str          # "user" | "assistant"
    content: str
    timestamp: datetime = field(default_factory=_now)

    def to_dict(self) -> dict[str, str]:
        return {
            "role": self.role,
            "content": self.content,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class Session:
    id: str = field(default_factory=lambda: str(uuid4()))
    created_at: datetime = field(default_factory=_now)
    updated_at: datetime = field(default_factory=_now)
    messages: list[SessionMessage] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def touch(self) -> None:
        self.updated_at = _now()

    def add_message(self, role: str, content: str) -> None:
        self.messages.append(SessionMessage(role=role, content=content))
        self.touch()

    def history(self, max_turns: int = 10) -> list[dict[str, str]]:
        """Return the last *max_turns* messages in ``{role, content}`` format."""
        return [m.to_dict() for m in self.messages[-max_turns:]]


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------

class SessionStore:
    """Thread-safe in-memory session store.

    Attributes
    ----------
    checkpointer:
        Shared ``MemorySaver`` instance.  Pass this to
        :class:`~app.agents.orchestrator.LangGraphOrchestrator` for
        session-aware LangGraph checkpointing.
    """

    def __init__(self, ttl_hours: int = 24) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()
        self._ttl = timedelta(hours=ttl_hours)
        self.checkpointer = MemorySaver()

    # ------------------------------------------------------------------ CRUD

    def create(self, metadata: dict[str, Any] | None = None) -> Session:
        session = Session(metadata=metadata or {})
        with self._lock:
            self._sessions[session.id] = session
        return session

    def get(self, session_id: str) -> Session | None:
        with self._lock:
            session = self._sessions.get(session_id)
        if session is not None and self._is_expired(session):
            self.delete(session_id)
            return None
        return session

    def require(self, session_id: str) -> Session:
        """Like :meth:`get` but raises ``KeyError`` when not found / expired."""
        session = self.get(session_id)
        if session is None:
            raise KeyError(session_id)
        return session

    def delete(self, session_id: str) -> bool:
        with self._lock:
            return self._sessions.pop(session_id, None) is not None

    def list_all(self) -> list[Session]:
        with self._lock:
            all_sessions = list(self._sessions.values())
        return [s for s in all_sessions if not self._is_expired(s)]

    def add_message(self, session_id: str, role: str, content: str) -> None:
        self.require(session_id).add_message(role, content)

    def prune_expired(self) -> int:
        """Remove all expired sessions and return the count removed."""
        with self._lock:
            expired = [sid for sid, s in self._sessions.items() if self._is_expired(s)]
        for sid in expired:
            self.delete(sid)
        return len(expired)

    # ------------------------------------------------------------------ Internal

    def _is_expired(self, session: Session) -> bool:
        return (_now() - session.updated_at) > self._ttl


# ---------------------------------------------------------------------------
# Application-wide singleton — created in main.py lifespan
# ---------------------------------------------------------------------------

_store: SessionStore | None = None


def get_session_store() -> SessionStore:
    """FastAPI dependency that returns the application-level session store."""
    if _store is None:
        raise RuntimeError("SessionStore not initialised. Check lifespan setup in app/main.py.")
    return _store


def init_session_store(ttl_hours: int = 24) -> SessionStore:
    """Called once during application startup to create the singleton store."""
    global _store  # noqa: PLW0603
    _store = SessionStore(ttl_hours=ttl_hours)
    return _store
