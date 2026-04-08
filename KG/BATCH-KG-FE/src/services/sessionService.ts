/**
 * sessionService.ts
 *
 * All communication with the FastAPI /api/v1/sessions endpoints.
 */

import type { Session, SessionCreate } from '@/types';

const BASE_URL = import.meta.env.VITE_API_URL ?? '';
const API_KEY  = import.meta.env.VITE_API_KEY  ?? '';

function _headers(): Record<string, string> {
  const h: Record<string, string> = { 'Content-Type': 'application/json' };
  if (API_KEY) h['X-API-Key'] = API_KEY;
  return h;
}

async function _fetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: _headers(),
    ...init,
  });
  if (res.status === 204) return undefined as T;
  if (!res.ok) {
    const detail = await res.text();
    throw new Error(detail || res.statusText);
  }
  return res.json() as Promise<T>;
}

/** Create a new conversation session. Returns the session with its generated ID. */
export async function createSession(payload: SessionCreate = {}): Promise<Session> {
  return _fetch<Session>('/api/v1/sessions', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

/** Fetch all active sessions (without message history). */
export async function listSessions(): Promise<Session[]> {
  return _fetch<Session[]>('/api/v1/sessions');
}

/** Fetch a single session with its full message history. */
export async function getSession(sessionId: string): Promise<Session> {
  return _fetch<Session>(`/api/v1/sessions/${sessionId}`);
}

/** Delete a session. Resolves when the server returns 204. */
export async function deleteSession(sessionId: string): Promise<void> {
  return _fetch<void>(`/api/v1/sessions/${sessionId}`, { method: 'DELETE' });
}
