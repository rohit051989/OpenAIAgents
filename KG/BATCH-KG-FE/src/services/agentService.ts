/**
 * agentService.ts
 *
 * All communication with the FastAPI backend's agentic endpoints.
 * React components and stores never call fetch() directly — they use this module.
 *
 * Two chat modes:
 *   sendChatMessage()   — blocking POST, waits for full answer
 *   streamChatMessage() — streaming POST, yields typed AgentEvents via SSE
 */

import type { AgentEvent, ChatRequest, ChatResponse, GraphData, LLMProvider } from '@/types';

const BASE_URL = import.meta.env.VITE_API_URL ?? '';
const API_KEY = import.meta.env.VITE_API_KEY ?? '';

class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

function _headers(extra?: Record<string, string>): Record<string, string> {
  const h: Record<string, string> = { 'Content-Type': 'application/json' };
  if (API_KEY) h['X-API-Key'] = API_KEY;
  return { ...h, ...extra };
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(`${BASE_URL}${path}`, {
    method: 'POST',
    headers: _headers(),
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const detail = await response.text();
    throw new ApiError(response.status, detail || response.statusText);
  }
  return response.json() as Promise<T>;
}

// ---------------------------------------------------------------------------
// Blocking chat
// ---------------------------------------------------------------------------

/**
 * Send a user question to the agent and await the full response.
 * Use this when the UI does not need real-time progress feedback.
 */
export async function sendChatMessage(request: ChatRequest): Promise<ChatResponse> {
  return post<ChatResponse>('/api/v1/chat', request);
}

// ---------------------------------------------------------------------------
// Streaming chat (SSE)
// ---------------------------------------------------------------------------

const DONE_SENTINEL = '[DONE]';

/**
 * Send a user question and yield typed {@link AgentEvent} objects as the
 * backend streams them via Server-Sent Events.
 *
 * Uses `fetch` + `ReadableStream` rather than `EventSource` so that:
 * - POST bodies are supported (SSE via EventSource only supports GET)
 * - The caller has full control over cancellation via `AbortController`
 *
 * Usage:
 * ```ts
 * for await (const event of streamChatMessage(request, signal)) {
 *   if (event.type === 'done') setAnswer(event.answer);
 * }
 * ```
 */
export async function* streamChatMessage(
  request: ChatRequest,
  signal?: AbortSignal,
): AsyncGenerator<AgentEvent> {
  const response = await fetch(`${BASE_URL}/api/v1/chat/stream`, {
    method: 'POST',
    headers: _headers(),
    body: JSON.stringify(request),
    signal,
  });

  if (!response.ok) {
    const detail = await response.text();
    throw new ApiError(response.status, detail || response.statusText);
  }

  if (!response.body) {
    throw new Error('Response body is null — streaming not supported by this environment.');
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });

      // SSE frames are separated by "\n\n"; split and process complete frames
      const parts = buffer.split('\n\n');
      buffer = parts.pop() ?? '';  // keep any incomplete trailing frame

      for (const part of parts) {
        for (const line of part.split('\n')) {
          if (!line.startsWith('data: ')) continue;
          const data = line.slice(6).trim();
          if (data === DONE_SENTINEL) return;
          try {
            yield JSON.parse(data) as AgentEvent;
          } catch {
            // Malformed frame — skip silently
          }
        }
      }
    }
  } finally {
    reader.releaseLock();
  }
}

// ---------------------------------------------------------------------------
// Provider discovery
// ---------------------------------------------------------------------------

/**
 * Fetch the LLM providers that have credentials configured on the backend.
 */
export async function fetchAvailableProviders(): Promise<LLMProvider[]> {
  const response = await fetch(`${BASE_URL}/api/v1/config/providers`, {
    headers: _headers(),
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new ApiError(response.status, detail || response.statusText);
  }
  const data = (await response.json()) as { available_providers: LLMProvider[] };
  return data.available_providers;
}

// ---------------------------------------------------------------------------
// Graph REST endpoints
// ---------------------------------------------------------------------------

/**
 * Fetch a 1-hop subgraph centred on any KG entity.
 * `entityId` can be the node's id property, its name, or the Neo4j element ID.
 */
export async function fetchNodeGraph(entityId: string): Promise<GraphData> {
  const response = await fetch(
    `${BASE_URL}/api/v1/graph/${encodeURIComponent(entityId)}`,
    { headers: _headers() },
  );
  if (!response.ok) {
    const detail = await response.text();
    throw new ApiError(response.status, detail || response.statusText);
  }
  return response.json() as Promise<GraphData>;
}

/**
 * Expand a node by fetching its immediate neighbours that are not already
 * known to the frontend.
 *
 * @param nodeId          The `id` property or Neo4j element ID of the node to expand.
 * @param existingNodeIds IDs already rendered — excluded from the response.
 */
export async function expandNode(
  nodeId: string,
  existingNodeIds: string[],
): Promise<GraphData> {
  const params = existingNodeIds.length
    ? `?existing_node_ids=${existingNodeIds.map(encodeURIComponent).join(',')}`
    : '';
  const response = await fetch(
    `${BASE_URL}/api/v1/graph/expand/${encodeURIComponent(nodeId)}${params}`,
    { headers: _headers() },
  );
  if (!response.ok) {
    const detail = await response.text();
    throw new ApiError(response.status, detail || response.statusText);
  }
  return response.json() as Promise<GraphData>;
}
