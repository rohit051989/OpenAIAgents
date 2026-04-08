/**
 * chatStore.ts
 *
 * Two send modes:
 *   streamingEnabled=true  -> SSE streaming (events appear in real time)
 *   streamingEnabled=false -> blocking POST (waits for full answer)
 *
 * Graph data is now delivered directly in the API response (graph_data field).
 * No client-side extraction from step_results is needed.
 */

import { create } from "zustand";
import type { GraphData, ExecutionLogEntry, Message } from "@/types";
import { sendChatMessage, streamChatMessage } from "@/services/agentService";
import { useConfigStore } from "@/store/configStore";

function genId(): string {
  if (typeof crypto !== "undefined" && crypto.randomUUID) return crypto.randomUUID();
  return Math.random().toString(36).slice(2);
}

interface ChatState {
  messages: Message[];
  isLoading: boolean;
  error: string | null;
  streamingEnabled: boolean;
  activeSessionId: string | null;
  _abortController: AbortController | null;

  sendMessage: (content: string) => Promise<void>;
  editAndRetry: (messageId: string, newContent: string) => Promise<void>;
  cancelStream: () => void;
  clearMessages: () => void;
  dismissError: () => void;
  setStreamingEnabled: (enabled: boolean) => void;
  setActiveSessionId: (id: string | null) => void;
}

export const useChatStore = create<ChatState>((set, get) => ({
  messages: [],
  isLoading: false,
  error: null,
  streamingEnabled: true,
  activeSessionId: null,
  _abortController: null,

  // -------------------------------------------------------------------------
  // Send
  // -------------------------------------------------------------------------

  sendMessage: async (content: string) => {
    const { llmProvider } = useConfigStore.getState();
    const { streamingEnabled, activeSessionId } = get();

    const userMessage: Message = {
      id: genId(),
      role: "user",
      content,
      timestamp: new Date().toISOString(),
    };
    set((s) => ({ messages: [...s.messages, userMessage], isLoading: true, error: null }));

    const history = activeSessionId
      ? []
      : get()
          .messages.slice(-6)
          .map((m) => ({ role: m.role, content: m.content }));

    const request = {
      question: content,
      history,
      llm_provider: llmProvider,
      session_id: activeSessionId,
    };

    if (streamingEnabled) {
      // @ts-expect-error - private method
      await get()._streamSend(request);
    } else {
      // @ts-expect-error - private method
      await get()._blockingSend(request);
    }
  },

  // -------------------------------------------------------------------------
  // Edit & retry — trims history back to the edited message then re-sends
  // -------------------------------------------------------------------------

  editAndRetry: async (messageId: string, newContent: string) => {
    const { messages, isLoading } = get();
    if (isLoading) return;
    const idx = messages.findIndex((m) => m.id === messageId);
    if (idx === -1) return;
    set({ messages: messages.slice(0, idx) });
    await get().sendMessage(newContent.trim());
  },

  // -------------------------------------------------------------------------
  // Cancel
  // -------------------------------------------------------------------------

  cancelStream: () => {
    get()._abortController?.abort();
    set({ isLoading: false, _abortController: null });
  },

  // -------------------------------------------------------------------------
  // Utility
  // -------------------------------------------------------------------------

  clearMessages: () => set({ messages: [], error: null }),
  dismissError: () => set({ error: null }),
  setStreamingEnabled: (enabled) => set({ streamingEnabled: enabled }),
  setActiveSessionId: (id) => set({ activeSessionId: id }),

  // -------------------------------------------------------------------------
  // Private: blocking send
  // -------------------------------------------------------------------------

  // @ts-expect-error - private method
  _blockingSend: async (request) => {
    try {
      const response = await sendChatMessage(request);
      const graphData: GraphData | undefined =
        response.graph_data?.nodes?.length ? response.graph_data : undefined;
      const assistantMessage: Message = {
        id: genId(),
        role: "assistant",
        content: response.answer,
        timestamp: new Date().toISOString(),
        executionLog: response.execution_log,
        plan: response.plan ?? undefined,
        stepResults: response.step_results,
        graphData,
      };
      set((s) => ({ messages: [...s.messages, assistantMessage], isLoading: false }));
    } catch (err) {
      set({ isLoading: false, error: err instanceof Error ? err.message : "Unexpected error" });
    }
  },

  // -------------------------------------------------------------------------
  // Private: SSE streaming send
  // -------------------------------------------------------------------------

  // @ts-expect-error - private method
  _streamSend: async (request) => {
    const abortController = new AbortController();
    set({ _abortController: abortController });

    const assistantId = genId();
    const placeholder: Message = {
      id: assistantId,
      role: "assistant",
      content: "",
      timestamp: new Date().toISOString(),
      isStreaming: true,
      events: [],
      executionLog: [],
    };
    set((s) => ({ messages: [...s.messages, placeholder] }));

    const _update = (patch: Partial<Message>) =>
      set((s) => ({
        messages: s.messages.map((m) => (m.id === assistantId ? { ...m, ...patch } : m)),
      }));

    const _accLog: ExecutionLogEntry[] = [];

    try {
      for await (const event of streamChatMessage(request, abortController.signal)) {
        switch (event.type) {
          case "plan_generated":
            _accLog.push({
              agent: "Agent 1 (Planner)",
              message: `Plan created with ${event.plan.plan.length} step${event.plan.plan.length !== 1 ? "s" : ""}`,
            });
            _update({ plan: event.plan, executionLog: [..._accLog] });
            break;

          case "step_started":
            _accLog.push({
              agent: `Step ${event.step_number}`,
              message: `Starting: ${event.step_description}`,
            });
            set((s) => ({
              messages: s.messages.map((m) => {
                if (m.id !== assistantId) return m;
                return { ...m, events: [...(m.events ?? []), event], executionLog: [..._accLog] };
              }),
            }));
            break;

          case "step_completed": {
            _accLog.push({
              agent: `Step ${event.step_number}`,
              message: event.success
                ? `Tool executed successfully (${event.duration_ms}ms)`
                : `Tool failed (${event.duration_ms}ms)`,
            });
            set((s) => ({
              messages: s.messages.map((m) => {
                if (m.id !== assistantId) return m;
                return {
                  ...m,
                  events: [...(m.events ?? []), event],
                  stepResults: { ...(m.stepResults ?? {}), [event.step_number]: event.result },
                  executionLog: [..._accLog],
                };
              }),
            }));
            break;
          }

          case "done": {
            const serverLog: ExecutionLogEntry[] = event.execution_log ?? [];
            if (serverLog.length > 0) {
              for (const entry of serverLog) {
                const alreadyHave = _accLog.some(
                  (e) => e.agent === entry.agent && e.message === entry.message
                );
                if (!alreadyHave) _accLog.push(entry);
              }
            }

            const graphData: GraphData | undefined =
              event.graph_data?.nodes?.length ? event.graph_data : undefined;

            _update({
              content: event.answer,
              executionLog: [..._accLog],
              ...(event.plan != null ? { plan: event.plan } : {}),
              stepResults: event.step_results,
              graphData,
            });
            break;
          }

          case "error":
            _accLog.push({ agent: "Error", message: `[${event.error_code}] ${event.message}` });
            _update({ content: `[Error ${event.error_code}] ${event.message}`, executionLog: [..._accLog] });
            break;
        }
      }
    } catch (err: unknown) {
      if ((err as { name?: string }).name !== "AbortError") {
        const msg = err instanceof Error ? err.message : "Streaming error";
        _update({ content: msg || "Stream failed." });
        set({ error: msg });
      }
    } finally {
      _update({ isStreaming: false });
      set({ isLoading: false, _abortController: null });
    }
  },
}));
