# BATCH-KG-FE — Spring Batch KG Agent Frontend

React 18 + TypeScript chat UI for the Spring Batch Knowledge Graph agent.
Communicates exclusively with the [BATCH-KG-BE](../BATCH-KG-BE) backend via REST and SSE — it never calls the MCP server or Neo4j directly.

---

## System Context

```
BATCH-KG-FE   (this project — port 3000)
    │   REST + SSE  /api/* → proxy → port 8001
    ▼
BATCH-KG-BE   (port 8001)
    │
    ▼
BATCH-kg-ui-mcp  (port 8100)  →  Neo4j
```

---

## Prerequisites

- Node.js 20+
- [BATCH-KG-BE](../BATCH-KG-BE) running on port 8001

---

## Quick Start

```bash
npm install
npm run dev
```

Open: `http://localhost:3000`

### Build for production

```bash
npm run build     # outputs to dist/
npm run preview   # preview production build locally
```

---

## Environment Variables

Create a `.env.local` file at the project root (never commit this file):

| Variable | Default | Description |
|---|---|---|
| `VITE_API_URL` | `` (empty) | Backend base URL. Empty = use the Vite proxy (dev). Set to `https://your-api.com` in production. |
| `VITE_API_KEY` | `` (empty) | Forwarded as `X-API-Key` header. Required when `API_KEY` is set on the backend. |

---

## Project Structure

```
BATCH-KG-FE/
├── index.html
├── package.json
├── vite.config.ts          # Vite + proxy /api → localhost:8001
├── tsconfig.json
└── src/
    ├── main.tsx             # React entry point
    ├── App.tsx              # Root layout: header + Sidebar + ChatWindow
    ├── types/
    │   └── index.ts         # All TypeScript types (AgentEvent union, Message, Session…)
    ├── styles/
    │   ├── variables.css    # Design tokens (dark theme)
    │   └── globals.css      # Reset + base styles
    ├── services/
    │   ├── agentService.ts  # sendChatMessage() + streamChatMessage() — SSE streaming
    │   ├── mcpService.ts    # fetchTools(), fetchSchema(), fetchAvailableProviders()
    │   └── sessionService.ts# createSession(), getSession(), deleteSession()
    ├── store/
    │   ├── chatStore.ts     # Zustand: messages, streaming, sessions
    │   └── configStore.ts   # Zustand: mcpUrl, llmProvider, connectionStatus
    ├── hooks/
    │   └── useChat.ts
    └── components/
        ├── chat/            # ChatWindow, MessageBubble, ChatInput, ExecutionLog
        ├── sidebar/         # Sidebar, McpConfig, LlmConfig, ConnectionStatus, ToolsList
        └── common/          # StatusBadge
```

---

## Chat Modes

The store supports two modes toggled by `streamingEnabled` (default: `true`):

| Mode | Transport | When to use |
|---|---|---|
| **Streaming** | `POST /api/v1/chat/stream` → SSE | Real-time step-by-step feedback |
| **Blocking** | `POST /api/v1/chat` | Simpler environments without streaming |

To cancel an in-flight stream: `useChatStore.getState().cancelStream()`.

---

## Stack

| | Technology |
|---|---|
| Framework | React 18 |
| Language | TypeScript 5 (strict) |
| Build | Vite 5 |
| State | Zustand 4 |
| Styling | CSS Modules + CSS custom properties |
