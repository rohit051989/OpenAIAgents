# Frontend Integration Guide — Graph Visualization

This document describes all backend API changes that the React frontend must consume to support Knowledge Graph visualization.

---

## Table of Contents

1. [Updated TypeScript Types](#1-updated-typescript-types)
2. [Updated Chat API](#2-updated-chat-api)
3. [New Graph REST Endpoints](#3-new-graph-rest-endpoints)
4. [SSE Streaming Changes](#4-sse-streaming-changes)
5. [Recommended Graph Library](#5-recommended-graph-library)
6. [Node Color & Size Reference](#6-node-color--size-reference)
7. [Example Flow](#7-example-flow)

---

## 1. Updated TypeScript Types

Add these types to your API types file (e.g. `src/types/api.ts`):

```ts
// ── Graph visualization types ─────────────────────────────────────────────

export interface GraphNode {
  id: string;
  labels: string[];          // e.g. ["ScheduleInstanceContext"], ["Job"]
  properties: Record<string, unknown>;
}

export interface GraphRelationship {
  id: string;
  type: string;              // e.g. "PRECEDES", "FOR_JOB", "FOR_GROUP"
  startNodeId: string;       // matches a GraphNode.id
  endNodeId: string;         // matches a GraphNode.id
  properties: Record<string, unknown>;
}

export interface GraphData {
  nodes: GraphNode[];
  relationships: GraphRelationship[];
}

// ── Updated ChatResponse ──────────────────────────────────────────────────

export interface ChatResponse {
  answer: string;
  execution_log: ExecutionLogEntry[];
  plan: object | null;
  step_results: Record<string, unknown>;
  graph_data: GraphData | null;   // NEW — null when answer is purely textual
  session_id: string | null;
}

export interface ExecutionLogEntry {
  agent: string;
  message: string;
}
```

---

## 2. Updated Chat API

### `POST /api/v1/chat`

**Request** — unchanged:

```json
{
  "question": "what runs before and after customerExportJob",
  "history": []
}
```

**Response** — now includes `graph_data`:

```json
{
  "answer": "The customerExportJob is preceded by ...",
  "execution_log": [...],
  "plan": {...},
  "step_results": {...},
  "graph_data": {
    "nodes": [
      {
        "id": "Context_customerExportJob",
        "labels": ["ScheduleInstanceContext"],
        "properties": {
          "name": "Context_customerExportJob",
          "jobName": "customerExportJob",
          "direction": "TARGET",
          "enabled": true
        }
      }
    ],
    "relationships": [
      {
        "id": "rel-0",
        "type": "PRECEDES",
        "startNodeId": "Context_customerProcessingJob",
        "endNodeId": "Context_customerExportJob",
        "properties": { "on": "DEFAULT" }
      }
    ]
  },
  "session_id": null
}
```

> `graph_data` is `null` when the agent's answer does not involve graph tool calls (e.g. a simple factual question). Always null-check before rendering.

**Logic to implement in frontend:**

```ts
const response = await fetch('/api/v1/chat', { method: 'POST', body: ... });
const data: ChatResponse = await response.json();

if (data.graph_data && data.graph_data.nodes.length > 0) {
  renderGraph(data.graph_data);
}
```

---

## 3. New Graph REST Endpoints

These endpoints allow the frontend to fetch or expand graph data independently of the chat flow — e.g. on initial load or when a user clicks a node.

### `GET /api/v1/graph/{entity_id}`

Returns a 1-hop subgraph centred on any KG entity.

- `entity_id` can be the node's `id` property, its `name`, or the Neo4j element ID.

**Example request:**
```
GET /api/v1/graph/customerExportJob
```

**Response:** `GraphData`

```json
{
  "nodes": [
    {
      "id": "job-uuid-123",
      "labels": ["Job"],
      "properties": { "id": "job-uuid-123", "name": "customerExportJob", "enabled": true }
    },
    {
      "id": "step-uuid-456",
      "labels": ["Step"],
      "properties": { "id": "step-uuid-456", "name": "exportStep" }
    }
  ],
  "relationships": [
    {
      "id": "rel-elem-id-789",
      "type": "HAS_STEP",
      "startNodeId": "job-uuid-123",
      "endNodeId": "step-uuid-456",
      "properties": {}
    }
  ]
}
```

---

### `GET /api/v1/graph/expand/{node_id}?existing_node_ids=id1,id2,id3`

Returns immediate neighbours of `node_id` **not already known** to the frontend. Use this when the user clicks a node to progressively reveal the graph.

| Parameter | Type | Description |
|---|---|---|
| `node_id` | path | `id` property or Neo4j element ID of the node to expand |
| `existing_node_ids` | query (optional) | Comma-separated list of node IDs already rendered — excluded from response |

**Example request:**
```
GET /api/v1/graph/expand/job-uuid-123?existing_node_ids=job-uuid-123,step-uuid-456
```

**Response:** `GraphData` — only new nodes and any relationships connecting them.

**Frontend implementation pattern:**

```ts
async function onNodeClick(nodeId: string, currentGraph: GraphData) {
  const existingIds = currentGraph.nodes.map(n => n.id).join(',');
  const url = `/api/v1/graph/expand/${nodeId}?existing_node_ids=${existingIds}`;
  const res = await fetch(url);
  const newData: GraphData = await res.json();

  // Merge new nodes and relationships into the existing graph
  setGraph(prev => ({
    nodes: [...prev.nodes, ...newData.nodes],
    relationships: [...prev.relationships, ...newData.relationships],
  }));
}
```

---

## 4. SSE Streaming Changes

### `POST /api/v1/chat/stream`

The `done` event now includes `graph_data`.

**Updated `done` event shape:**

```ts
interface DoneEvent {
  type: "done";
  id: string;
  timestamp: string;
  session_id: string;
  answer: string;
  execution_log: ExecutionLogEntry[];
  plan: object | null;
  step_results: Record<string, unknown>;
  graph_data: GraphData | null;   // NEW
}
```

**Frontend SSE handler update:**

```ts
eventSource.addEventListener('done', (e) => {
  const event: DoneEvent = JSON.parse(e.data);
  setAnswer(event.answer);
  if (event.graph_data?.nodes.length) {
    renderGraph(event.graph_data);
  }
});
```

---

## 5. Recommended Graph Library

Use **`@neo4j-nvl/react`** — the same library used in the reference application.

```bash
npm install @neo4j-nvl/react @neo4j-nvl/base
```

**Mapping `GraphData` to NVL format:**

```ts
import { InteractiveNvlWrapper } from '@neo4j-nvl/react';
import type { Node, Relationship } from '@neo4j-nvl/base';

function toNvlNodes(nodes: GraphNode[]): Node[] {
  return nodes.map(n => ({
    id: n.id,
    caption: (n.properties.name ?? n.properties.jobName ?? n.id) as string,
    color: NODE_COLORS[n.labels[0]] ?? '#718096',
    size: NODE_SIZES[n.labels[0]] ?? 20,
  }));
}

function toNvlRelationships(rels: GraphRelationship[]): Relationship[] {
  return rels.map(r => ({
    id: r.id,
    from: r.startNodeId,
    to: r.endNodeId,
    caption: r.type,
  }));
}

// Usage
<InteractiveNvlWrapper
  nodes={toNvlNodes(graphData.nodes)}
  rels={toNvlRelationships(graphData.relationships)}
  nvlOptions={{ layout: 'hierarchical' }}
  mouseEventCallbacks={{
    onNodeClick: (node) => onNodeClick(node.id, currentGraph),
  }}
/>
```

---

## 6. Node Color & Size Reference

Map `labels[0]` to colors and sizes for consistent rendering:

```ts
const NODE_COLORS: Record<string, string> = {
  Job:                     '#4299E1',  // blue
  Step:                    '#48BB78',  // green
  JobGroup:                '#ED8936',  // orange
  ScheduleInstanceContext: '#9F7AEA',  // purple
  Decision:                '#F56565',  // red
  Block:                   '#38B2AC',  // teal
};

const NODE_SIZES: Record<string, number> = {
  Job:                     30,
  JobGroup:                28,
  ScheduleInstanceContext: 22,
  Step:                    20,
  Decision:                20,
  Block:                   18,
};
```

---

## 7. Example Flow

```
User asks: "what runs before and after customerExportJob"
                      │
                      ▼
         POST /api/v1/chat
                      │
              Backend calls MCP tool:
         get_job_dependency_chain(job_name="customerExportJob")
                      │
              MCP returns graphlet with
              nodes[] and links[] (PRECEDES chain)
                      │
              Backend normalizes → GraphData
              { nodes: [...], relationships: [...] }
                      │
              ChatResponse includes graph_data
                      │
                      ▼
         Frontend receives graph_data
         → renders dependency graph in NVL
         → user clicks a node
                      │
                      ▼
         GET /api/v1/graph/expand/{nodeId}
         ?existing_node_ids=id1,id2,...
                      │
         New neighbours returned → merged into graph
```

---

## Backend Endpoints Summary

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/chat` | Agentic chat — response includes `graph_data` |
| `POST` | `/api/v1/chat/stream` | SSE streaming — `done` event includes `graph_data` |
| `GET`  | `/api/v1/graph/{entity_id}` | 1-hop subgraph for any KG entity |
| `GET`  | `/api/v1/graph/expand/{node_id}` | Expand a node by its neighbours |
