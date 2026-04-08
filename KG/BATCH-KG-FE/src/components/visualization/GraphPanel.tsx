/**
 * GraphPanel — interactive knowledge-graph visualization using @xyflow/react.
 *
 * Features:
 *  - Receives GraphData (nodes[] + relationships[]) directly from chat response
 *  - Hierarchical auto-layout (topological BFS — no extra deps)
 *  - Node colours / sizes driven by label (Job, Step, JobGroup, etc.)
 *  - Hover tooltip showing key node properties
 *  - Click a node → expand its neighbours via GET /api/v1/graph/expand/{nodeId}
 *  - New nodes animate in via a subtle "new" highlight ring
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Handle,
  Position,
  BackgroundVariant,
  useNodesState,
  useEdgesState,
  useReactFlow,
  ReactFlowProvider,
  type Node,
  type Edge,
  type NodeProps,
  type NodeMouseHandler,
} from "@xyflow/react";
import type { GraphData, GraphNode } from "@/types";
import { expandNode } from "@/services/agentService";
import styles from "./GraphPanel.module.css";

// ---------------------------------------------------------------------------
// Visual constants
// ---------------------------------------------------------------------------

const NODE_COLORS: Record<string, string> = {
  Job:                     "#4299E1",
  Step:                    "#48BB78",
  JobGroup:                "#ED8936",
  ScheduleInstanceContext: "#9F7AEA",
  Decision:                "#F56565",
  Block:                   "#38B2AC",
};
const DEFAULT_COLOR = "#718096";

function colorFor(n: GraphNode) { return NODE_COLORS[n.labels[0]] ?? DEFAULT_COLOR; }

function labelFor(n: GraphNode): string {
  const p = n.properties;
  return (p.name ?? p.jobName ?? p.id ?? n.id) as string;
}

// ---------------------------------------------------------------------------
// Custom node component — ensures text always wraps inside the box
// ---------------------------------------------------------------------------

const NODE_WIDTH = 160;

function KgNode({ data }: NodeProps) {
  const { label, color } = data as { label: string; color: string };
  return (
    <>
      <Handle type="target" position={Position.Left} style={{ background: color, width: 8, height: 8, border: `2px solid ${color}` }} />
      <div
        style={{
          width: NODE_WIDTH,
          padding: "10px 12px",
          background: `${color}18`,
          border: `2px solid ${color}`,
          borderRadius: "10px",
          color: "#1a202c",
          fontWeight: 600,
          fontSize: "12px",
          lineHeight: 1.45,
          textAlign: "center",
          wordBreak: "break-word",
          overflowWrap: "break-word",
          whiteSpace: "normal",
          cursor: "pointer",
          boxSizing: "border-box",
        }}
      >
        {label}
      </div>
      <Handle type="source" position={Position.Right} style={{ background: color, width: 8, height: 8, border: `2px solid ${color}` }} />
    </>
  );
}

const NODE_TYPES = { kgNode: KgNode };

// ---------------------------------------------------------------------------
// Auto-layout: BFS topological hierarchy
// ---------------------------------------------------------------------------

function computeLayout(
  nodes: GraphNode[],
  relationships: GraphData["relationships"],
): Map<string, { x: number; y: number }> {
  // Build adjacency
  const children = new Map<string, Set<string>>();
  const parents  = new Map<string, Set<string>>();
  for (const n of nodes) { children.set(n.id, new Set()); parents.set(n.id, new Set()); }
  for (const r of relationships) {
    children.get(r.startNodeId)?.add(r.endNodeId);
    parents.get(r.endNodeId)?.add(r.startNodeId);
  }

  // BFS levels
  const level = new Map<string, number>();
  const queue: string[] = [];
  for (const n of nodes) {
    if ((parents.get(n.id)?.size ?? 0) === 0) {
      level.set(n.id, 0);
      queue.push(n.id);
    }
  }
  // Handle cycles / disconnected by assigning any unvisited node to level 0
  for (const n of nodes) { if (!level.has(n.id)) { level.set(n.id, 0); queue.push(n.id); } }

  let head = 0;
  while (head < queue.length) {
    const id = queue[head++];
    const l = level.get(id)!;
    for (const child of children.get(id) ?? []) {
      if (!level.has(child) || level.get(child)! < l + 1) {
        level.set(child, l + 1);
        queue.push(child);
      }
    }
  }

  // Group by level
  const byLevel = new Map<number, string[]>();
  for (const [id, lv] of level) {
    if (!byLevel.has(lv)) byLevel.set(lv, []);
    byLevel.get(lv)!.push(id);
  }

  const COL_WIDTH  = 260;
  const ROW_HEIGHT = 130;
  const positions  = new Map<string, { x: number; y: number }>();

  for (const [lv, ids] of byLevel) {
    const x = lv * COL_WIDTH;
    const totalH = (ids.length - 1) * ROW_HEIGHT;
    ids.forEach((id, i) => positions.set(id, { x, y: -totalH / 2 + i * ROW_HEIGHT }));
  }
  return positions;
}

// ---------------------------------------------------------------------------
// Convert GraphData → ReactFlow nodes + edges
// ---------------------------------------------------------------------------

function buildFlow(
  graphData: GraphData,
  newIds: Set<string> = new Set(),
): { nodes: Node[]; edges: Edge[] } {
  const positions = computeLayout(graphData.nodes, graphData.relationships);

  const nodes: Node[] = graphData.nodes.map((n) => {
    const color = colorFor(n);
    const pos   = positions.get(n.id) ?? { x: 0, y: 0 };
    const isNew = newIds.has(n.id);
    return {
      id: n.id,
      type: "kgNode",
      position: pos,
      data: {
        label: labelFor(n),
        color,
        nodeData: n,
      },
      // The wrapper style only controls glow / shadow; visual chrome lives inside KgNode
      style: {
        boxShadow: isNew
          ? `0 0 0 4px ${color}55, 0 4px 12px ${color}33`
          : undefined,
        background: "transparent",
        border: "none",
        padding: 0,
      },
    };
  });

  const edges: Edge[] = graphData.relationships.map((r, i) => ({
    id: r.id || `e${i}`,
    source: r.startNodeId,
    target: r.endNodeId,
    label: r.type,
    type: "smoothstep",
    animated: newIds.size > 0,
    style: { stroke: "#a0aec0", strokeWidth: 1.5 },
    labelStyle: { fill: "#4a5568", fontSize: "10px", fontWeight: 600 },
    labelBgStyle: { fill: "#ffffff", fillOpacity: 0.95 },
    labelBgPadding: [4, 6] as [number, number],
    markerEnd: { type: "arrowclosed" as const, color: "#a0aec0" },
  }));

  return { nodes, edges };
}

// ---------------------------------------------------------------------------
// Tooltip component
// ---------------------------------------------------------------------------

interface TooltipData {
  node: GraphNode;
  x: number;
  y: number;
}

function NodeTooltip({ data }: { data: TooltipData }) {
  const { node, x, y } = data;
  const label = node.labels[0] ?? "";
  const color = NODE_COLORS[label] ?? DEFAULT_COLOR;
  const props = Object.entries(node.properties)
    .filter(([, v]) => v !== null && v !== undefined && v !== "")
    .slice(0, 6);
  return (
    <div
      className={styles.tooltip}
      style={{ left: x + 12, top: y - 8, borderTopColor: color }}
    >
      <div className={styles.tooltipLabel} style={{ color }}>
        {label}
      </div>
      {props.map(([k, v]) => (
        <div key={k} className={styles.tooltipRow}>
          <span className={styles.tooltipKey}>{k}</span>
          <span className={styles.tooltipVal}>{String(v)}</span>
        </div>
      ))}
      <div className={styles.tooltipHint}>Click to expand neighbours</div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Inner graph component (needs ReactFlowProvider context)
// ---------------------------------------------------------------------------

interface InnerProps {
  graphData: GraphData;
}

function GraphInner({ graphData }: InnerProps) {
  const [localData, setLocalData] = useState<GraphData>(graphData);
  const [newIds, setNewIds] = useState<Set<string>>(new Set());
  const [tooltip, setTooltip] = useState<TooltipData | null>(null);
  const [expanding, setExpanding] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  const { fitView } = useReactFlow();

  // Reset when parent passes new graph data (new chat response)
  useEffect(() => {
    setLocalData(graphData);
    setNewIds(new Set());
  }, [graphData]);

  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);

  // Sync nodes/edges whenever localData changes
  useEffect(() => {
    const { nodes: n, edges: e } = buildFlow(localData, newIds);
    setNodes(n);
    setEdges(e);
    setTimeout(() => fitView({ padding: 0.25, duration: 400 }), 50);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [localData, newIds]);

  const onNodeClick: NodeMouseHandler = useCallback(
    async (_event, node) => {
      if (expanding) return;
      const nodeData = (node.data as { nodeData: GraphNode }).nodeData;
      setExpanding(true);
      setTooltip(null);
      try {
        const existingIds = localData.nodes.map((n) => n.id);
        const newData = await expandNode(node.id, existingIds);
        if (newData.nodes.length === 0 && newData.relationships.length === 0) return;
        const incomingIds = new Set(newData.nodes.map((n) => n.id));
        setNewIds(incomingIds);
        setLocalData((prev) => ({
          nodes: [...prev.nodes, ...newData.nodes],
          relationships: [...prev.relationships, ...newData.relationships],
        }));
        // Clear new-node highlight after 2 s
        setTimeout(() => setNewIds(new Set()), 2000);
      } catch {
        // Expand failed silently — node is a leaf or API unavailable
      } finally {
        setExpanding(false);
      }
      void nodeData; // used indirectly via node.id
    },
    [expanding, localData],
  );

  const onNodeMouseEnter: NodeMouseHandler = useCallback((_event, node) => {
    if (!containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    // Use the node's screen position from the event
    const domNode = document.querySelector(`[data-id="${node.id}"]`);
    const nodeRect = domNode?.getBoundingClientRect();
    if (!nodeRect) return;
    setTooltip({
      node: (node.data as { nodeData: GraphNode }).nodeData,
      x: nodeRect.left - rect.left + nodeRect.width / 2,
      y: nodeRect.top - rect.top,
    });
  }, []);

  const onNodeMouseLeave: NodeMouseHandler = useCallback(() => {
    setTooltip(null);
  }, []);

  return (
    <div ref={containerRef} className={styles.flowInner}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={NODE_TYPES}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={onNodeClick}
        onNodeMouseEnter={onNodeMouseEnter}
        onNodeMouseLeave={onNodeMouseLeave}
        fitView
        fitViewOptions={{ padding: 0.25 }}
        colorMode="light"
        nodesDraggable
        nodesConnectable={false}
        edgesReconnectable={false}
        proOptions={{ hideAttribution: true }}
      >
        <Background variant={BackgroundVariant.Dots} color="#e2e8f0" gap={20} size={1} />
        <Controls
          style={{
            background: "#ffffff",
            border: "1px solid #e2e8f0",
            borderRadius: "8px",
            boxShadow: "0 1px 3px rgba(0,0,0,0.08)",
          }}
        />
        <MiniMap
          nodeColor={(n) => {
            const nd = (n.data as { nodeData?: GraphNode }).nodeData;
            return nd ? colorFor(nd) : DEFAULT_COLOR;
          }}
          style={{
            background: "#f7fafc",
            border: "1px solid #e2e8f0",
            borderRadius: "8px",
          }}
          maskColor="rgba(240,244,248,0.6)"
        />
      </ReactFlow>

      {/* Hover tooltip */}
      {tooltip && <NodeTooltip data={tooltip} />}

      {/* Expanding overlay */}
      {expanding && (
        <div className={styles.expandingOverlay}>
          <span className={styles.expandingDot} /><span className={styles.expandingDot} /><span className={styles.expandingDot} />
          <span>Expanding…</span>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Public component
// ---------------------------------------------------------------------------

interface Props {
  graphData: GraphData | null;
}

export function GraphPanel({ graphData }: Props) {
  const nodeCount    = graphData?.nodes.length ?? 0;
  const edgeCount    = graphData?.relationships.length ?? 0;

  // Colour legend — only labels actually present in the data
  const presentLabels = useMemo(() => {
    if (!graphData) return [];
    const seen = new Set<string>();
    for (const n of graphData.nodes) if (n.labels[0]) seen.add(n.labels[0]);
    return [...seen];
  }, [graphData]);

  return (
    <div className={styles.root}>
      <div className={styles.header}>
        <span className={styles.headerTitle}>Graph Visualization</span>
        {graphData && (
          <span className={styles.headerMeta}>
            {nodeCount} node{nodeCount !== 1 ? "s" : ""} &middot; {edgeCount} edge{edgeCount !== 1 ? "s" : ""}
          </span>
        )}
      </div>

      {!graphData ? (
        <div className={styles.empty}>
          <span className={styles.emptyIcon}>🕸</span>
          <p className={styles.emptyTitle}>No graph data yet</p>
          <p className={styles.emptyHint}>
            Ask about job dependencies, execution chains, or relationships — an
            interactive graph will appear here.
          </p>
        </div>
      ) : (
        <div className={styles.flowContainer}>
          {/* Dynamic legend */}
          {presentLabels.length > 0 && (
            <div className={styles.legend}>
              {presentLabels.map((lbl) => (
                <span key={lbl} className={styles.legendItem}>
                  <span className={styles.legendDot} style={{ background: NODE_COLORS[lbl] ?? DEFAULT_COLOR }} />
                  {lbl}
                </span>
              ))}
            </div>
          )}

          <ReactFlowProvider>
            <GraphInner graphData={graphData} />
          </ReactFlowProvider>
        </div>
      )}

      {graphData && (
        <div className={styles.footer}>
          Scroll to zoom &middot; Drag nodes &middot; <strong>Click a node</strong> to expand neighbours
        </div>
      )}
    </div>
  );
}
