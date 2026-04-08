// -------------------------------------------------------------------------
// Domain types — kept in sync with backend Pydantic models
// -------------------------------------------------------------------------

export type LLMProvider = 'openai' | 'azure_openai' | 'aws_bedrock' | 'google_gemini';
export type ConnectionStatus = 'disconnected' | 'connecting' | 'connected' | 'error';

// -------------------------------------------------------------------------
// Graph visualization types — synced with backend GraphData schema
// -------------------------------------------------------------------------

export interface GraphNode {
  id: string;
  labels: string[];           // e.g. ["Job"], ["ScheduleInstanceContext"]
  properties: Record<string, unknown>;
}

export interface GraphRelationship {
  id: string;
  type: string;               // e.g. "PRECEDES", "HAS_STEP", "FOR_JOB"
  startNodeId: string;
  endNodeId: string;
  properties: Record<string, unknown>;
}

export interface GraphData {
  nodes: GraphNode[];
  relationships: GraphRelationship[];
}

// -------------------------------------------------------------------------
// Agent / execution types
// -------------------------------------------------------------------------

export interface ExecutionLogEntry {
  agent: string;
  message: string;
}

export interface PlanStep {
  step: number;
  action: string;
  type: 'direct_tool' | 'cypher_query';
  tool?: string;
  depends_on?: number[];
  requires_schema_analysis?: boolean;
}

export interface ExecutionPlan {
  plan: PlanStep[];
  strategy?: string;
  complexity?: string;
}

// -------------------------------------------------------------------------
// Agent event types — discriminated union, mirrors backend app/models/events.py
// -------------------------------------------------------------------------

interface _EventBase {
  id: string;
  timestamp: string;  // ISO-8601
  session_id: string;
}

export interface TokenEvent extends _EventBase {
  type: 'token';
  content: string;
  agent: string;
}

export interface PlanGeneratedEvent extends _EventBase {
  type: 'plan_generated';
  plan: ExecutionPlan;
  complexity: string;
  total_steps: number;
}

export interface StepStartedEvent extends _EventBase {
  type: 'step_started';
  step_number: number;
  step_description: string;
  step_type: string;
}

export interface StepCompletedEvent extends _EventBase {
  type: 'step_completed';
  step_number: number;
  success: boolean;
  result: Record<string, unknown>;
  duration_ms: number;
}

export interface ErrorEvent extends _EventBase {
  type: 'error';
  error_code: string;
  message: string;
  recoverable: boolean;
}

export interface DoneEvent extends _EventBase {
  type: 'done';
  answer: string;
  execution_log: ExecutionLogEntry[];
  plan: ExecutionPlan | null;
  step_results: Record<string, unknown>;
  graph_data: GraphData | null;  // NEW — populated when answer involves KG tools
}

/** Discriminated union of all agent events */
export type AgentEvent =
  | TokenEvent
  | PlanGeneratedEvent
  | StepStartedEvent
  | StepCompletedEvent
  | ErrorEvent
  | DoneEvent;

// -------------------------------------------------------------------------
// Chat types
// -------------------------------------------------------------------------

export interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
  executionLog?: ExecutionLogEntry[];
  plan?: ExecutionPlan;
  stepResults?: Record<string, unknown>;
  isStreaming?: boolean;
  events?: AgentEvent[];
  graphData?: GraphData;       // NEW — replaces graphlet
}

// -------------------------------------------------------------------------
// API request / response types — match backend schemas
// -------------------------------------------------------------------------

export interface ChatRequest {
  question: string;
  history: Array<{ role: string; content: string }>;
  llm_provider: LLMProvider;
  session_id?: string | null;
}

export interface ChatResponse {
  answer: string;
  execution_log: ExecutionLogEntry[];
  plan: ExecutionPlan | null;
  step_results: Record<string, unknown>;
  graph_data: GraphData | null;  // NEW
  session_id?: string | null;
}

export interface ProvidersResponse {
  available_providers: LLMProvider[];
}

// -------------------------------------------------------------------------
// Session types — mirrors backend SessionOut
// -------------------------------------------------------------------------

export interface SessionMessage {
  role: string;
  content: string;
  timestamp: string;
}

export interface Session {
  id: string;
  created_at: string;
  updated_at: string;
  message_count: number;
  messages: SessionMessage[];
}

export interface SessionCreate {
  metadata?: Record<string, unknown>;
}

// -------------------------------------------------------------------------
// Config type for the config store
// -------------------------------------------------------------------------

export interface AppConfig {
  llmProvider: LLMProvider;
}
