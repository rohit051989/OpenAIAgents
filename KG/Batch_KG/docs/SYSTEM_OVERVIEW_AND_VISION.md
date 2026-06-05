# Spring Batch Intelligence Platform — System Overview & Vision

**Authors:** Rohit Khanna  
**Date:** April 2026  

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [The Problem — What Is Broken Today](#2-the-problem--what-is-broken-today)
3. [Why a Plain LLM Cannot Solve This](#3-why-a-plain-llm-cannot-solve-this)
4. [Why So Much Engineering Is Required](#4-why-so-much-engineering-is-required)
5. [Solution Overview — The Two-Graph Architecture](#5-solution-overview--the-two-graph-architecture)
6. [Phase 1 — Information Graph (IG)](#6-phase-1--information-graph-ig)
   - 6.1 [Spring Batch XML Parsing](#61-spring-batch-xml-parsing)
   - 6.2 [Java Source-Code Parsing & Call Hierarchy](#62-java-source-code-parsing--call-hierarchy)
   - 6.3 [Enrichers — Operations Discovery](#63-enrichers--operations-discovery)
   - 6.4 [Database Repository Scanner](#64-database-repository-scanner)
   - 6.5 [Human-in-the-Loop — VS Code Gap Analyzer Extension](#65-human-in-the-loop--vs-code-gap-analyzer-extension)
   - 6.6 [Manual Resource Associator & Configuration Layer](#66-manual-resource-associator--configuration-layer)
   - 6.7 [Dynamic Job Support — Excel-Driven Job Configuration](#67-dynamic-job-support--excel-driven-job-configuration)
7. [Phase 2 — Knowledge Graph (KG)](#7-phase-2--knowledge-graph-kg)
   - 7.1 [Class-Level (Structural) Loading](#71-class-level-structural-loading)
   - 7.2 [Instance-Level (Execution History) Loading](#72-instance-level-execution-history-loading)
   - 7.3 [CPM / PERT Critical-Path Analysis Engine](#73-cpm--pert-critical-path-analysis-engine)
   - 7.4 [Knowledge Graph Schema](#74-knowledge-graph-schema)
   - 7.5 [Dynamic Job Support in the Knowledge Graph](#75-dynamic-job-support-in-the-knowledge-graph)
8. [Phase 3 — MCP Server (BATCH-kg-ui-mcp)](#8-phase-3--mcp-server-batch-kg-ui-mcp)
9. [Phase 4 — Agentic Backend (BATCH-KG-BE)](#9-phase-4--agentic-backend-batch-kg-be)
10. [Phase 5 — Chat Frontend (BATCH-KG-FE)](#10-phase-5--chat-frontend-batch-kg-fe)
11. [End-to-End Data Flow](#11-end-to-end-data-flow)
12. [Use Cases — PoC Demo Scope & Query Capabilities](#12-use-cases--poc-demo-scope--query-capabilities)
13. [Technology Stack](#13-technology-stack)
14. [Competitive Differentiation](#14-competitive-differentiation)
15. [Customer Value Proposition](#15-customer-value-proposition)
16. [Roadmap & Extensibility](#16-roadmap--extensibility)

---

## 1. Executive Summary

Large financial institutions and insurance companies run thousands of **Spring Batch jobs** every night. These jobs read from databases, call stored procedures, invoke shell scripts, depend on external files arriving on time, and must complete within contractual SLA windows. The people who operate these jobs live under constant pressure: a delayed upstream file, a failing step, a slow database query, or a midnight job that quietly breaches its SLA.

The knowledge about the system — what every job does, which tables it touches, which jobs must finish before others can start, what the critical path looks like — is trapped in four disconnected places:

- Dense, hand-written Spring Batch XML configuration files
- Java source code spread across dozens of Git repositories
- A database or scheduling tool that holds historical run data
- The heads of a handful of senior engineers who have been around long enough to remember

This project converts all of that disconnected, tacit knowledge into a structured, queryable **graph** and then puts a **conversational AI agent** in front of it. Any team member — developer, operations analyst, business user, or senior leader — can ask plain-English questions about the batch estate and receive precise, evidence-backed answers in seconds.

The platform consists of five tightly integrated phases:

| Phase | Component | Purpose |
|---|---|---|
| 1 | Information Graph (IG) | Parse source + enrich with operations; human gap-fill |
| 2 | Knowledge Graph (KG) | Structural + execution data; CPM/PERT computations |
| 3 | MCP Server | AI-facing graph query layer |
| 4 | Agent Backend | Multi-agent LangGraph orchestration |
| 5 | Chat Frontend | Natural-language UI |

---

## 2. The Problem — What Is Broken Today

### 2.1 Information Is Siloed

A typical enterprise Spring Batch estate looks like this:

```
Git Repo A          Git Repo B          Git Repo C
  ├── jobs-config.xml  ├── dao-layer/     ├── procedures/
  ├── tasklets/        ├── services/      ├── shell-scripts/
  └── readers/         └── utils/        └── ddl/

Control-M / Autosys    Oracle / SQL Server    Spreadsheets / Wikis
  (schedule, SLAs)      (execution history)    (manual notes)
```

No single tool understands the complete picture. A developer debugging a failing job must open the XML to find the step, then grep the Java to find the DAO, then query the database to find the execution log, then call the DBA to understand the stored procedure. This takes hours, and any one person only ever sees a slice.

### 2.2 Operational Questions That Cannot Be Answered Today

The following questions are asked in production every week. Today they require a team of experienced engineers to answer manually:

| Question | Answer today |
|---|---|
| "Which jobs will be impacted if TABLE_X is unavailable?" | 2–4 hours, DBA + developer collaboration |
| "What is the critical path through tonight's batch?" | Nobody knows with precision |
| "Why did last night's batch SLA breach?" | Post-mortem, takes a day |
| "Which steps perform DELETE operations?" | Full code scan, hours |
| "If I change this DAO method, what breaks?" | Unknown without tracing |
| "How long does Job Y typically run, and is tonight's run slow?" | Excel sheet or monitoring tool |
| "What does customerProcessingJob actually do end to end?" | Ask the most senior engineer |

### 2.3 Tacit Knowledge Risk

Senior engineers hold critical understanding in their heads. When they leave, so does the knowledge. This is a real, recurring, and expensive problem for every customer in this space.

### 2.4 The Cost of Disconnection

- **Incident resolution time**: 2–8 hours per P1 incident (most of that is triage)
- **SLA breach discovery**: Often discovered reactively, never proactively
- **Onboarding time**: New engineers take months to become productive
- **Change risk**: Making a change to a shared DAO is terrifying because nobody knows all the callers

---

## 3. Why a Plain LLM Cannot Solve This

This is the most important question a senior architect or customer will ask. The answer is deeply technical, and it matters commercially.

### 3.1 LLMs Are Stateless — Your System Is Stateful

A plain LLM (GPT-4, Claude, Gemini) has no memory of your system. Every time you ask a question, you would need to provide the full context: all the XML, all the Java source code, all the execution history. A real enterprise batch estate has:

- Hundreds of XML files, totalling hundreds of thousands of lines
- Hundreds of Java classes and thousands of methods
- Years of execution history (millions of rows)

This exceeds the context window of any LLM available today, by orders of magnitude. Even if context windows continue to grow, stuffing raw, unstructured files into a prompt is the most expensive and least reliable approach possible.

### 3.2 LLMs Cannot Traverse Relationships

The core questions in batch operations require **graph traversal**:

> "Which jobs are impacted if this table is unavailable?"

To answer this, you need to follow a chain:
```
TABLE → JavaMethod (uses table) → JavaMethod (calls that method) → JavaClass → Step → Job → JobGroup
```

This chain may be 5–7 hops deep, across thousands of nodes. An LLM alone cannot do this. It cannot "follow links". It can only reason about text that is already in its context. A graph database executes this traversal in milliseconds.

### 3.3 LLMs Hallucinate Structural Facts

If you ask an LLM "which tables does customerProcessingJob write to?", it cannot know. It was not trained on your codebase. If you provide the code, it may correctly identify some tables and miss others, especially when the table name is constructed dynamically or passed through multiple method layers. The answer from an LLM is a **plausible guess**. The answer from the graph is **a fact derived from actual code analysis**.

### 3.4 LLMs Cannot Compute CPM / PERT

Critical Path Method (CPM) and Program Evaluation and Review Technique (PERT) are well-defined algorithms from operations research. They compute, given a directed acyclic graph of dependent tasks and their durations, what the minimum completion time is, which path is the bottleneck, and how much slack each task has. LLMs cannot run this computation reliably. They may approximate and guess; graphs compute it exactly.

### 3.5 LLMs Cannot Do Real-Time Comparison

"Is tonight's batch running slower than usual?" requires a precise statistical comparison against historical execution data. An LLM cannot retrieve, aggregate, and compare structured time-series data. A knowledge graph combined with Cypher queries can do this in milliseconds.

### 3.6 What LLMs *Can* Do, and Where We Use Them

We absolutely use LLMs — but in a precisely controlled role:

| LLM Task | Why LLM Is Right Here |
|---|---|
| Classify ambiguous DAO methods (LLM DAO Analyzer) | Pattern matching alone may fail for complex, dynamic SQL |
| Convert a natural-language question into a Cypher query | Translation task, bounded context (schema description) |
| Summarise graph query results into a readable answer | Synthesis task, bounded context (query results) |
| Decompose a complex user question into a plan of steps | Planning task, bounded context (available tools) |

The LLM is used as a **translator and summariser**. The graph is the source of truth. This is the right division of labour.

---

## 4. Why So Much Engineering Is Required

Building a knowledge graph from a live enterprise codebase is not a weekend project. Here is why.

### 4.1 The Source Material Is Not Machine-Readable Out of the Box

Spring Batch XML files were designed to be human-readable configuration files, not graph schemas. Java source code was designed to solve business problems, not to be analysed as a graph. Stored procedures are inside a database. Shell scripts may be inline strings or referenced by path. Extracting structured, connected information from all of these requires custom parsers for each.

### 4.2 Every Enterprise Has Gaps

No enterprise codebase is clean. Over years of development:

- Some steps reference bean names that no longer exist
- Some DAOs use dynamic SQL where the table name is a runtime variable
- Some stored procedure calls are wrapped in utility methods several layers deep
- Some resources (files, tables) are referenced in configuration rather than code

These gaps cannot be automatically resolved. They require a human reviewer who understands the business context. That is why we built the **VS Code Gap Analyzer Extension** — to put a structured, guided workflow in front of the engineer who can fill in what the automated analysis cannot.

### 4.3 Two-Graph Architecture Is Not Obvious but Is Essential

The distinction between the **Information Graph** (an exhaustive technical representation of the codebase) and the **Knowledge Graph** (a curated, enriched representation designed for AI consumption) is deliberate and important.

The IG is dense, technical, and complete. It includes every Java class, every method, every CALLS relationship. It is too large and too detailed for an AI agent to reason about directly; it would bury the relevant signal in noise.

The KG is selective and semantically enriched. It contains Jobs, Steps, Resources, SLAs, Calendars, Execution History, Critical Path calculations, and consolidated operation counts. It is designed to answer operational and business questions efficiently.

The pipeline that transforms one to the other is non-trivial. It involves:

- Traversing call graphs to consolidate DB operations up to the Step level
- Computing CPM/PERT across execution histories
- Linking scheduling contexts to jobs and execution runs
- Detecting resource availability events and their impact on running jobs

### 4.4 The Enrichment Pipeline Is Sophisticated

Identifying what a DAO method does is not simple:

- **JPA annotation-based queries** (`@Query`) are relatively straightforward
- **Named queries** require looking up a `@NamedQuery` definition elsewhere
- **JPQL** requires parsing a query language
- **Native SQL strings** require parsing SQL
- **Stored procedure calls** via `CallableStatement` or `JdbcTemplate.call` require Java AST analysis
- **Dynamic SQL** assembled at runtime may be partially or fully unresolvable statically

We use a tiered approach: fast pattern-matching first, then LLM analysis for ambiguous cases, then human review via the extension for unresolvable gaps.

### 4.5 Multi-Agent Orchestration Is Complex

Answering a question like "Show me the critical path for last night's batch run and explain which job caused the SLA breach" is not a single database query. It requires:

1. Understanding the question and breaking it into sub-tasks (Planner)
2. Retrieving the execution run identifiers (Tool call)
3. Querying the critical path calculation (Tool call or Cypher)
4. Querying the SLA configuration (Tool call)
5. Comparing execution duration against SLA (Cypher)
6. Synthesising all results into a coherent narrative (Summariser)

Wiring five specialised agents together, maintaining state across steps, handling errors, and streaming progress to a UI requires a proper orchestration framework (LangGraph). This is engineering, not configuration.

---

## 5. Solution Overview — The Two-Graph Architecture

The platform follows a layered architecture that transforms raw batch artefacts into a connected intelligence system. It starts by building an Information Graph from source repositories and execution inputs, then promotes that structure into a Knowledge Graph enriched with runtime history and critical-path reasoning. On top of that graph foundation, the MCP server, agent backend, and chat frontend work together to deliver grounded, conversational analysis.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        SOURCE SYSTEMS (Input)                               │
│  Spring Batch XML  │  Java Source Repos  │  DB Repo  │  Execution History   │
│  Dynamic Jobs Excel (Excel-configured jobs, no XML / Java definition)       │
└────────────────────┬────────────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│              PHASE 1 — INFORMATION GRAPH (IG) — Neo4j                       │
│                                                                             │
│  ┌────────────────────┐   ┌──────────────────────┐   ┌───────────────────┐ │
│  │ information_graph  │   │    Enrichers          │   │  VS Code          │ │
│  │ _builder_v4.py     │   │  db_operation_        │   │  Gap Analyzer     │ │
│  │                    │   │  enricher.py          │   │  Extension        │ │
│  │  Job, Step, Block  │   │  procedure_call_      │   │                   │ │
│  │  Decision, Listener│   │  enricher.py          │   │  Human fills      │ │
│  │  JavaClass         │   │  shell_execution_     │   │  unresolvable     │ │
│  │  JavaMethod        │   │  enricher.py          │   │  gaps via YAML    │ │
│  │  Bean, Resource    │   │                       │   └───────────────────┘ │
│  └────────────────────┘   └──────────────────────┘           │             │
│                                                               │             │
│                    manual_resource_associator.py ◄────────────┘             │
│                                                                             │
└────────────────────────────────────────────┬────────────────────────────────┘
                                             │
                                             ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│              PHASE 2 — KNOWLEDGE GRAPH (KG) — Neo4j                         │
│                                                                             │
│  ┌────────────────────────────────┐   ┌──────────────────────────────────┐  │
│  │  neo4j_direct_class_loader_v4  │   │  neo4j_direct_instance_loader_v3 │  │
│  │                                │   │                                  │  │
│  │  JobGroup, Job, Step           │   │  JobGroupExecution               │  │
│  │  ScheduleInstanceContext       │   │  JobContextExecution             │  │
│  │  SLA, BusinessCalendar, CalendarPattern, Holiday        │   │  ResourceAvailabilityEvent       │  │
│  │  Resource, DataAsset           │   │                                  │  │
│  │  Tag, Block, Decision          │   │  + CPM / PERT computation        │  │
│  └────────────────────────────────┘   └──────────────────────────────────┘  │
│                                                                             │
└────────────────────────────────────────┬────────────────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│              PHASE 3 — MCP SERVER (BATCH-kg-ui-mcp)                         │
│                                                                             │
│  FastAPI + FastMCP · SSE transport · Cypher-backed services                 │
│  Topology / Execution / Performance / Dependency / Schema tools             │
│                                                                             │
└────────────────────────────────────────┬────────────────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│              PHASE 4 — AGENT BACKEND (BATCH-KG-BE)                          │
│                                                                             │
│  FastAPI · LangGraph · Multi-LLM factory (OpenAI/Azure/Bedrock/Gemini)      │
│  Planner → ToolExecutor → CypherGenerator → Summariser                      │
│  Session management · SSE streaming · Correlation IDs                       │
│                                                                             │
└────────────────────────────────────────┬────────────────────────────────────┘
                                         │
                                         ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│              PHASE 5 — CHAT FRONTEND (BATCH-KG-FE)                          │
│                                                                             │
│  React 18 · TypeScript · Zustand · Vite · Real-time SSE streaming           │
│  Chat window · Execution log · MCP config · LLM provider selector           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Phase 1 — Information Graph (IG)

The Information Graph is the foundation of the entire platform. It is a complete, connected, machine-readable representation of the Spring Batch estate derived from source artefacts. 

### 6.0 The Starting Point — Multi-Repository Scanning and the File Tree

**Script**: `information_graph_builder_v4.py`, class `InformationGraphBuilder`

Before any parsing can begin, every artefact must be found and catalogued. Enterprise Spring Batch systems are not in a single folder. They span multiple Git repositories — typically a **code repository** (Java source), one or more **framework repositories** (shared Spring configuration, shared utilities), and a **DB repository** (SQL DDL, stored procedure definitions). A bean declared in the framework repo may be referenced from a job XML in the code repo. A stored procedure defined in the DB repo is called by a Java method in the code repo. Nothing is co-located.

Our first action is a **complete repository scan** — an exhaustive, recursive walk of every configured repository. Every file found is created as a node in the Information Graph before any semantic analysis starts. This is the **two-shot architecture**:

#### Shot 1 — Build the Complete File Tree

The first shot creates the structural skeleton of everything that exists:

```
Directory (root)
  └── Repository (code-repo)
        └── Project (core-batch)
              └── Package (com.company.batch.tasklets)
                    ├── JavaFile  → CustomerProcessingTasklet.java
                    ├── JavaFile  → OrderValidationTasklet.java
                    └── ...
  └── Repository (framework-repo)
        └── ...
  └── Repository (db-repo)
        └── ...
```

Every folder, package, project, and file becomes a node. This matters because:

1. **Scattered information is centralised**: All artefacts from all repositories land in one graph. A DAO in the code repo, a procedure definition in the DB repo, and a shared Spring config in the framework repo are now all nodes in the same connected graph.
2. **The graph exists before analysis**: If a file fails to parse, it still appears as a node. The gap is visible rather than silently absent.
3. **Paths are normalised to repo-relative format**: Every path is stored as `{repo_name}/{relative/path}` rather than an absolute system path. This makes the graph portable and independent of where the code is checked out on any particular machine.

#### File-Type Tagging

Each file node is tagged with one or more semantic labels based on rules configured in `config/information_graph_config.yaml`. The tagging is not a simple extension check — it inspects file content where needed:

| Label | Detection Logic |
|---|---|
| `JavaClass` | `.java` extension, not in test path |
| `JavaTestClass` | `.java` extension in `/src/test/`, `/test/` path patterns |
| `SpringConfig` | `.xml` file containing Spring namespace declarations (`springframework.org/schema/beans`, `/schema/batch`, etc.) — detected by parsing the XML root element |
| `XmlConfig` | Any non-POM `.xml` file |
| `PomFile` | `pom.xml` exact name match |
| `PropertyFile` | `.properties`, `.yaml`, `.yml` extensions |
| `WebXml` | `web.xml` exact name match |
| `DockerFile` | `Dockerfile`, `docker-compose*.yml` |
| `ShellScript` | `.sh`, `.bat`, `.ps1` extensions |
| `SqlFile` | `.sql`, `.ddl` extensions |
| `File` | Fallback for any unrecognised type |

**For Spring XML files specifically**, the system reads the batch-configuration entry point file (if the repository declares one) and builds an **allowed import list**. Only XML files that are reachable via `<import resource="..."/>` chains from the declared entry point are tagged as `SpringConfig` and included in Spring parsing. This prevents the graph from being polluted by test fixture XMLs, archived configuration, or unrelated Spring context files that happen to sit in the same repository.

**Why Shot 1 comes first**: All file paths must be recorded before any Java is parsed, because the Java parser needs to resolve source paths for class files — it looks up files by their node path in the graph. Building the tree first means lookups always find the file node even if the parser has not yet processed that file's content.

#### Git Provenance on Every Node

Every node in the Information Graph carries full git metadata populated during the scan:

| Property | Description |
|---|---|
| `gitRepoName` | Name of the repository (from config) |
| `gitBranchName` | Branch being scanned |
| `gitCreatedBy` | Author who first introduced this file |
| `gitCreatedAt` | ISO-8601 timestamp of first commit |
| `gitUpdatedBy` | Author of the last modifying commit |
| `gitUpdatedAt` | ISO-8601 timestamp of last commit |
| `gitLastCommitId` | Full SHA of the last commit |
| `gitFileExists` | `true` for active files; `false` for soft-deleted nodes |

This enables auditing, change tracking, and provenance queries: "Who last changed this DAO method's file, and when?"

### 6.1 Spring Batch XML Parsing

**Script**: `information_graph_builder_v4.py` — Shot 2 (after file tree is built)

With the file tree in place, Shot 2 processes the semantic content of each file. For Spring XML files tagged `SpringConfig`, the parser reads the batch namespace elements — Jobs, Steps, Flows, Splits, Decisions, Listeners, and Beans — using Python's `xml.etree.ElementTree`.

**Node types extracted**:

| Node Type | Description |
|---|---|
| `Job` | A Spring Batch Job definition |
| `Step` | An individual unit of work (TASKLET or CHUNK kind) |
| `Block` | A FLOW or PARALLEL block grouping multiple Steps |
| `Decision` | A routing point based on exit status |
| `Listener` | A `JobExecutionListener` or `StepExecutionListener` |
| `Bean` | A Spring bean definition linking ID to implementing class |

**Relationships extracted**:

| Relationship | Meaning |
|---|---|
| `Job -[:CONTAINS]-> Step/Block` | Steps/Blocks belong to this Job |
| `Job -[:ENTRY]-> Step/Block` | First node in the execution graph |
| `Step/Block -[:PRECEDES]-> Step/Block` | Execution ordering with `on` condition |
| `Block -[:CONTAINS]-> Step/Block` | Nested structure inside a Flow or Split |
| `Job -[:HAS_LISTENER]-> Listener` | Job-level execution listeners |

**Why this matters**: The XML defines the *skeleton* of the batch — the sequence, branching, and parallelism. Without this, the Java code analysis has no context. A DAO method is meaningless until you know which Step calls it, and which Job owns that Step.

### 6.1a The Global Spring Bean Registry and Composite Keys

One of the most subtle but important engineering challenges in building the IG is **cross-file bean resolution**. In a real enterprise Spring application:

- A job XML in repository A declares `<step ref="customerTasklet"/>` — a reference to a bean
- The bean `customerTasklet` is defined in a shared Spring configuration file in repository B
- That bean's `class` attribute points to a class in repository A's Java source

Resolving this requires a **global registry** of all beans discovered across all XML files in all repositories, built and indexed before any job processing begins.

The `SpringBeanRegistry` class (`classes/SpringBeanRegistry.py`) implements this:

```python
class SpringBeanRegistry:
    """
    Central registry for all Spring beans with dual-indexed maps.
    Uses composite keys (bean_id___bean_class) internally to prevent overwrites.
    """
    beans_by_composite_key: Dict[str, BeanDef]   # "myBean___com.example.MyClass"
    beans_by_simple_id:     Dict[str, List[str]]  # "myBean" → [composite_keys]
    beans_by_class:         Dict[str, List[BeanDef]]  # class FQN → [BeanDefs]
```

**The composite key problem**: Without composite keys, two beans with the same `id` in different XML files (e.g., a production bean and a test override bean, both named `dataSource`) would overwrite each other in a simple dictionary. The composite key `bean_id___bean_class` uniquely identifies each bean even when IDs collide across files. Lookups by simple ID still work but surface the ambiguity as a warning.

**Three lookup strategies**:
1. `get_by_id(bean_id)` — fast lookup when you have just a bean name from an XML `ref="..."` attribute
2. `get_by_composite_key(bean_id___class_fqn)` — precise lookup when you have both
3. `get_by_class(class_fqn)` — lookup all beans backed by a given Java class

**Bean nodes in the graph**: Each resolved `BeanDef` becomes a `Bean` node in the IG, linked to its `SpringConfig` source file and to the `JavaClass` node it implements. This means the graph can answer "which beans implement CustomerDAO?" and "which XML file declares the `customerTasklet` bean?".

### 6.2 Java Source-Code Parsing & Call Hierarchy

**Script**: `information_graph_builder_v4.py`, `classes/JavaCallHierarchyParser.py`

This is the most technically complex part of the entire platform. Building a correct, complete call hierarchy from a real enterprise Java codebase is a multi-faceted parsing and resolution problem. Each of the challenges below required specific engineering to solve.

#### The Parsing Foundation — TreeSitter AST

The fundamental approach is to first parse every Java source file into a full **Abstract Syntax Tree (AST)** using **`tree-sitter-java`**. TreeSitter is a deterministic, incremental parser generator that produces a concrete syntax tree for any Java file, regardless of which Java version features it uses — records, sealed classes, text blocks, pattern matching, or any other construct.

Once the AST is available, all information extraction is done by **custom traversal logic** written on top of the tree:

- **Package declaration**: Extracted from the `package_declaration` node at the root — gives the canonical package name for FQN construction
- **Import statements**: All `import_declaration` nodes collected into a map of `simple_name → fully_qualified_name` — used throughout to resolve unqualified type names in method signatures and field declarations
- **Class and interface declarations**: `class_declaration` and `interface_declaration` nodes extracted with their modifiers, `extends` type, and `implements` list
- **Fields**: All `field_declaration` nodes in the class body extracted in a dedicated first pass — capturing field name and declared type before any method body is processed
- **Methods**: `method_declaration` nodes extracted with their return type, parameter list (name + type pairs), and modifiers
- **Method bodies**: Each method body is traversed to extract all `method_invocation` and `object_creation_expression` nodes — these form the raw `CALLS` edges before resolution

This approach — parse once to AST, then apply custom extraction on top — means the system is decoupled from any particular Java version or syntax flavour. Adding support for a new Java construct requires only a new traversal rule, not a new parser.

#### Challenge 1 — Method Overloading Resolution

Java allows multiple methods with the same name but different parameter signatures in the same class. When method `A` calls `process(order)`, which overloaded version of `process` was called?

The parser captures **argument types at each call site** by:
1. Resolving the type of each argument from local variable declarations, field types, and method parameters
2. Using `get_method_by_name_and_params(method_name, argument_types)` to find the correct overload

A method key is constructed as `method_name(param_type1, param_type2)` — for example, `process(Order)` vs `process(String, Long)`. This composite method key ensures that `CALLS` relationships point to the correct overload and that duplicate edges between the same two classes are not created for different overloads.

#### Challenge 2 — Spring Dependency Injection and Field Resolution

In Spring, classes depend on each other via injected fields, not via `new` instantiation. A typical tasklet looks like:

```java
@Component
public class CustomerProcessingTasklet implements Tasklet {
    @Autowired
    private CustomerDataService customerDataService;  // injected

    public RepeatStatus execute(...) {
        customerDataService.processCustomer(...);  // who is this?
    }
}
```

When parsing the `execute()` method, encountering `customerDataService.processCustomer(...)` requires knowing that `customerDataService` is a field of type `CustomerDataService`. The parser:

1. **Extracts all fields** from the class body *before* processing any method bodies — fields are stored in `ClassInfo.fields` as a `{field_name: type_name}` map
2. When processing a method call with qualifier `customerDataService`, looks up `customerDataService` in the fields map to resolve the type
3. Applies the same logic to **constructor-injected parameters** and **method-level parameters**

For TreeSitter parsing, fields must be extracted in a **first pass over the class body** before any method body is touched. Failing to do this first-pass ensures every qualifier lookup fails silently — a bug that was caught and fixed.

#### Challenge 3 — Inheritance and Parent Class Method Resolution

A class may call a method that is not defined in itself but inherited from a parent class:

```java
public class BatchJobDAOImpl extends AbstractBatchDAO {
    public List<Job> findActiveJobs() {
        return getJdbcTemplate().queryForList(...);  // defined in AbstractBatchDAO
    }
}
```

`getJdbcTemplate()` is not in `BatchJobDAOImpl`. The parser must walk the inheritance chain:

```
BatchJobDAOImpl → AbstractBatchDAO → JdbcDaoSupport (Spring)
```

`find_method_in_class_hierarchy(class_fqn, method_name, all_classes_cache, max_depth=10)` implements this with a guard on maximum depth (10 levels) to prevent infinite loops from circular inheritance edges in partially parsed class trees.

#### Challenge 4 — Interface-to-Implementation Resolution (Spring DI)

This is the hardest challenge. In idiomatic Spring code, dependencies are declared on **interfaces**, not concrete classes:

```java
private CustomerRepository customerRepository;  // interface
customerRepository.findByStatus("ACTIVE");      // which implementation?
```

The `CustomerRepository` interface may have one implementation, multiple (for different environments), or zero in the local codebase (it might be in an external library). Resolution requires:

**Step 1 — Build the Interface Registry**:
`build_simple_interface_registry(all_classes_cache)` scans every parsed class and maps each interface to all classes that `implements` it directly:

```
CustomerRepository → [CustomerRepositoryImpl, MockCustomerRepository, ...] 
```

**Step 2 — Classify each interface call site**:

| Scenario | Resolution | CALLS relationship |
|---|---|---|
| Interface has exactly 1 implementation | Auto-resolve to that implementation | `resolvedFromInterface=true`, `requiresHumanReview=false` |
| Interface has 0 implementations (external library, e.g. Spring's `JpaRepository`) | Cannot resolve | `requiresHumanReview=true`, `reviewReason="unresolved_no_impl"` |
| Interface has 2+ implementations | Use first; flag ambiguity | `requiresHumanReview=true`, `reviewReason="multiple_implementations"`, `candidateImplementations=[...]` |
| Method name not found in resolved implementation | Walk parent class chain | If still not found: `requiresHumanReview=true`, `reviewReason="method_not_found_in_implementation"` |

Every `CALLS` relationship in the graph carries these metadata properties. The VS Code Gap Analyzer Extension (Phase 1.5) surfaces all relationships with `requiresHumanReview=true` so a domain expert can review and correct them.

**Interface resolution statistics** are logged at the end of each job's processing, showing exactly how many calls were auto-resolved, how many defaulted to first-of-multiple, and how many were left unresolved. This transparency is essential for understanding graph completeness.

#### Challenge 5 — Chained Method Call Resolution

Modern Java code frequently uses method chaining:

```java
customerService
    .getActiveCustomers()
    .stream()
    .filter(c -> c.isEligible())
    .forEach(this::process);
```

When `.filter(...)` is encountered, there is no explicit qualifier — it is called on the return value of the previous call. The parser maintains a `previous_call_return_types` map during method body processing. After resolving each call, its return type is stored. The next call with no qualifier checks whether a previous call's return type has a method of that name.

This allows the parser to follow chains across service and repository boundaries without requiring explicit variable declarations.

#### Challenge 6 — Qualified vs Unqualified Calls and `this`/`super`

Within a method body, calls appear in several syntactic forms:
- `doSomething()` — unqualified call, target is `this` class
- `this.doSomething()` — explicit `this`, same result
- `super.doSomething()` — parent class method (walk extends chain)
- `someField.doSomething()` — field-qualified call (resolve field type first)
- `getHelper().doSomething()` — method-return-qualified call (chained)
- `new CustomerService().doSomething()` — object creation inline

For TreeSitter, **named field access** is used exclusively rather than text-based splitting of the source bytes. Text splitting fails for multi-line chains where the qualifier spans multiple lines. The TreeSitter grammar provides `object` and `name` named fields on every `method_invocation` node, making the receiver and called method always unambiguous.

#### The Resulting Call Hierarchy Node Types

Once all the above challenges are handled, the parser emits the final graph nodes:

| Node Type | Captured Properties |
|---|---|
| `JavaClass` | FQN, class name, package, `isInterface`, `isDAOClass`, `isShellExecutorClass`, `isTestClass`, `extends`, `implements` |
| `JavaMethod` | FQN, method name, return type, signature (with parameter types), modifiers, line count |

**Relationships**:

| Relationship | Properties |
|---|---|
| `JavaClass -[:HAS_METHOD]-> JavaMethod` | — |
| `JavaMethod -[:CALLS]-> JavaMethod` | `lineNumber`, `requiresHumanReview`, `resolvedFromInterface`, `originalInterface`, `reviewReason`, `candidateImplementations` |
| `JavaClass -[:USES_CLASS]-> JavaClass` | Class-level dependency edge |
| `Step -[:IMPLEMENTED_BY]-> JavaClass` | Step's implementing Tasklet |
| `Step -[:USES_READER]-> JavaClass` | Step's ItemReader |
| `Step -[:USES_WRITER]-> JavaClass` | Step's ItemWriter |
| `Step -[:USES_PROCESSOR]-> JavaClass` | Step's ItemProcessor |

**Call-depth traversal**: The `CALLS` graph can be queried to any depth, for example to ask "which DAO methods are reachable from the `execute()` method of step X within 5 hops", while the `requiresHumanReview` property on each edge tells the reader how much confidence to place in that edge.

### 6.3 Enrichers — Operations Discovery

After the graph skeleton is built, three independent enrichers run to discover what each method *does*. They are designed to run in parallel.

#### DB Operation Enricher (`db_operation_enricher.py`)

Analyses every `JavaMethod` in a DAO class to determine what database operations it performs. Uses a two-tier strategy:

**Tier 1 — Pattern Matching (fast, deterministic)**:
- Method name heuristics: `findAll` → SELECT, `save`/`insert` → INSERT, `delete` → DELETE
- JPA `@Query` annotation content
- Spring Data method name conventions (`findByCustomerId`)
- EntityManager API calls (`em.persist`, `em.merge`)
- JPQL/HQL string analysis

**Tier 2 — LLM Analysis (for complex cases)**:
- SQL strings assembled at runtime
- Complex conditional logic
- Stored procedure wrappers
- LLM receives the method body and returns structured JSON: `{operation_type, table_name, confidence}`
- Supports AWS Bedrock (Claude) and OpenAI

**Output**: Each `JavaMethod` node is updated with:
- `dbOperations` — serialised list of detected operations (TYPE:TABLE:CONFIDENCE)
- `dbOperationCount` — integer count
- `Step` nodes are updated with consolidated `stepDbOperations` and `stepDbOperationCount`

#### Procedure Call Enricher (`procedure_call_enricher.py`)

Analyses Java methods for calls to Oracle stored procedures or SQL Server stored functions via:
- `CallableStatement` usage
- `JdbcTemplate.call()` / `SimpleJdbcCall`
- String patterns like `{call SCHEMA.PACKAGE.PROCEDURE_NAME(...)}`

**Output**: `procedureCalls` and `procedureCallCount` on `JavaMethod` nodes; consolidated on `Step` nodes.

#### Shell Execution Enricher (`shell_execution_enricher.py`)

Analyses Java methods for shell script invocations via:
- `Runtime.getRuntime().exec(...)`
- `ProcessBuilder` with script file references
- Custom utility wrapper patterns

**Output**: `shellExecutions` and `shellExecutionCount` on `JavaMethod` nodes.

#### Rules Engine

Each enricher is configured via a YAML rules file (`config/dao_analysis_rules.yaml`, `config/procedure_analysis_rules.yaml`, `config/shell_execution_rules.yaml`). This allows rules to be updated without code changes — a pattern recognition problem (e.g., a new ORM framework) becomes a configuration change, not a software release.

### 6.4 Database Repository Scanner

**Script**: `db_repo_scanner.py`

Beyond code analysis, the platform scans dedicated SQL/DDL repositories to discover resource objects — tables, views, stored procedures, functions, packages, and sequences — directly from their definition files. Each discovered object becomes a `Resource` node with:

- Schema name, object type, package name (Oracle packages)
- Git provenance (repo, branch, author, commit)
- DDL snippet for documentation

This means the platform knows not just that *code calls a table* but that *this specific table exists, lives in this schema, was created by this team, and its DDL is here*. Resource discovery from the code repo and from the DB repo is reconciled automatically.

### 6.5 Human-in-the-Loop — VS Code Gap Analyzer Extension

**Repository**: `batch-ig-vscode-extension`  
**API**: `Batch-IG-Extension-APIs`

No automated analysis is perfect. In any large, real-world codebase there will be:
- Dynamic SQL where the table name is a variable
- Shell script paths passed as configuration properties
- Stored procedures referenced through abstraction layers the parser cannot resolve
- Resource associations that are conceptual (a job "logically" reads from a table, but the DAO doesn't show it directly)

These are called **gaps** — knowledge that the automated pipeline cannot fill with confidence.

#### The VS Code Extension

The Gap Analyzer is a Visual Studio Code extension that presents a structured workflow to the engineer:

1. **Browse**: Jobs → Steps → Categories (DB Operations / Procedure Calls / Shell Executions)
2. **View Gaps**: See what the automated analysis detected, what it could not resolve, and which steps have `FURTHER_ANALYSIS` flags
3. **Fill Gaps**: Category-specific forms guide the engineer through providing the missing information
4. **Export**: The extension generates YAML configuration files ready for ingestion by `manual_resource_associator.py`

The extension communicates with Neo4j via the **`Batch-IG-Extension-APIs`** FastAPI service, which acts as a controlled API layer. The extension never speaks to Neo4j directly. The API provides:

- `GET /api/v1/jobs` — list all jobs with gap counts
- `GET /api/v1/jobs/{job_name}/steps` — steps per job
- `GET /api/v1/steps/{step_name}/gaps` — gap list per step (DB/procedure/shell)
- `GET /api/v1/methods/java-file?fqn={fqn}` — resolve source file for a method FQN

This human review step is what separates a *high-confidence knowledge graph* from a *best-effort automated index*. The engineer's domain knowledge fills precisely the gaps that automation cannot.

### 6.6 Manual Resource Associator & Configuration Layer

**Script**: `manual_resource_associator.py`  
**Config**: `config/grey_area_resolution_*.yaml`, `config/manual_mappings_sample.yaml`

The YAML files generated via the VS Code extension are ingested by the manual resource associator, which:
- Creates or updates `Resource` nodes for manually identified tables, files, and procedures
- Creates `PERFORMS_DB_OPERATION`, `CALLS_PROCEDURE`, or `EXECUTES_SHELL` relationships
- Attaches confidence scores and resolution provenance to each assertion

This produces a fully enriched Information Graph ready for Knowledge Graph extraction.

### 6.7 Dynamic Job Support — Excel-Driven Job Configuration

**Script**: `dynamic_ig_loader.py`  
**Configuration**: `config/information_graph_config.yaml` (`dynamic_jobs:` section)  
**Data Source**: `sample_data/Dynamic_Jobs.xlsx` (sheet: `Dynamic_Job_Details`)

Not all batch jobs are defined in Spring Batch XML. Some jobs are **dynamically configured** — they run a single, shared implementing class (`DynamicTasklet`) and determine what to do entirely from runtime parameters. Because there is no custom Java logic and no job-specific XML, these jobs would otherwise be invisible to the graph.

The `dynamic_ig_loader.py` module reads an Excel file and creates a complete, connected IG representation for every dynamic job. **Dynamic steps link Resources directly — there are no artificial Bean, JavaClass, or JavaMethod nodes.** This keeps the graph clean and avoids polluting the Java call-hierarchy with synthetic code nodes.

#### Excel Input Format

The Excel file (`Dynamic_Jobs.xlsx`, sheet `Dynamic_Job_Details`) contains one row per step parameter:

| Column | Description |
|---|---|
| `JOB_NAME` | Name of the dynamic job |
| `JOB_ID` | Numeric job identifier |
| `STEP_NAME` | Step name within the job |
| `STEP_ORDER` | Execution order of the step within the job |
| `STEP_KIND` | Semantic role of the step (see supported values below) |
| `KEY_PARAM` | Parameter key (see supported keys below) |
| `VALUE_PARAM` | Parameter value for that key |

**`STEP_KIND` values** (new column — defines the semantic role of the step):

| `STEP_KIND` | Description |
|---|---|
| `SHELL_EXECUTION` | Runs a shell/batch script |
| `FILE_DOWNLOAD` | Downloads a file from a remote location |
| `FILE_UPLOAD` | Uploads a file to a remote location |
| `DO_NOTHING` | Placeholder / no-op step |

`STEP_KIND` is extensible — new kinds can be added as requirements evolve without changing the graph schema.

**Supported `KEY_PARAM` values**:

| `KEY_PARAM` | Type | Description |
|---|---|---|
| `FILE` | Shell | Shell script filename to execute |
| `DIR` | Shell | Directory containing the script |
| `PARAMS` | Shell | Runtime arguments passed to the script |
| `USER` | Shell | OS user under which the script runs |
| `PROC_NAME` | Procedure | Name of the stored procedure to call |
| `PROC_SCHEMA` | Procedure | Database schema owning the procedure |
| `PROC_PACKAGE` | Procedure | Package containing the procedure (Oracle) |
| `PROC_PARAMS` | Procedure | Parameters passed to the procedure |

A step with `FILE`/`DIR` keys creates a **SHELL_SCRIPT Resource**; a step with `PROC_NAME` creates a **PROCEDURE/FUNCTION Resource**. A step may reference both types. The `STEP_KIND` property is stored on the `Step` node as `dynamicStepKind`.

#### Direct Step → Resource Model

Dynamic steps expose their resource associations **directly on the Step node**, without any Java code intermediary. This is the correct model because dynamic jobs have no custom Java — the step *is* the operation.

| Node/Property | Description |
|---|---|
| `Step.stepKind` | `TASKLET` (Spring Batch execution model) , `SHELL_EXECUTION`, `FILE_DOWNLOAD`, etc. |
| `Step.stepShellExecutions` | Summary array: `RESOLVED:<script>:HIGH` |
| `Step.stepProcedureCalls` | Summary array: `ORACLE:<proc>:HIGH` |
| `Step.stepSqlFileInvocations` | SQL files invoked via sqlplus inside the shell |

#### Resource Nodes — Script Detail Belongs on Resource, Not Step

A key design principle: **script detail lives on `Resource` nodes, not on `Step` nodes**. Each unique shell script or stored procedure found in the Excel becomes a dedicated `Resource` node.

**Shell script `Resource` properties**: `name`, `type=SHELL_SCRIPT`, `scriptPath`, `scriptType`, `scriptParams`, `executionUser`

**Procedure `Resource` properties**: `name`, `type=PROCEDURE|FUNCTION`, `databaseType`, `schemaName`, `packageName`

**Smart common-key matching**: If the Excel path contains a `*common/<Folder>/<File>` pattern and an existing IG node from the repository scan has the same `<Folder>/<File>` path suffix, the loader enriches and links that existing node — no duplicate `Resource` is created.

**SQL invocation tracking**: If the shell script file exists in the scanned repositories, the loader parses it for `sqlplus @/path/to/file.sql` patterns and creates additional `Resource {type: 'SQL_SCRIPT'}` nodes linked via `INVOKES {executionType: 'SQL_SCRIPT'}`.

#### IG Relationships Created

| Relationship | Meaning |
|---|---|
| `Job -[:CONTAINS]-> Step` | Dynamic step belongs to dynamic job |
| `Step -[:EXECUTES {scriptType, confidence, dynamicJob:true}]-> Resource` | Shell script execution (direct from Step) |
| `Step -[:INVOKES {databaseType, confidence, dynamicJob:true}]-> Resource` | Stored procedure invocation (direct from Step) |
| `Resource(SHELL) -[:INVOKES {executionType:'SQL_SCRIPT'}]-> Resource(SQL)` | SQL file called from within the shell script |
| `Job -[:ENTRY]-> Step` | First step in execution order |
| `Step -[:PRECEDES {on: 'COMPLETED'}]-> Step` | Ordered execution chain |

The `Job` node carries `type = 'dynamic_job'` making dynamic vs XML-parsed jobs easily filterable. `Step` nodes carry both `dynamicJob = true` and `dynamicStepKind`, enabling targeted queries such as "show me all dynamic steps that execute shell scripts".

#### Integration into the IG Build Pipeline

The dynamic IG loader runs as the **last phase** of `information_graph_builder_v4.py`, after all regular XML parsing and enrichment is complete. Its execution time is measured separately and reported in the performance summary. The `dynamic_jobs:` section in `config/information_graph_config.yaml` controls whether loading is enabled, the Excel file path, and the shared tasklet class FQN (kept for config compatibility — no longer used to create JavaClass nodes).

---

## 7. Phase 2 — Knowledge Graph (KG)

While the Information Graph is a faithful, exhaustive representation of the source code and its structure, the Knowledge Graph is a *curated, semantically enriched* representation designed specifically for operational AI reasoning. It is a different Neo4j database.

### 7.1 Class-Level (Structural) Loading

**Script**: `neo4j_direct_class_loader_v4.py`

The class-level loader pulls from two sources: the Information Graph (for Jobs, Steps, Resources, and Java lineage) and an Excel/YAML configuration file (for scheduling metadata that lives outside the codebase).

**Nodes loaded**:

| Node | Source |
|---|---|
| `Job` | Pulled directly from Information Graph |
| `JobGroup` | Excel / manual configuration |
| `Step` | Pulled from Information Graph with consolidated operation counts |
| `Block` | Pulled from Information Graph |
| `Decision` | Pulled from Information Graph |
| `Listener` | Pulled from Information Graph |
| `ScheduleInstanceContext` | Excel / scheduling system export |
| `Resource` | Merged from Information Graph + Excel |
| `DataAsset` | Derived from Step DB operations via IG traversal |
| `SLA` | Excel / manual configuration |
| `BusinessCalendar` | Excel / manual configuration |
| `CalendarPattern` | Excel / manual configuration |
| `Holiday` | Excel / manual configuration |
| `Tag` | Excel / manual configuration |

**Key enrichment during loading — DataAsset derivation**:

The loader traverses the Information Graph's `IMPLEMENTED_BY → HAS_METHOD → CALLS*` graph to collect every DB operation reachable from each Step's entry methods. It additionally reads shell-script and stored-procedure execution links from the IG. All of these are consolidated into `DataAsset` nodes linked by typed relationships:

| Relationship | Meaning |
|---|---|
| `Step -[:READS_FROM]-> DataAsset` | Step reads data from this resource |
| `Step -[:WRITES_TO]-> DataAsset` | Step writes data to this resource |
| `Step -[:DELETES_FROM]-> DataAsset` | Step deletes data from this resource |
| `Step -[:AGGREGATES_ON]-> DataAsset` | Step aggregates from this resource |
| `Step -[:EXECUTES]-> DataAsset` | Step executes a shell script or calls a stored procedure |

This single capability enables the "data lineage" and "blast radius" queries that are impossible with raw source analysis.

**Scheduling graph**:

The `ScheduleInstanceContext` nodes represent the *scheduling instances* of Jobs — the same Job may run in multiple contexts (e.g., different parameter sets, different times). The PRECEDES graph between SIC nodes defines the job execution order within a `JobGroup`, enabling:

- Topological traversal of the entire job group execution sequence
- Upstream/downstream dependency queries for any individual job

### 7.2 Instance-Level (Execution History) Loading

**Script**: `neo4j_direct_instance_loader_v3.py`

Historical execution data is loaded from the scheduling/operations system (exported to Excel). This layer links *what was planned* (class-level graph) to *what actually happened* (execution instances).

**Nodes loaded**:

| Node | Description |
|---|---|
| `JobGroupExecution` | A single run of an entire job group (one business date) |
| `JobContextExecution` | A single execution of one job context within that run |
| `ResourceAvailabilityEvent` | When a file or other resource became available |

**Relationships**:

| Relationship | Meaning |
|---|---|
| `JobGroupExecution -[:EXECUTES_JOB_GROUP]-> JobGroup` | Links run to its group definition |
| `JobGroupExecution -[:EXECUTES_JOB_CONTEXT]-> JobContextExecution` | All job runs in this group run |
| `JobContextExecution -[:EXECUTES_CONTEXT]-> ScheduleInstanceContext` | Links execution to its schedule context |
| `JobContextExecution -[:EXECUTES_JOB]-> Job` | Direct job reference for fast query |
| `ResourceAvailabilityEvent -[:FOR_RESOURCE]-> Resource` | Which resource arrived |
| `ResourceAvailabilityEvent -[:FOR_RUN]-> JobGroupExecution` | Which batch run it belongs to |
| `ResourceAvailabilityEvent -[:IMPACTED]-> JobGroupExecution/JobContextExecution` | Arrival was late (arrived after expected start time) |

The `IMPACTED` relationship is automatically computed during loading: if a file arrived *after* a job was supposed to have started, the resource event is marked as impacting that job.

### 7.3 CPM / PERT Critical-Path Analysis Engine

**Script**: `execution_cpm_analyzer_v3.py`, `cpm_analyzer_v1.py`

After execution history is loaded, the platform runs Critical Path Method (CPM) analysis for every `JobGroupExecution`. This is full algorithmic CPM:

1. **Build the DAG**: The `ScheduleInstanceContext PRECEDES` graph defines dependencies
2. **Assign durations**: From actual `JobContextExecution.durationMs` (or estimated durations for the class-level version)
3. **Forward pass**: Compute Earliest Start (ES) and Earliest Finish (EF) for every node
4. **Backward pass**: Compute Latest Start (LS) and Latest Finish (LF) for every node
5. **Compute slack**: `Slack = LS − ES` for each node
6. **Identify critical path**: Nodes with `Slack = 0` form the critical path

**Results persisted in the graph**:

| Node | Properties |
|---|---|
| `CriticalPathInstance` | ES, EF, LS, LF, Slack, Duration, `isLongest` flag per job execution |
| `CriticalPathCalculated` | Total completion time, total buffer, critical path sequence, signature hash |
| `CriticalPathSignature` | Unique patterns of critical paths with occurrence counts |

**Critical Path Signatures**: A signature is a canonical string representation of the critical path sequence. The platform maintains a library of unique signatures per job group, tracking how frequently each pattern occurs. When tonight's critical path matches a known signature, it can be compared against historical performance for that exact pattern.

This enables questions that exist nowhere else in the industry:

- "What is the critical path for tonight's run, and how does it compare to historical runs with this same critical path?"
- "Has the critical path shifted to a new sequence not seen before?"
- "Which job has the smallest slack and is most at risk of causing an SLA breach if it runs 10% slower?"

### 7.4 Knowledge Graph Schema

The full schema contains 22 node types, connected by over 30 relationship types, and is described in `Latest_KG_Schema.txt`. The key node categories are:

**Structural (Class-Level)**:
`JobGroup → Job → Step/Block/Decision/Listener → DataAsset → Resource`

**Scheduling**:
`JobGroup → ScheduleInstanceContext ← Job`  
`ScheduleInstanceContext -[:PRECEDES]-> ScheduleInstanceContext`

**Constraints**:
`JobGroup/ScheduleInstanceContext/Resource -[:HAS_SLA]-> SLA`  
`SLA -[:RELATIVE_TO_RESOURCE]-> Resource` (for relative SLAs)  
`JobGroup/ScheduleInstanceContext -[:Require_Resource]-> Resource`

**Execution (Instance-Level)**:
`JobGroupExecution -[:EXECUTES_JOB_GROUP]-> JobGroup`  
`JobGroupExecution -[:EXECUTES_JOB_CONTEXT]-> JobContextExecution`  
`JobContextExecution -[:EXECUTES_JOB]-> Job`

**Critical Path**:
`JobGroupExecution -[:HAS_CRITICAL_PATH_CALCULATED]-> CriticalPathCalculated`  
`CriticalPathInstance -[:FOR_RUN]-> JobContextExecution`  
`CriticalPathCalculated -[:HAS_SIGNATURE]-> CriticalPathSignature`

**Code Lineage** (IG-sourced, available for deep queries):
`Step -[:IMPLEMENTED_BY]-> JavaClass -[:HAS_METHOD]-> JavaMethod -[:CALLS]-> JavaMethod`

### 7.5 Dynamic Job Support in the Knowledge Graph

Dynamic jobs created by `dynamic_ig_loader.py` flow into the KG automatically — **no separate loader or additional configuration is required**.

#### Automatic Flow via Existing Loaders

The KG loading methods `_load_jobs_from_graph()` and `_load_steps_directly_from_IG()` query **all** `Job` and `Step` nodes from the Information Graph without type-filtering. Because dynamic jobs are first-class IG nodes (carrying `type='dynamic_job'` but structurally identical to XML-parsed jobs), they are included in the standard structural load automatically.

The result is that after `neo4j_direct_class_loader_v4.py` runs, the KG contains all dynamic `Job` and `Step` nodes with standard properties, linked into the same `JobGroup → Job → Step` graph as every other job.

#### Shell and Procedure Executions — DataAsset Enrichment

Beyond the structural copy, the class loader runs `_copy_step_shell_and_procedure_executions_from_info_graph()` (immediately after the existing DB-operations enrichment). This method:

1. Reads `JavaMethod -[:EXECUTES]-> Resource(SHELL_SCRIPT)` and `JavaMethod -[:INVOKES]-> Resource(PROCEDURE|FUNCTION)` links from the IG
2. Traverses from each `Step` to its implementing `JavaClass` — supporting both `IMPLEMENTED_BY` (TASKLET steps) and `USES_BEAN → Bean → IMPLEMENTS` (CHUNK steps)
3. Creates `DataAsset` nodes following the same intermediary pattern used for DB operations:

```
Step -[:EXECUTES {scriptType|databaseType, confidence:'HIGH'}]-> DataAsset -[:FOR_RESOURCE]-> Resource
```

**Shell `DataAsset` properties**: `description`, `scriptType`, `scriptParams`, `executionUser`  
**Procedure `DataAsset` properties**: `description`, `databaseType`, `schemaName`, `packageName`

This means the full data-lineage graph pattern applies uniformly to shell-script steps, procedure-calling steps, and DB-operation steps — the `Step → DataAsset → Resource` chain works identically for all three execution types.

---

## 8. Phase 3 — MCP Server (BATCH-kg-ui-mcp)

**Repository**: `BATCH-kg-ui-mcp`  
**Port**: 8100  
**Technology**: FastAPI + FastMCP, Python 3.11+

The MCP (Model Context Protocol) Server is the **AI-facing query layer** over the Knowledge Graph. MCP is an open standard developed by Anthropic that defines how AI agents discover and call tools. Any MCP-compatible agent (LangGraph, Claude Desktop, LangChain) can connect to this server and immediately access the full graph query capability.

### Architecture

```
BATCH-kg-ui-mcp/
├── app/
│   ├── services/          # All Cypher logic (independently testable)
│   │   ├── topology_service.py       # Job structure queries
│   │   ├── execution_service.py      # History and failure queries
│   │   ├── performance_service.py    # Duration and health metrics
│   │   ├── dependency_service.py     # Upstream/downstream traversal
│   │   └── schema_service.py         # Schema description for agents
│   └── mcp/
│       ├── tools/                    # Thin MCP wrappers over services
│       └── resources/                # KG schema as an MCP resource
```

The key design principle is **separation of concerns**: MCP tools are deliberately thin — they contain only the MCP registration and parameter validation. All Cypher queries and business logic live in `services/`, making them independently testable without an MCP client.

### MCP Tools

| Tool | Description |
|---|---|
| `get_job_topology` | Full structure of a job: steps, blocks, SLAs, calendars, resources |
| `get_failed_jobs` | Recent failed executions with error messages |
| `get_common_errors` | Most frequent error patterns across the estate |
| `get_job_performance` | Avg/min/max duration metrics for a job |
| `get_slow_jobs` | Jobs exceeding a duration threshold |
| `project_sla_impact` | Predict SLA risk/breach from upstream job/resource delay across dependent SICs |
| `get_execution_timeline` | Daily execution statistics |
| `get_job_execution_history` | Full execution history for a job |
| `get_job_dependency_chain` | Upstream/downstream dependency graph |
| `get_jobgroup_execution_flow` | Topological execution order for a group |
| `execute_cypher_query` | Guarded read-only Cypher execution (allowlisted) |

### MCP Resources

| URI | Description |
|---|---|
| `kg://schema` | Full KG schema with node types, properties, relationship types, and example patterns |

Providing the schema as an MCP resource means the agent can load the schema into context before generating a Cypher query — dramatically reducing hallucination of non-existent properties or relationship types.

---

## 9. Phase 4 — Agentic Backend (BATCH-KG-BE)

**Repository**: `BATCH-KG-BE`  
**Port**: 8001  
**Technology**: FastAPI, LangGraph 0.2+, multi-LLM factory

This is the *intelligence layer* — where user questions become graph queries and graph results become English answers.

### Multi-Agent Architecture

The backend implements a five-agent **LangGraph directed graph**:

```
START
  └─► Planner
        └─► ExecutorRouter
              ├─► DirectToolExecutor ──► CheckNext
              └─► CypherExecutor     ──► CheckNext
                                         ├─► ExecutorRouter (loop)
                                         └─► Summariser ──► END
```

**Agent Responsibilities**:

| Agent | Role |
|---|---|
| **Planner** | Receives user question + available tools + KG schema. Decomposes the question into a typed execution plan: each step is either a `direct_tool` call or a `cypher_query` |
| **SchemaAnalyzer** | Extracts the relevant subset of the KG schema before Cypher generation, preventing token waste |
| **CypherGenerator** | Converts a natural-language sub-task into a parameterised Cypher query using the schema subset. Returns query + parameters |
| **ToolExecutor** | Calls MCP tools or executes generated Cypher queries against the knowledge graph |
| **Summariser** | Receives all step results and synthesises them into a coherent, accurate, natural-language answer |

### Streaming Architecture

All responses are available in two modes:

- **Blocking** (`POST /api/v1/chat`): Full answer returned as a single JSON response
- **Streaming** (`POST /api/v1/chat/stream`): SSE stream of typed `AgentEvent` frames:

```
data: {"type":"plan_generated","plan":{...},"total_steps":3}
data: {"type":"step_started","step_number":1,"step_description":"Fetch critical path..."}
data: {"type":"step_completed","step_number":1,"success":true}
data: {"type":"done","answer":"The critical path runs through..."}
data: [DONE]
```

The SSE design means the user sees the agent's reasoning process in real time, building trust and transparency. A user can watch the planner decompose the question, see each tool call execute, and receive the answer with full provenance.

### Multi-LLM Support

The backend supports four LLM providers through a common factory interface:

| Provider | Implementation |
|---|---|
| OpenAI | GPT-4o, GPT-4-turbo |
| Azure OpenAI | Enterprise-grade, data residency |
| AWS Bedrock | Anthropic Claude 3.5 Sonnet, full AWS ecosystem |
| Google Gemini | Gemini 1.5 Pro/Flash |

This means the platform is **cloud-portable**. A customer who cannot send data to OpenAI because of data residency requirements can use AWS Bedrock. A customer on Azure can use Azure OpenAI with enterprise security controls.

### Session Management

The backend maintains per-session conversation memory via LangGraph's `MemorySaver` checkpointer. Each session has a `thread_id` and the graph state (including all previous question/answer pairs) is preserved across turns. A user can ask a follow-up question without re-stating context:

> "Show me the critical path for last night's batch." → *[answer]*  
> "Now compare that to the previous 5 runs."

The second question is answered in the context of the first.

---

## 10. Phase 5 — Chat Frontend (BATCH-KG-FE)

**Repository**: `BATCH-KG-FE`  
**Port**: 3000  
**Technology**: React 18, TypeScript 5, Zustand, Vite

The frontend is a clean, professional chat UI purpose-built for the Spring Batch intelligence agent.

### Key Components

| Component | Purpose |
|---|---|
| `ChatWindow` | Message thread with Markdown rendering |
| `MessageBubble` | Per-message display with role styling |
| `ExecutionLog` | Collapsible step-by-step agent reasoning trace |
| `Sidebar → McpConfig` | MCP server URL configuration |
| `Sidebar → LlmConfig` | LLM provider selection with connection status |
| `Sidebar → ToolsList` | Live list of available MCP tools |

### Design Principles

- **Transparency**: The `ExecutionLog` panel shows every step the agent took — which tool it called, what it queried, and how confident it was. This is critical for enterprise users who need to trust and verify AI answers.
- **Streaming by default**: Real-time step feedback via SSE so the user is never staring at a spinner for a long-running query
- **Never speaks directly to MCP or Neo4j**: All graph communication is proxied through the backend, maintaining security boundaries
- **Dark-theme design tokens**: Consistent, professional appearance aligned with operations/monitoring tooling aesthetics

---

## 11. End-to-End Data Flow

```
1. User types: "What is the critical path for yesterday's EOD batch?"
   └── BATCH-KG-FE sends POST /api/v1/chat/stream to BATCH-KG-BE

2. BATCH-KG-BE Planner:
   ├── Loads KG schema from MCP resource kg://schema
   ├── Identifies the question needs: execution run ID, critical path data
   └── Creates plan:
       Step 1: get_job_execution_history (find last EOD run ID)
       Step 2: execute_cypher with Q16 (critical path for that run ID)
       Step 3: execute_cypher for SLA config comparison

3. BATCH-KG-BE → BATCH-kg-ui-mcp → Neo4j (Knowledge Graph)
   ├── Tool call: get_job_execution_history → returns last run ID
   ├── Cypher execute: Q16 → CriticalPathCalculated + CriticalPathInstances
   └── Cypher execute: SLA data for this JobGroup

4. BATCH-KG-BE Summariser:
   └── Synthesises: "Last night's EOD batch completed in 4h 23m.
       The critical path runs through: DataLoad → Transform → Reconcile.
       DataLoad had the most slack (12 min). Reconcile had zero slack
       and ran 8% longer than its 90-day average, which is why the
       4:00 AM SLA was breached by 4 minutes."

5. BATCH-KG-FE renders:
   ├── Final answer (Markdown formatted)
   └── ExecutionLog (3 steps, all green, tool names and results)
```

---

## 12. Use Cases — PoC Demo Scope & Query Capabilities

The platform's use case coverage exists at two distinct levels.

**Level 1 — PoC Priority Demo Scenarios** are the five high-value operational situations that form the core of the proof-of-concept demonstration. They represent the most visible, highest-impact problems that batch operations teams face in production. Each scenario requires the full depth of the platform — graph traversal, execution history, CPM analysis, resource tracking, and multi-hop conversational reasoning — to answer correctly. These are the use cases the conversational AI agent and chat UI (Phases 3–5) are specifically being built to handle, and they define the primary success criteria of the PoC.

**Level 2 — Foundation Query Library** covers 17+ routine operational query patterns that the Knowledge Graph can answer immediately once the data is loaded. These are structured, deterministic queries that can be surfaced as upfront search screens, list views, or graph visualisations within the UI. They do not require the AI agent and can be made available as navigation and exploration tools from day one. The AI agent also draws on this library when decomposing complex multi-step questions.

---

### Part 1 — PoC Priority Demo Scenarios

These five scenarios define the first phase of the PoC demonstration. Each has been selected because it represents a real, recurring operational problem that no existing tool can reliably answer today, and because answering it correctly requires connecting scheduling data, execution history, resource dependencies, SLA constraints, and code-level knowledge in a single conversational query.

#### Scenario 1 — Data Dependency Impact: Out-of-Order Job Execution

| | |
|---|---|
| **Trigger** | The *Population CDW (Central Data Warehouse)* job fails or does not run on a given business date |
| **Problem** | Dependent child jobs still execute as scheduled and process stale data from the previous successful run. Business users receive incorrect or outdated metrics with no obvious job failure to alert them. |
| **Questions to answer** | "Which jobs are downstream of Population CDW and would have consumed stale data today?" |
| | "Has Population CDW run successfully today? If not, which dependent jobs have already executed?" |
| | "Show me the full downstream dependency chain from Population CDW." *(Graphlet)* |
| **KG capabilities** | `ScheduleInstanceContext -[:PRECEDES]->` graph traversal, `JobContextExecution` status lookup by business date, `ResourceAvailabilityEvent` correlation |

#### Scenario 2 — Calendar / Holiday Dependency: Jobs That Should Not Have Run

| | |
|---|---|
| **Trigger** | A manual trigger file is placed on a configured holiday date (e.g. 25th Dec, 1st Jan) |
| **Problem** | Jobs configured not to execute on holidays still run due to the manual trigger, bypassing their calendar constraint. When regular processing resumes on the next business day, BD runs are impacted: data is partially loaded, cut-off assumptions break, and sequence integrity is violated. |
| **Questions to answer** | "Which jobs are configured with a 'do not run on holiday' calendar constraint?" |
| | "Did any holiday-restricted job execute on [date], and what triggered it?" |
| | "What is the downstream impact of the unexpected run on [date]?" |
| **KG capabilities** | `(ScheduleInstanceContext)-[:DENIES]->(BusinessCalendar)-[:USES_PATTERN]->(CalendarPattern)` with HOLIDAY evaluator, `JobContextExecution` lookup by `businessDate` cross-referenced against deny rules |

#### Scenario 3 — Long-Running Jobs: SLA Breach and Cascade Impact

| | |
|---|---|
| **Trigger** | A job starts within its expected window but runs significantly longer than its historical average, breaching its SLA |
| **Problem** | Downstream dependent jobs are delayed, potentially cascading SLA breaches across the pipeline. The breach may not be noticed until business users report late data — by which point multiple downstream systems are already impacted. |
| **Questions to answer** | "Which jobs in tonight's run are currently running longer than their 90-day average?" |
| | "For job group X tonight, which jobs have breached SLA? Which downstream jobs are now at risk?" |
| | "What is the critical path for tonight's run, and which critical-path job is furthest behind its baseline?" *(CPM Graphlet)* |
| | "If job Y runs 20% longer than usual, does the group SLA breach? By how much?" |
| **KG capabilities** | `CriticalPathInstance` slack values, `JobContextExecution` duration vs historical averages, `SLA` node constraints, CPM forward/backward pass results |

#### Scenario 4 — Upstream File Delay: Input Arrival Impact

| | |
|---|---|
| **Trigger** | An upstream input file arrives later than its expected cut-off time |
| **Problem** | Dependent jobs are delayed or execute with incomplete data, delaying downstream data delivery. No existing tool connects "this file is late" directly to "these jobs are waiting" and "these downstream consumers will be impacted by this many minutes". |
| **Questions to answer** | "Which jobs depend on file X arriving before [cut-off time]?" |
| | "File X arrived 45 minutes late today — which jobs were delayed and by how much?" |
| | "What is the blast radius of a 1-hour delay on [upstream file]?" *(Graphlet: `ResourceAvailabilityEvent -[:IMPACTED]->`)* |
| | "Which upstream files have caused the most SLA breaches in the last 30 days?" |
| **KG capabilities** | `Resource -[:Require_Resource]-> ScheduleInstanceContext`, `ResourceAvailabilityEvent -[:IMPACTED]-> JobContextExecution`, file arrival time vs expected start time delta |

#### Scenario 5 — SQL Performance Degradation: Query Long-Running Impact

| | |
|---|---|
| **Trigger** | A job slows down because a specific SQL query it executes is running significantly longer than its historical average |
| **Problem** | The degradation may be caused by data volume growth, a missing index, or an execution plan change. Job monitoring shows the job is slow but no tool connects "job X is slow" → "SQL query Z is the cause" → "this query historically ran in 2ms but tonight it runs in 45ms". |
| **Questions to answer** | "Which jobs contain SQL operations running longer than their historical best or average?" |
| | "For job X, which SQL operations have shown the most significant performance degradation in the last 30 days?" |
| | "Which DB operations in tonight's run are the most likely performance bottlenecks based on historical comparison?" |
| **KG capabilities** | Step-level `dbOperations` and `dbOperationCount` from the IG, `JobContextExecution` duration metrics, historical performance comparison across `CriticalPathInstance` data |

---

### Part 2 — Foundation Query Library

Beyond the five priority scenarios, the Knowledge Graph supports a broad library of 17+ operational query patterns available immediately once the graph is loaded. These can be surfaced as search screens, list views, or graph visualisations in the UI without requiring the full conversational AI pipeline. The AI agent also draws on this library when decomposing complex multi-step questions into sub-queries.

### 12.1 System Overview
- "How many jobs, steps, and resources are in the system?"
- "List all job groups and their job counts."
- "Find all jobs related to 'funding'."

### 12.2 Job and Job Group Details
- "Tell me everything about job group X: jobs, SLAs, resources, calendars, tags."
- "What does job Y contain: steps, their kinds, DB operation counts, listeners?"

### 12.3 Execution Flow Visualisation
- "Show me the internal step execution flow of job X as a graph." *(Graphlet)*
- "Show me the execution order of jobs in group X." *(Graphlet)*
- "What jobs run before and after job Y in every group it belongs to?" *(Graphlet with UPSTREAM/DOWNSTREAM tagging)*

### 12.4 Java Code Lineage
- "Show me the Java call hierarchy behind step X in job Y." *(Graphlet with CALLS depth 3)*
- "What database operations does job X perform at the step level?"
- "Which Job call stored procedures X?"
- "Which dynamic jobs execute shell script X, and what parameters do they pass?"
- "What stored procedures do dynamic batch jobs call, and which schema or package do they belong to?"

### 12.5 Resource & Data Lineage
- "What data does job X read and write?"
- "What is the blast radius if TABLE_Y is unavailable?" *(Graphlet showing all impacted JobGroups, Jobs, SICs)*
- "Which jobs and steps are impacted if shell script X is unavailable?" *(Blast radius extended to SHELL_SCRIPT resources)*
- "Which dynamic jobs produce output to file directory DIR_Z?"

### 12.6 Execution History & Health
- "Show me the last 10 runs of job group X with per-job status."
- "What is the success rate and average duration of each job in group X over 90 days?"

### 12.7 SLA & Critical Path
- "What are the SLA requirements for job group X?"
- "Show me the critical path for execution run ID R, with slack values per job." *(CPM Graphlet)*
- "Has tonight's critical path changed from the most common historical pattern?"
- "If upstream resource R (or job J) is delayed by 20 minutes, which dependent SICs are at risk of SLA breach?"

### 12.8 Additional Code-Level Queries (sample_cypher_queries.cypher)
- "Visualise the full call hierarchy for all methods in job X up to 4 hops deep."
- "Find all Java methods in job X with DB operations that have no Resource association." *(Gap analysis)*
- "Which methods perform DELETE operations across the whole estate?"

---

## 13. Technology Stack

| Layer | Technology | Purpose |
|---|---|---|
| Graph Database | Neo4j 5.x (2 databases: IG + KG) | Source-of-truth graph storage |
| IG Builder | Python 3.11+, TreeSitter, ElementTree | XML + Java parsing |
| Enrichers | Python, regex, AWS Bedrock / OpenAI | Operation extraction |
| KG Loaders | Python, neo4j driver, pandas | Structured graph loading |
| CPM Engine | Python (pure algorithm, no library) | Critical path computation |
| VS Code Extension | TypeScript, VS Code API | Human gap-fill workflow |
| Extension API | FastAPI, async neo4j driver | Extension backend |
| MCP Server | FastAPI, FastMCP, SSE | AI-facing query layer |
| Agent Backend | FastAPI, LangGraph 0.2+, Pydantic v2 | Multi-agent orchestration |
| LLM Abstraction | Custom factory (OpenAI/Azure/Bedrock/Gemini) | Cloud-portable LLM |
| Frontend | React 18, TypeScript 5, Zustand, Vite | Chat UI |
| Configuration | YAML, .env, Pydantic Settings | Environment-driven config |
| Logging | Python logging (JSON in prod) | Structured, ELK-compatible |
| Security | X-API-Key guards, CORS, read-only Cypher | Boundary protection |

---

## 14. Competitive Differentiation

### What Makes This Different From:

**Traditional monitoring tools (Grafana, Kibana)**:
- Monitoring tools show metrics and logs. They cannot answer "which DAO method caused this failure" or "what tables does this job write to". They have no understanding of the code structure.

**API management / discovery tools**:
- These track service-to-service communication. Spring Batch is an internal processing platform; jobs don't expose APIs. No existing tool models the Job → Step → Java → DB chain.

**Generic AI coding assistants (GitHub Copilot)**:
- These assist individual developers writing new code. They cannot answer operational questions about a running estate because they have no execution history, no SLA data, no scheduling graph, and no live graph traversal capability.

**Process mining tools**:
- Process mining analyses event logs to discover process models. It operates on execution traces, not source code. It cannot answer "what Java code is on the critical path" or "which table should I put an index on to speed up tonight's batch".

**Data lineage tools (Atlan, Collibra)**:
- These track data lineage at the dataset level (table to table). They do not model the job execution sequence, the critical path, or the Java call hierarchy that determines *how* data moves between tables.

### The Unique Value

This platform is the **only solution that connects**:
- The scheduling graph (what runs when, in what order)
- The code graph (what Java runs each step)
- The data graph (what tables/files/procedures each step touches)
- The execution graph (what actually happened, how long it took)
- The constraint graph (what SLAs and calendars govern each job)
- The critical path (which jobs are on the bottleneck path)

...and makes all of that instantly queryable in plain English.

---

## 15. Customer Value Proposition

### Incident Resolution
**Before**: P1 batch incident takes 2–8 hours to triage. Engineers manually trace from monitoring alert → job name → step name → Java code → DAO → SQL → DBA.  
**After**: "Which step failed, what SQL was it running, and what table is affected?" answered in 30 seconds.

**Estimated ROI**: 10 P1 incidents/year × 5 hours saved × £100/hr loaded cost = **£5,000/year** per application. Enterprise customers have 50+ applications.

### SLA Management
**Before**: SLA breaches are discovered by the business at 7 AM. Post-mortems take a day.  
**After**: "Is tonight's batch on track? What is the current critical path and does any job have negative slack?" — real-time, at any hour.

**Business value**: SLA breach prevention, regulatory compliance, reduced reputational risk.

### Change Impact Analysis
**Before**: "If I change the shared CustomerDAO, will anything break?" — no reliable answer. Engineers either don't change it or spend days tracing manually.  
**After**: "Which jobs call CustomerDAO.findAll()?" answered instantly with full blast-radius graph.

### Knowledge Preservation
**Before**: Senior engineers leave; their knowledge leaves with them. New hires take 3–6 months to become productive.  
**After**: The graph is the institutional knowledge. New hires can ask the agent and explore the graph. Onboarding time in batch operations can be reduced from months to weeks.

### Capacity Planning
The platform's performance statistics and critical path analysis enable data-driven capacity planning:
- "Which jobs consistently exceed their SLA window by more than 5%?"
- "What is the 95th percentile duration for the EOD batch group?"
- "If Job X runs 20% longer than usual, will the SLA breach?"

---

## 16. Roadmap & Extensibility

The architecture is explicitly designed for extensibility at every layer.

### Near-Term Additions

| Enhancement | Engineering Effort |
|---|---|
| Incremental graph updates (delta processing from git diff) | Medium — IG already captures git metadata per node |
| PERT probability distributions on critical path | Low — CPM engine is already pluggable |
| Anomaly detection alerts (job running >2σ longer than baseline) | Medium — execution data already loaded |
| Predictive SLA breach warning | Medium — time-series analysis on top of execution graph |
| Multi-repository, multi-team support | Low — architecture already partitions by repo |

### Longer-Term Extensions

| Extension | Value |
|---|---|
| Support for other batch frameworks (Quartz, Apache Camel) | Broadens addressable market |
| Python batch support (Airflow DAGs) | Extends to data engineering teams |
| Integration with CI/CD pipeline (auto-update graph on PR merge) | Continuous, fresh graph |
| Compliance reporting (who changed what, when, what was the impact) | Regulated industries |
| Capacity and cost modelling (cloud batch costs per job) | FinOps integration |

### Pluggable LLM Architecture

The `BaseLLM` factory in `BATCH-KG-BE` accepts any provider. Adding a new LLM (e.g., a customer's privately hosted model) is a single new implementation of `BaseLLM` with no changes to agent logic, tools, or frontend. This makes the platform model-agnostic and future-proof.

### Pluggable Enrichers

The enricher architecture (separate scripts per operation type, YAML rule configuration) means adding a new analysis type (e.g., a Redis cache operation enricher, or a Kafka topic enricher) is adding one new script and one YAML file. The existing graph and KG loading infrastructure do not change.

---

## Appendix A — Project Repository Map

| Repository | Technology | Role |
|---|---|---|
| `Batch_KG` | Python | IG builder, enrichers, KG loaders, CPM engine |
| `batch-ig-vscode-extension` | TypeScript (VS Code) | Gap analyzer UI |
| `Batch-IG-Extension-APIs` | Python (FastAPI) | Extension API layer |
| `BATCH-kg-ui-mcp` | Python (FastAPI + FastMCP) | MCP server |
| `BATCH-KG-BE` | Python (FastAPI + LangGraph) | Agent backend |
| `BATCH-KG-FE` | TypeScript (React + Vite) | Chat frontend |

---

## Appendix B — Key Design Principles

1. **Source never mutated**: The IG and KG construction processes are read-only with respect to source systems. Nothing modifies the Java code, XML files, or database.

2. **Incremental enrichment**: The two-phase design (graph structure first, then enrichers) means analysis can be re-run without rebuilding the graph. A new LLM can be used to re-analyse only the DAO methods where the old analysis had low confidence.

3. **Confidence-aware**: Every automatically derived fact carries a confidence level. Low-confidence facts are surfaced as gaps for human review. The graph distinguishes between facts derived from code analysis, facts from human review, and facts from manual configuration.

4. **AI is a consumer, not the owner**: LLMs translate questions into graph queries and synthesise results into text. They do not own or mutate the graph. The graph is the ground truth. This prevents hallucination from corrupting the knowledge base.

5. **MCP as the AI contract boundary**: All agent-to-graph communication is mediated by the MCP server. This means tools are precisely defined, discoverable, documented, and testable. An agent cannot do anything that is not in the tool set. This is a security and reliability boundary.

6. **Human-in-the-loop by design**: The Gap Analyzer extension is not an afterthought; it is a first-class component. The system acknowledges that automated analysis has limits and provides a structured, low-friction workflow for human expertise to fill those limits.

---

*This document describes a complete, working system designed and implemented as a proof-of-concept / pilot platform. All architectural decisions have been validated through working code. The system is ready for demonstration, piloting on a customer codebase, and productionisation.*
