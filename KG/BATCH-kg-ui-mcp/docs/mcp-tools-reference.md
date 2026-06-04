# MCP Tools Reference

This document lists all MCP tools available in the BATCH Knowledge Graph MCP server, along with brief descriptions and sample queries for each tool.

---

## Table of Contents

1. [Graph Visualization](#graph-visualization)
   - [get_entity_graph](#get_entity_graph)
   - [expand_node](#expand_node)
   - [get_job_graph_for_date](#get_job_graph_for_date)
2. [Job Topology](#job-topology)
   - [get_job_topology](#get_job_topology)
3. [Dependency Chains & Execution Flow](#dependency-chains--execution-flow)
   - [get_job_dependency_chain](#get_job_dependency_chain)
   - [get_jobgroup_execution_flow](#get_jobgroup_execution_flow)
   - [get_job_step_flow](#get_job_step_flow)
4. [Execution History & Monitoring](#execution-history--monitoring)
   - [get_failed_jobs](#get_failed_jobs)
   - [get_job_execution_history](#get_job_execution_history)
5. [Performance Analysis](#performance-analysis)
   - [get_job_performance](#get_job_performance)
   - [get_sla_execution_breach](#get_sla_execution_breach)
   - [predict_sla_impact](#predict_sla_impact)
   - [get_job_execution_analysis](#get_job_execution_analysis)
6. [Anomaly Detection](#anomaly-detection)
   - [detect_calendar_anomalies](#detect_calendar_anomalies)
7. [Custom Cypher Query](#custom-cypher-query)
   - [execute_cypher_query](#execute_cypher_query)

---

## Graph Visualization

### `get_entity_graph`

Returns a 1-hop subgraph centred on any Knowledge Graph entity (Job, Step, JobGroup, etc.) — useful for visualising a node and its immediate relationships.

**Sample Queries**
1. *"Show me the graph for the job named `EOD_SETTLEMENT_JOB`."*
2. *"What nodes are directly connected to the JobGroup `ASIA_BATCH_GROUP`?"*
3. *"Give me the entity graph for the step with id `step-001` so I can see its relationships."*

---

### `expand_node`

Returns immediate neighbours of a node that are not already rendered on the graph — used for progressive, click-driven graph exploration.

**Sample Queries**
1. *"I clicked on node `job-789` in the graph; expand it to show its neighbours."*
2. *"Expand node `sic-4421`, but skip nodes `sic-4400` and `sic-4390` which I already see."*
3. *"Reveal the connections around `step-block-12` without duplicating what is already on screen."*

---

### `get_job_graph_for_date`

Generates a date-aware job graph showing which ScheduleInstanceContext nodes were planned and/or actually ran on a given business date, filtered by region and optional JobGroup.

**Sample Queries**
1. *"Show me the job execution graph for 2026-06-02 in the US region."*
2. *"Which jobs were scheduled to run in the UK on 2026-12-25 (a holiday)?"*
3. *"Give me the planned vs actual graph for JobGroup `EMEA_NIGHTLY` on 2026-05-30."*

---

## Job Topology

### `get_job_topology`

Retrieves the full structural definition of a Job — including its steps, blocks, SLA constraints, business calendar allow/deny rules, required resources, listeners, tags, and schedule contexts.

**Sample Queries**
1. *"What is the internal structure of the job `TRADE_RECONCILIATION_JOB`?"*
2. *"Show me the SLA rules and calendar constraints attached to `RISK_CALCULATION_JOB`."*
3. *"List all steps, blocks, and required resources for `PORTFOLIO_VALUATION_JOB`."*

---

## Dependency Chains & Execution Flow

### `get_job_dependency_chain`

Returns the upstream and downstream dependency graphlet for a Job across all its JobGroups, showing which jobs must complete before it and which jobs depend on its completion.

**Sample Queries**
1. *"What jobs does `SETTLEMENT_JOB` depend on, and which jobs depend on it?"*
2. *"Show me the full upstream chain for `RISK_AGGREGATION_JOB`."*
3. *"If `MARKET_DATA_LOADER` fails, which downstream jobs in all its groups will be blocked?"*

---

### `get_jobgroup_execution_flow`

Returns the execution-flow graphlet for an entire JobGroup, traversing the PRECEDES chain from the ENTRY node and ordering every job by its minimum distance from the entry point.

**Sample Queries**
1. *"What is the full execution order of jobs in JobGroup `EMEA_NIGHTLY_BATCH`?"*
2. *"Show me the flow graph for JobGroup id `jg-0042` so I can see wave-by-wave execution."*
3. *"How many jobs run in parallel in the first wave of `US_EOD_GROUP`?"*

---

### `get_job_step_flow`

Returns the internal step-flow graphlet for a Job, traversing Step, Decision, and Block nodes from the ENTRY point and summarising node counts per type.

**Sample Queries**
1. *"Walk me through every step and decision node inside `CASH_POSITION_JOB`."*
2. *"How many steps and decision branches does `COLLATERAL_CALC_JOB` have?"*
3. *"Show the internal flow of `NOSTRO_RECONCILIATION_JOB` including all block nodes."*

---

## Execution History & Monitoring

### `get_failed_jobs`

Retrieves jobs that failed within a configurable look-back window, returning the job name, error details, and failure count.

**Sample Queries**
1. *"Which jobs have failed in the last 7 days?"*
2. *"Show me all failures from the past 24 hours."*
3. *"List the top 5 most recently failed jobs over the last 14 days."*

---

### `get_job_execution_history`

Returns the complete execution history for a specific job — status, duration, and business date — over a configurable time window.

**Sample Queries**
1. *"Give me the last 30 days of execution history for `EOD_SETTLEMENT_JOB`."*
2. *"How many times has `RISK_CALC_JOB` failed versus succeeded in the past 2 weeks?"*
3. *"Show every execution of `PORTFOLIO_VALUATION_JOB` since the start of the month."*

---

## Performance Analysis

### `get_job_performance`

Retrieves aggregate performance metrics (avg/min/max duration, success/failure counts) and a linear-regression trend analysis for a specific job over a configurable number of days.

**Sample Queries**
1. *"Is `MARKET_DATA_LOADER` getting slower over the last 60 days?"*
2. *"What is the average and maximum execution time of `SETTLEMENT_JOB` for the past 30 days?"*
3. *"Show me the performance trend for `RISK_AGGREGATION_JOB` — is it deteriorating or improving?"*

---

### `get_sla_execution_breach`

Returns SLA breach status and duration anomaly flags for all jobs on a given business date, based on actual execution history and defined SLA thresholds.

**Sample Queries**
1. *"Were any SLAs breached on 2026-06-02?"*
2. *"Show me the SLA breach report for the US region on 2026-05-31."*
3. *"Which jobs exceeded their SLA targets on last Friday?"*

---

### `predict_sla_impact`

Simulates a delay on a specific resource, job, or job group and predicts downstream SLA impact — identifying critical-path jobs at risk and buffer margins.

**Sample Queries**
1. *"If `MARKET_DATA_LOADER` is delayed by 30 minutes, which SLAs will be at risk?"*
2. *"Predict the SLA impact of a 60-minute delay on resource `SHARED_DB_CONNECTION`."*
3. *"What happens to downstream SLAs if JobGroup `ASIA_BATCH_GROUP` starts 45 minutes late on 2026-06-05?"*

---

### `get_job_execution_analysis`

Provides a comprehensive, unified view of job execution for a past or current business date — combining execution hierarchy, actual durations, SLA breach status, and duration anomaly detection in a single call.

**Sample Queries**
1. *"Give me a full execution analysis for 2026-06-01 in the US region."*
2. *"Which jobs ran significantly longer than expected on 2026-05-29 for the EMEA region?"*
3. *"Show me the complete execution breakdown for JobGroup `EOD_BATCH` on today's date, including any SLA breaches."*

---

## Anomaly Detection

### `detect_calendar_anomalies`

Detects calendar-based execution anomalies — jobs that ran when they should not have (e.g., on a public holiday) or were missed when they should have run — and computes the cascading impact on downstream jobs.

**Sample Queries**
1. *"Were there any wrong job executions in the US on 2026-05-25 (Memorial Day)?"*
2. *"Detect calendar anomalies for the UK region on 2026-04-18 (Good Friday)."*
3. *"Which jobs were missed or incorrectly executed globally on 2026-01-01, and what was the downstream impact?"*

---

## Custom Cypher Query

### `execute_cypher_query`

Executes an arbitrary read-only Cypher query directly against the Knowledge Graph. Only `MATCH`/`CALL`/`RETURN` operations are permitted; all write and administration queries are blocked for safety.

**Sample Queries**
1. *"Run this Cypher: `MATCH (j:Job)-[:HAS_STEP]->(s:Step) WHERE j.name = 'EOD_SETTLEMENT_JOB' RETURN s.name, s.type`"*
2. *"Find all JobGroups containing more than 10 jobs: `MATCH (jg:JobGroup)<-[:BELONGS_TO]-(j:Job) WITH jg, count(j) AS jobCount WHERE jobCount > 10 RETURN jg.name, jobCount ORDER BY jobCount DESC`"*
3. *"List all SLA rules with a threshold below 60 minutes: `MATCH (s:SLA) WHERE s.threshold_minutes < 60 RETURN s.name, s.threshold_minutes ORDER BY s.threshold_minutes`"*

---

> **Note:** Tools whose registration is commented out in the source (`get_slow_jobs`, `compare_jobs`, `get_common_errors`, `get_execution_timeline`, `get_all_active_jobs`) are currently disabled and not exposed via MCP. Contact the platform team to enable them if needed.
