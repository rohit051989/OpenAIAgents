// =============================================================================
// KG MCP QUERIES — Spring Batch Knowledge Graph
// =============================================================================
//
// Purpose : Curated query library for MCP tool operations & UI visualization
// Schema  : See Latest_KG_Schema.txt
// Database: KG  (database_kg in config/information_graph_config.yaml)
//
// Legend
//   [JSON]     — Returns structured JSON only; designed for LLM agent / MCP use
//   [GRAPHLET] — Returns {nodes, links} map + JSON summary for custom UI rendering
//                For quick Neo4j Browser visualization, run the embedded browser hint
//
// All parameters use $camelCase  (e.g. $jobName, $jobGroupName, $resourceName)
// =============================================================================


// ─────────────────────────────────────────────────────────────────────────────
// SECTION 1 : SYSTEM OVERVIEW
// ─────────────────────────────────────────────────────────────────────────────

// Q01 [JSON] — KG Node Statistics
// Returns a count of every node type present in the Knowledge Graph.
// MCP use : "how many jobs/steps/resources are loaded in the KG?"
// ─────────────────────────────────────────────────────────────────────────────
MATCH (n)
WITH labels(n)[0] AS nodeType, count(n) AS cnt
WHERE nodeType IS NOT NULL
ORDER BY cnt DESC
RETURN collect({ type: nodeType, count: cnt }) AS kgStats;


// Q02 [JSON] — List All Job Groups
// Returns all JobGroup nodes with job count and job name list.
// MCP use : "what job groups exist in the system?"
// ─────────────────────────────────────────────────────────────────────────────
MATCH (jg:JobGroup)
OPTIONAL MATCH (jg)-[:HAS_JOB]->(j:Job)
WITH jg, count(j) AS jobCount, collect(j.name) AS jobNames
ORDER BY jg.name
RETURN collect({
  id          : jg.id,
  name        : jg.name,
  description : jg.description,
  enabled     : jg.enabled,
  priority    : jg.priority,
  jobCount    : jobCount,
  jobs        : jobNames
}) AS jobGroups;


// Q03 [JSON] — Search Jobs by Name Pattern
// Parameter : $namePattern  (case-insensitive substring, e.g. "funding")
// Returns matching Job nodes with their parent JobGroup.
// MCP use : "find all jobs related to X"
// ─────────────────────────────────────────────────────────────────────────────
MATCH (j:Job)
WHERE toLower(j.name) CONTAINS toLower($namePattern)
OPTIONAL MATCH (jg:JobGroup)-[:HAS_JOB]->(j)
WITH j, jg
ORDER BY jg.name, j.name
RETURN collect({
  id          : j.id,
  name        : j.name,
  description : j.description,
  enabled     : j.enabled,
  jobGroup    : jg.name,
  sourceFile  : j.sourceFile,
  gitRepoName : j.gitRepoName
}) AS matchingJobs;


// ─────────────────────────────────────────────────────────────────────────────
// SECTION 2 : JOB GROUP & JOB DETAILS
// ─────────────────────────────────────────────────────────────────────────────

// Q04 [JSON] — Job Group Full Detail
// Parameter : $jobGroupName
// Returns complete details: jobs, SLAs, required resources, calendars, tags.
// MCP use : "tell me everything about job group X"
// ─────────────────────────────────────────────────────────────────────────────
MATCH (jg:JobGroup {name: $jobGroupName})
OPTIONAL MATCH (jg)-[:HAS_JOB]->(j:Job)
OPTIONAL MATCH (jg)-[:HAS_SLA]->(sla:SLA)
OPTIONAL MATCH (jg)-[:Require_Resource]->(r:Resource)
OPTIONAL MATCH (jg)-[:CAN_EXECUTE_ON]->(cal:Calendar)
OPTIONAL MATCH (jg)-[:HAS_TAG]->(t:Tag)
WITH jg,
     collect(DISTINCT { id: j.id,   name: j.name,   enabled: j.enabled,
                        description: j.description }) AS jobs,
     collect(DISTINCT { id: sla.id, name: sla.name, type: sla.type,
                        policy: sla.policy, severity: sla.severity,
                        durationMs: sla.durationMs, time: sla.time,
                        tz: sla.tz }) AS slas,
     collect(DISTINCT { id: r.id,   name: r.name,   type: r.type,
                        schemaName: r.schemaName }) AS resources,
     collect(DISTINCT { id: cal.id, name: cal.name, type: cal.type }) AS calendars,
     collect(DISTINCT { id: t.id,   name: t.name,   tagType: t.tagType }) AS tags
RETURN {
  id               : jg.id,
  name             : jg.name,
  description      : jg.description,
  enabled          : jg.enabled,
  priority         : jg.priority,
  createdAt        : jg.createdAt,
  jobCount         : size(jobs),
  jobs             : jobs,
  slas             : slas,
  requiredResources: resources,
  calendars        : calendars,
  tags             : tags
} AS jobGroupDetail;


// Q05 [JSON] — Job Full Detail
// Parameter : $jobName
// Returns complete job info: steps summary, SLA, resources, listeners, tags, git.
// MCP use : "tell me everything about job X"
// ─────────────────────────────────────────────────────────────────────────────
MATCH (j:Job {name: $jobName})
OPTIONAL MATCH (jg:JobGroup)-[:HAS_JOB]->(j)
OPTIONAL MATCH (j)-[:CONTAINS]->(s:Step)
OPTIONAL MATCH (j)-[:HAS_SLA]->(sla:SLA)
OPTIONAL MATCH (j)-[:Require_Resource]->(r:Resource)
OPTIONAL MATCH (j)-[:HAS_LISTENER]->(l:Listener)
OPTIONAL MATCH (j)-[:HAS_TAG]->(t:Tag)
WITH j, jg,
     collect(DISTINCT {
       name               : s.name,
       stepKind           : s.stepKind,
       className          : s.className,
       readerClass        : s.readerClass,
       writerClass        : s.writerClass,
       processorClass     : s.processorClass,
       dbOperationCount   : coalesce(s.stepDbOperationCount,   0),
       procedureCallCount : coalesce(s.stepProcedureCallCount, 0),
       shellExecutionCount: coalesce(s.stepShellExecutionCount,0)
     }) AS steps,
     collect(DISTINCT { id: sla.id, name: sla.name, type: sla.type,
                        policy: sla.policy, severity: sla.severity,
                        durationMs: sla.durationMs }) AS slas,
     collect(DISTINCT { id: r.id,   name: r.name,   type: r.type,
                        schemaName: r.schemaName }) AS resources,
     collect(DISTINCT { name: l.name, scope: l.scope,
                        implBean: l.impl_bean }) AS listeners,
     collect(DISTINCT { id: t.id, name: t.name, tagType: t.tagType }) AS tags
RETURN {
  id               : j.id,
  name             : j.name,
  description      : j.description,
  enabled          : j.enabled,
  restartable      : j.restartable,
  sourceFile       : j.sourceFile,
  gitRepoName      : j.gitRepoName,
  gitBranchName    : j.gitBranchName,
  gitUpdatedBy     : j.gitUpdatedBy,
  gitUpdatedAt     : j.gitUpdatedAt,
  gitLastCommitId  : j.gitLastCommitId,
  jobGroup         : jg.name,
  stepCount        : size(steps),
  steps            : steps,
  slas             : slas,
  requiredResources: resources,
  listeners        : listeners,
  tags             : tags
} AS jobDetail;


// Q06 [JSON] — Job Steps Summary with Operation Counts
// Parameter : $jobName
// Returns each step with DB / procedure / shell operation counts and class info.
// MCP use : "what does each step in job X do?"
// ─────────────────────────────────────────────────────────────────────────────
MATCH (j:Job {name: $jobName})-[:CONTAINS]->(s:Step)
OPTIONAL MATCH (s)-[:IMPLEMENTED_BY]->(c:JavaClass)
WITH s, c
ORDER BY s.name
RETURN collect({
  name                : s.name,
  stepKind            : s.stepKind,
  implBean            : s.implBean,
  className           : s.className,
  readerClass         : s.readerClass,
  writerClass         : s.writerClass,
  processorClass      : s.processorClass,
  dbOperationCount    : coalesce(s.stepDbOperationCount,   0),
  dbOperations        : s.stepDbOperations,
  procedureCallCount  : coalesce(s.stepProcedureCallCount, 0),
  procedureCalls      : s.stepProcedureCalls,
  shellExecutionCount : coalesce(s.stepShellExecutionCount,0),
  shellExecutions     : s.stepShellExecutions,
  isDAOClass          : c.isDAOClass,
  isShellExecutorClass: c.isShellExecutorClass
}) AS steps;


// ─────────────────────────────────────────────────────────────────────────────
// SECTION 3 : EXECUTION FLOW VISUALIZATION
// ─────────────────────────────────────────────────────────────────────────────

// Q07 [GRAPHLET] — Job Internal Step-Flow Graph
// Parameter : $jobName
// Returns graphlet {nodes, links} of the Step/Decision/Block PRECEDES chain
// plus a JSON summary with node counts.
//
// Neo4j Browser hint (run separately for visual rendering):
//   MATCH (j:Job {name:$jobName})-[:ENTRY]->(entry)
//   MATCH p = (entry)-[:PRECEDES*0..20]->(n)
//   RETURN p LIMIT 100
//
// MCP use : "show me the execution flow of job X"
// ─────────────────────────────────────────────────────────────────────────────
MATCH (j:Job {name: $jobName})-[:ENTRY]->(entry)
MATCH p = (entry)-[:PRECEDES*0..20]->(n)
WITH j, collect(p) AS paths
WITH j,
     reduce(ns = [], pth IN paths | ns + nodes(pth))          AS rawNodes,
     reduce(rs = [], pth IN paths | rs + relationships(pth))  AS rawRels
UNWIND rawNodes AS nd
WITH j, rawRels, collect(DISTINCT nd) AS allNodes
UNWIND rawRels AS rel
WITH j, allNodes, collect(DISTINCT rel) AS allRels
RETURN
  {
    nodes: [n IN allNodes | {
      id       : elementId(n),
      labels   : labels(n),
      name     : coalesce(n.name, ''),
      stepKind : coalesce(n.stepKind, ''),
      blockType: coalesce(n.block_type, '')
    }],
    links: [r IN allRels | {
      source: elementId(startNode(r)),
      target: elementId(endNode(r)),
      on    : coalesce(r.on, 'DEFAULT')
    }]
  } AS graphlet,
  {
    jobName      : j.name,
    nodeCount    : size(allNodes),
    stepCount    : size([n IN allNodes WHERE 'Step'     IN labels(n)]),
    decisionCount: size([n IN allNodes WHERE 'Decision' IN labels(n)]),
    blockCount   : size([n IN allNodes WHERE 'Block'    IN labels(n)])
  } AS flowSummary;


// Q08 [GRAPHLET] — Job Group Execution Sequence (ScheduleInstanceContext Flow)
// Parameter : $jobGroupName
// Returns graphlet of the SIC PRECEDES graph showing job execution order,
// plus a JSON summary mapping each context to its job.
//
// Neo4j Browser hint:
//   MATCH (jg:JobGroup {name:$jobGroupName})-[:ENTRY]->(entry:ScheduleInstanceContext)
//   MATCH p = (entry)-[:PRECEDES*0..30]->(n:ScheduleInstanceContext)
//   RETURN p LIMIT 100
//
// MCP use : "show me the execution order of jobs in group X"
// ─────────────────────────────────────────────────────────────────────────────
MATCH (jg:JobGroup {id: $jobGroupName})-[:ENTRY]->(entry:ScheduleInstanceContext)
MATCH p = (entry)-[:PRECEDES*0..30]->(sic:ScheduleInstanceContext)
WITH jg, collect(p) AS paths, collect(DISTINCT sic) AS allSics
WITH jg, paths, allSics,
     reduce(ns = [], pth IN paths | ns + nodes(pth))          AS rawNodes,
     reduce(rs = [], pth IN paths | rs + relationships(pth))  AS rawRels
UNWIND rawNodes AS nd
WITH jg, allSics, rawRels, collect(DISTINCT nd) AS allNodes
UNWIND rawRels AS rel
WITH jg, allSics, allNodes, collect(DISTINCT rel) AS allRels
OPTIONAL MATCH (sic2:ScheduleInstanceContext)-[:FOR_JOB]->(j:Job)
WHERE sic2 IN allSics
WITH jg, allNodes, allRels,
     collect({ context: sic2.name, job: j.name }) AS contextJobMap
RETURN
  {
    nodes: [n IN allNodes | {
      id     : elementId(n),
      labels : labels(n),
      name   : coalesce(n.name, ''),
      enabled: coalesce(n.enabled, true)
    }],
    links: [r IN allRels | {
      source: elementId(startNode(r)),
      target: elementId(endNode(r)),
      on    : coalesce(r.on, 'DEFAULT')
    }]
  } AS graphlet,
  {
    jobGroupName  : jg.name,
    totalContexts : size(allNodes),
    contextJobMap : contextJobMap
  } AS flowSummary;


// Q17 [GRAPHLET] — Job Execution Context Across All Groups (Upstream + Downstream)
// Parameter : $jobName
// For EVERY JobGroup containing this job, returns the PRECEDES subgraph centred on
// this job's ScheduleInstanceContext, walking both directions:
//   - UPSTREAM   : all SICs that must complete before this job runs
//   - DOWNSTREAM : all SICs that run after this job completes
// Each node carries a 'direction' tag (TARGET / UPSTREAM / DOWNSTREAM) so the UI
// can colour-code the graphlet.  Returns one row per job group.
//
// Neo4j Browser hint (per group):
//   MATCH (sic:ScheduleInstanceContext)-[:FOR_JOB]->(j:Job {name:$jobName})
//   OPTIONAL MATCH up   = ()-[:PRECEDES*1..30]->(sic)
//   OPTIONAL MATCH down = (sic)-[:PRECEDES*1..30]->()
//   RETURN up, down LIMIT 100
//
// MCP use : "what runs before and after job X, in every group it belongs to?"
// ─────────────────────────────────────────────────────────────────────────────
MATCH (j:Job {name: $jobName})
MATCH (targetSic:ScheduleInstanceContext)-[:FOR_JOB]->(j)
MATCH (targetSic)-[:FOR_GROUP]->(jg:JobGroup)

// Step 1 — downstream: SICs reachable FROM targetSic via PRECEDES
OPTIONAL MATCH downPath = (targetSic)-[:PRECEDES*1..30]->(ds:ScheduleInstanceContext)
WITH j, jg, targetSic,
     collect(DISTINCT ds) AS downstreamSics,
     collect(downPath)    AS downPaths

// Step 2 — upstream: SICs that reach TO targetSic via PRECEDES
OPTIONAL MATCH upPath = (us:ScheduleInstanceContext)-[:PRECEDES*1..30]->(targetSic)
WITH j, jg, targetSic, downstreamSics, downPaths,
     collect(DISTINCT us) AS upstreamSics,
     collect(upPath)      AS upPaths

// Step 3 — merge all path nodes and relationships; always include targetSic itself
WITH j, jg, targetSic, downstreamSics, upstreamSics,
     reduce(ns = [], p IN downPaths | ns + nodes(p)) + [targetSic] +
     reduce(ns = [], p IN upPaths   | ns + nodes(p)) AS rawNodes,
     reduce(rs = [], p IN downPaths | rs + relationships(p)) +
     reduce(rs = [], p IN upPaths   | rs + relationships(p)) AS rawRels

UNWIND rawNodes AS nd
WITH j, jg, targetSic, downstreamSics, upstreamSics, rawRels,
     collect(DISTINCT nd) AS allNodes

UNWIND rawRels AS rel
WITH j, jg, targetSic, downstreamSics, upstreamSics, allNodes,
     collect(DISTINCT rel) AS allRels

// Step 4 — enrich each SIC node with job name + direction label while
//           upstreamSics / downstreamSics are still in scope
// Two-pass job resolution: prefer FOR_JOB relationship; fall back to
// contextForEntityId property (which stores the Job.id) for SICs where
// the FOR_JOB edge was not populated.
UNWIND allNodes AS sn
OPTIONAL MATCH (sn)-[:FOR_JOB]->(relJob:Job)
OPTIONAL MATCH (ctxJob:Job {id: sn.contextForEntityId})
WITH j, jg, targetSic, allRels,
     collect({
       sic      : sn,
       jobName  : coalesce(
                    relJob.name,
                    ctxJob.name,
                    CASE WHEN sn.name STARTS WITH 'Context_'
                         THEN substring(sn.name, 8)
                         ELSE '' END
                  ),
       direction: CASE
                    WHEN elementId(sn) = elementId(targetSic) THEN 'TARGET'
                    WHEN sn IN upstreamSics                   THEN 'UPSTREAM'
                    WHEN sn IN downstreamSics                 THEN 'DOWNSTREAM'
                    ELSE 'OTHER'
                  END,
       enabled  : coalesce(sn.enabled, true)
     }) AS enrichedNodes

// Step 5 — derive upstream / downstream job name lists (direction already stamped)
WITH j, jg, targetSic, allRels, enrichedNodes,
     [en IN enrichedNodes WHERE en.direction = 'UPSTREAM'   | en.jobName] AS upstreamJobs,
     [en IN enrichedNodes WHERE en.direction = 'DOWNSTREAM' | en.jobName] AS downstreamJobs

RETURN
  {
    nodes: [en IN enrichedNodes | {
      id       : elementId(en.sic),
      labels   : labels(en.sic),
      name     : coalesce(en.sic.name, ''),
      jobName  : en.jobName,
      direction: en.direction,
      enabled  : en.enabled
    }],
    links: [r IN allRels | {
      source: elementId(startNode(r)),
      target: elementId(endNode(r)),
      on    : coalesce(r.on, 'DEFAULT')
    }]
  } AS graphlet,
  {
    jobName            : j.name,
    jobGroupName       : jg.name,
    targetContext      : targetSic.name,
    totalContexts      : size(enrichedNodes),
    upstreamJobCount   : size(upstreamJobs),
    downstreamJobCount : size(downstreamJobs),
    upstreamJobs       : upstreamJobs,
    downstreamJobs     : downstreamJobs
  } AS flowSummary;


// ─────────────────────────────────────────────────────────────────────────────
// SECTION 4 : JAVA CODE LINEAGE
// ─────────────────────────────────────────────────────────────────────────────

// Q09 [GRAPHLET] — Step Java Call Hierarchy
// Parameters : $jobName, $stepName
// Returns graphlet of JavaClass → JavaMethod → CALLS chain (up to 3 hops)
// plus a JSON summary with method and DB operation counts.
//
// Neo4j Browser hint:
//   MATCH (j:Job {name:$jobName})-[:CONTAINS]->(s:Step {name:$stepName})
//   MATCH (s)-[:IMPLEMENTED_BY]->(c:JavaClass)
//   MATCH p = (c)-[:HAS_METHOD]->(m:JavaMethod)-[:CALLS*0..3]->(mn:JavaMethod)
//   WHERE NOT c.isTestClass
//   RETURN p LIMIT 100
//
// MCP use : "show me the code behind step X in job Y"
// ─────────────────────────────────────────────────────────────────────────────
MATCH (j:Job {name: $jobName})-[:CONTAINS]->(s:Step {name: $stepName})
MATCH (s)-[:IMPLEMENTED_BY]->(c:JavaClass)
WHERE NOT coalesce(c.isTestClass, false)
OPTIONAL MATCH p = (c)-[:HAS_METHOD]->(m:JavaMethod)-[:CALLS*0..3]->(mn:JavaMethod)
WITH j, s, c, collect(p) AS callPaths
WITH j, s, c, callPaths,
     reduce(ns = [], pth IN callPaths | ns + nodes(pth))          AS rawNodes,
     reduce(rs = [], pth IN callPaths | rs + relationships(pth))  AS rawRels
UNWIND rawNodes AS nd
WITH j, s, c, rawRels, collect(DISTINCT nd) AS allNodes
UNWIND rawRels AS rel
WITH j, s, c, allNodes, collect(DISTINCT rel) AS allRels
RETURN
  {
    nodes: [n IN allNodes | {
      id              : elementId(n),
      labels          : labels(n),
      name            : coalesce(n.className, n.methodName, ''),
      fqn             : coalesce(n.fqn, ''),
      dbOperationCount: coalesce(n.dbOperationCount, 0),
      isDAOClass      : coalesce(n.isDAOClass, false)
    }],
    links: [r IN allRels | {
      source: elementId(startNode(r)),
      target: elementId(endNode(r)),
      type  : type(r)
    }]
  } AS graphlet,
  {
    jobName      : j.name,
    stepName     : s.name,
    implClass    : c.fqn,
    isDAOClass   : c.isDAOClass,
    methodCount  : size([n IN allNodes WHERE 'JavaMethod' IN labels(n)]),
    dbMethodCount: size([n IN allNodes WHERE 'JavaMethod' IN labels(n)
                                        AND coalesce(n.dbOperationCount, 0) > 0])
  } AS codeSummary;


// Q10 [JSON] — Step DB / Procedure / Shell Operations Detail
// Parameter : $jobName
// Returns all steps in the job that have at least one operation (DB/proc/shell).
// MCP use : "what database operations does job X perform?"
// ─────────────────────────────────────────────────────────────────────────────
MATCH (j:Job {name: $jobName})-[:CONTAINS]->(s:Step)
WHERE coalesce(s.stepDbOperationCount, 0)
    + coalesce(s.stepProcedureCallCount, 0)
    + coalesce(s.stepShellExecutionCount, 0) > 0
WITH s
ORDER BY s.name
RETURN collect({
  stepName           : s.name,
  stepKind           : s.stepKind,
  dbOperationCount   : coalesce(s.stepDbOperationCount,   0),
  dbOperations       : s.stepDbOperations,
  procedureCallCount : coalesce(s.stepProcedureCallCount, 0),
  procedureCalls     : s.stepProcedureCalls,
  shellExecutionCount: coalesce(s.stepShellExecutionCount,0),
  shellExecutions    : s.stepShellExecutions
}) AS stepOperations;


// ─────────────────────────────────────────────────────────────────────────────
// SECTION 5 : RESOURCE & DATA LINEAGE
// ─────────────────────────────────────────────────────────────────────────────

// Q11 [JSON] — Job Data Footprint
// Parameter : $jobName
// Returns all resources a job requires (job-level + group-level) and step-level
// DB operations with their operation details.
// MCP use : "what data does job X read or write?"
// ─────────────────────────────────────────────────────────────────────────────
MATCH (j:Job {name: $jobName})
OPTIONAL MATCH (jg:JobGroup)-[:HAS_JOB]->(j)
OPTIONAL MATCH (j)-[:Require_Resource]->(rj:Resource)
OPTIONAL MATCH (jg)-[:Require_Resource]->(rg:Resource)
OPTIONAL MATCH (j)-[:CONTAINS]->(s:Step)
  WHERE coalesce(s.stepDbOperationCount, 0) > 0
WITH j,
     collect(DISTINCT { id: rj.id, name: rj.name, type: rj.type,
                        schemaName: rj.schemaName, level: 'JOB' })    AS jobResources,
     collect(DISTINCT { id: rg.id, name: rg.name, type: rg.type,
                        schemaName: rg.schemaName, level: 'GROUP' })   AS groupResources,
     collect(DISTINCT { stepName: s.name, stepKind: s.stepKind,
                        dbOperationCount: coalesce(s.stepDbOperationCount, 0),
                        dbOperations: s.stepDbOperations })             AS stepsWithDbOps
RETURN {
  jobName             : j.name,
  jobResources        : jobResources,
  groupResources      : groupResources,
  stepsWithDbOps      : stepsWithDbOps,
  totalJobResources   : size(jobResources),
  totalGroupResources : size(groupResources),
  totalStepsWithDbOps : size(stepsWithDbOps)
} AS jobDataFootprint;


// Q12 [GRAPHLET] — Resource Dependency Graph (Blast-Radius Analysis)
// Parameter : $resourceName
// Returns graphlet of all nodes that depend on a resource (JobGroups, Jobs, SICs)
// plus a JSON impact summary.
//
// Neo4j Browser hint:
//   MATCH (res:Resource {name:$resourceName})
//   OPTIONAL MATCH (dep)-[:Require_Resource]->(res)
//   RETURN res, dep LIMIT 50
//
// MCP use : "what depends on table X? what is the blast radius if X is unavailable?"
// ─────────────────────────────────────────────────────────────────────────────
MATCH (res:Resource {name: $resourceName})
OPTIONAL MATCH (jg:JobGroup)-[rel1:Require_Resource]->(res)
OPTIONAL MATCH (j:Job)-[rel2:Require_Resource]->(res)
OPTIONAL MATCH (sic:ScheduleInstanceContext)-[rel3:Require_Resource]->(res)
WITH res,
     collect(DISTINCT jg)   AS jobGroups,
     collect(DISTINCT j)    AS jobs,
     collect(DISTINCT sic)  AS sics,
     collect(DISTINCT rel1) AS rels1,
     collect(DISTINCT rel2) AS rels2,
     collect(DISTINCT rel3) AS rels3
WITH res, jobGroups, jobs, sics,
     rels1 + rels2 + rels3             AS allRels,
     [res] + jobGroups + jobs + sics   AS allNodes
RETURN
  {
    nodes: [n IN allNodes | {
      id    : elementId(n),
      labels: labels(n),
      name  : coalesce(n.name, ''),
      kind  : coalesce(n.type, '')
    }],
    links: [rel IN allRels | {
      source: elementId(startNode(rel)),
      target: elementId(endNode(rel)),
      type  : type(rel)
    }]
  } AS graphlet,
  {
    resource         : { id: res.id, name: res.name, type: res.type,
                         schemaName: res.schemaName },
    impactedJobGroups: [jg  IN jobGroups | jg.name],
    impactedJobs     : [j   IN jobs      | j.name],
    impactedContexts : [sic IN sics      | sic.name],
    totalImpacted    : size(jobGroups) + size(jobs) + size(sics)
  } AS impactSummary;


// ─────────────────────────────────────────────────────────────────────────────
// SECTION 6 : EXECUTION HISTORY & HEALTH
// ─────────────────────────────────────────────────────────────────────────────

// Q13 [JSON] — Recent Job Group Executions
// Parameters : $jobGroupName,  $limit  (e.g. 10)
// Returns the last N execution runs with per-job status and duration details.
// MCP use : "show me the recent runs of job group X"
// ─────────────────────────────────────────────────────────────────────────────
MATCH (jge:JobGroupExecution)-[:EXECUTES_JOB_GROUP]->(jg:JobGroup {name: $jobGroupName})
OPTIONAL MATCH (jge)-[:EXECUTES_JOB_CONTEXT]->(jce:JobContextExecution)-[:EXECUTES_JOB]->(j:Job)
WITH jge, collect({
  jobName   : j.name,
  status    : jce.status,
  startTime : jce.startTime,
  endTime   : jce.endTime,
  durationMs: jce.durationMs,
  exitCode  : jce.exitCode,
  retryCount: jce.retryCount
}) AS jobRuns
ORDER BY jge.startTime DESC
LIMIT $limit
RETURN collect({
  execId      : jge.id,
  startTime   : jge.startTime,
  businessDate: jge.businessDate,
  totalJobs   : size(jobRuns),
  jobRuns     : jobRuns
}) AS recentExecutions;


// Q14 [JSON] — Job Group Execution Health Statistics
// Parameter : $jobGroupName
// Returns aggregate stats per job: total runs, success / failure rates,
// average / max / min duration.
// MCP use : "what is the health / reliability of job group X?"
// ─────────────────────────────────────────────────────────────────────────────
MATCH (jge:JobGroupExecution)-[:EXECUTES_JOB_GROUP]->(jg:JobGroup {name: $jobGroupName})
MATCH (jge)-[:EXECUTES_JOB_CONTEXT]->(jce:JobContextExecution)-[:EXECUTES_JOB]->(j:Job)
WITH jg, j.name AS jobName,
     count(jce)                                                                 AS totalRuns,
     sum(CASE WHEN jce.status = 'COMPLETED' THEN 1 ELSE 0 END)                 AS completed,
     sum(CASE WHEN jce.status = 'FAILED'    THEN 1 ELSE 0 END)                 AS failed,
     round(avg(coalesce(jce.durationMs, 0)))                                   AS avgDurationMs,
     max(coalesce(jce.durationMs, 0))                                          AS maxDurationMs,
     min(CASE WHEN jce.durationMs IS NOT NULL THEN jce.durationMs END)         AS minDurationMs
ORDER BY jobName
WITH jg.name AS groupName,
     collect({
       jobName      : jobName,
       totalRuns    : totalRuns,
       completed    : completed,
       failed       : failed,
       successRate  : CASE WHEN totalRuns > 0
                           THEN round(toFloat(completed) / totalRuns * 1000) / 10
                           ELSE 0.0 END,
       avgDurationMs: avgDurationMs,
       maxDurationMs: maxDurationMs,
       minDurationMs: minDurationMs
     }) AS byJob
RETURN {
  jobGroupName: groupName,
  byJob       : byJob
} AS healthStats;


// ─────────────────────────────────────────────────────────────────────────────
// SECTION 7 : SLA & CRITICAL PATH
// ─────────────────────────────────────────────────────────────────────────────

// Q15 [JSON] — SLA Configuration for a Job Group
// Parameter : $jobGroupName
// Returns group-level and job-level SLA definitions with resource linkages.
// MCP use : "what are the SLA requirements for job group X?"
// ─────────────────────────────────────────────────────────────────────────────
MATCH (jg:JobGroup {name: $jobGroupName})
OPTIONAL MATCH (jg)-[:HAS_SLA]->(groupSla:SLA)
OPTIONAL MATCH (groupSla)-[:RELATIVE_TO_RESOURCE]->(r1:Resource)
OPTIONAL MATCH (jg)-[:HAS_JOB]->(j:Job)-[:HAS_SLA]->(jobSla:SLA)
OPTIONAL MATCH (jobSla)-[:RELATIVE_TO_RESOURCE]->(r2:Resource)
WITH jg,
     collect(DISTINCT {
       id              : groupSla.id,
       name            : groupSla.name,
       type            : groupSla.type,
       policy          : groupSla.policy,
       severity        : groupSla.severity,
       durationMs      : groupSla.durationMs,
       time            : groupSla.time,
       tz              : groupSla.tz,
       relativeResource: r1.name
     }) AS groupSlas,
     collect(DISTINCT {
       jobName         : j.name,
       id              : jobSla.id,
       name            : jobSla.name,
       type            : jobSla.type,
       policy          : jobSla.policy,
       severity        : jobSla.severity,
       durationMs      : jobSla.durationMs,
       time            : jobSla.time,
       tz              : jobSla.tz,
       relativeResource: r2.name
     }) AS jobSlas
RETURN {
  jobGroupName: jg.name,
  groupSlas   : groupSlas,
  jobSlas     : jobSlas,
  totalSlas   : size(groupSlas) + size(jobSlas)
} AS slaConfig;


// Q16 [GRAPHLET] — Critical Path for a Job Group Execution
// Parameter : $execId  (JobGroupExecution.id)
// Returns graphlet of CriticalPathInstance nodes linked to their executions,
// plus a JSON summary with CPM metrics and the critical path sequence.
//
// Neo4j Browser hint:
//   MATCH (jge:JobGroupExecution {id:$execId})
//   OPTIONAL MATCH (jge)-[:HAS_CRITICAL_PATH_CALCULATED]->(cpc:CriticalPathCalculated)
//   OPTIONAL MATCH (jge)-[:EXECUTES_JOB_CONTEXT]->(jce:JobContextExecution)
//   OPTIONAL MATCH (cpi:CriticalPathInstance)-[:FOR_RUN]->(jce)
//   RETURN jge, cpc, jce, cpi LIMIT 100
//
// MCP use : "show me the critical path for execution run X"
// ─────────────────────────────────────────────────────────────────────────────
MATCH (jge:JobGroupExecution {id: $execId})
OPTIONAL MATCH (jge)-[:HAS_CRITICAL_PATH_CALCULATED]->(cpc:CriticalPathCalculated)
OPTIONAL MATCH (jge)-[:EXECUTES_JOB_CONTEXT]->(jce:JobContextExecution)
OPTIONAL MATCH (cpi:CriticalPathInstance)-[:FOR_RUN]->(jce)
OPTIONAL MATCH (cpi)-[:FOR_CONTEXT]->(sic:ScheduleInstanceContext)
OPTIONAL MATCH (jce)-[:EXECUTES_JOB]->(j:Job)
WITH jge, cpc,
     collect(DISTINCT jce)  AS allJces,
     collect(DISTINCT cpi)  AS allCpis,
     collect(DISTINCT sic)  AS allSics,
     collect({
       jobName   : j.name,
       status    : jce.status,
       durationMs: jce.durationMs,
       slack     : cpi.slack,
       isLongest : cpi.isLongest
     }) AS executionDetails
WITH jge, cpc, allJces, allCpis, allSics, executionDetails,
     allJces + allCpis + allSics +
     CASE WHEN cpc IS NOT NULL THEN [cpc] ELSE [] END +
     [jge]                  AS allNodes
RETURN
  {
    nodes: [n IN allNodes | {
      id        : elementId(n),
      labels    : labels(n),
      name      : coalesce(n.name, ''),
      status    : coalesce(n.status, ''),
      durationMs: coalesce(n.durationMs, n.dur, 0),
      slack     : coalesce(n.slack, 0),
      isLongest : coalesce(n.isLongest, false)
    }],
    links: []
  } AS graphlet,
  {
    execId          : jge.id,
    businessDate    : jge.businessDate,
    startTime       : jge.startTime,
    cpmCompletionMs : cpc.cpm_completion_ms,
    cpmTotalBufferMs: cpc.cpm_total_buffer_ms,
    longestPath     : cpc.cpm_longest_path,
    criticalPath    : cpc.cpm_critical_path,
    signatureHash   : cpc.signatureHash,
    signatureText   : cpc.signatureText,
    totalContexts   : size(allJces),
    criticalCount   : size([c IN allCpis WHERE c.isLongest = true]),
    executionDetails: executionDetails
  } AS cpmSummary;
