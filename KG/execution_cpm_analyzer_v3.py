"""
Execution CPM Analyzer (Phase-2)
================================

Computes CPM for a *single JobGroupExecution run* using:
  - Topology (class layer):
      (JobGroup)-[:ENTRY]->(ScheduleInstanceContext)
      (ScheduleInstanceContext)-[:PRECEDES]->(ScheduleInstanceContext)
      (ScheduleInstanceContext)-[:FOR_GROUP]->(JobGroup)
  - Durations (instance layer, per run):
      (JobGroupExecution)-[:EXECUTES_JOB_CONTEXT]->(JobContextExecution)-[:EXECUTES_CONTEXT]->(ScheduleInstanceContext)
    If multiple JobContextExecution exist for the same context in the same run, we pick one "representative"
    execution to feed CPM (default: prefer COMPLETED/SUCCESS, pick the longest durationMs; else longest overall).

Persists:
  - CriticalPathCalculated: one per JobGroupExecution (attached to JobGroupExecution)
  - CriticalPathInstance: one per selected JobContextExecution (attached to JobContextExecution)
  - CriticalPathSignature: a unique signature library per JobGroup (counted per JobGroupExecution)
      *Signature is incremented ONLY when a JobGroupExecution is first linked to that signature.*

Notes:
  - This file intentionally does NOT touch the older class-level CPM (cpm_analyzer_v1.py).
  - Relationship names match neo4j_direct_instance_loader_v3.py:
        (jge)-[:EXECUTES_JOB_GROUP]->(jg)
        (jge)-[:EXECUTES_JOB_CONTEXT]->(jce)
        (jce)-[:EXECUTES_CONTEXT]->(ctx)
"""

from dataclasses import dataclass
from typing import Dict, List, Tuple, Set, Optional, Any
from collections import defaultdict, deque
import hashlib


@dataclass
class ExecCPMResult:
    job_group_execution_id: str
    job_group_id: str
    group_sla_ms: Optional[int]
    completion_ms: int
    total_buffer_ms: Optional[int]
    longest_path: List[str]                  # list of ScheduleInstanceContext ids
    critical_path: List[str]                 # phase-2 (finish) == longest_path
    node_metrics: Dict[str, Dict[str, int]]  # {ctxId: {es,ef,ls,lf,slack,dur}}
    ctx_to_jce: Dict[str, Optional[str]]     # which JobContextExecution id was selected per ctx (may be None)


class ExecutionCPMAnalyzer:
    """
    CPM per JobGroupExecution.

    Public API:
      - compute_for_jobgroup_execution(job_group_execution_id, persist=True)
    """

    def __init__(self, driver):
        self.driver = driver

    def compute_for_jobgroup_execution(self, job_group_execution_id: str, persist: bool = True) -> ExecCPMResult:
        graph = self._fetch_run_graph(job_group_execution_id)

        job_group_id = graph["job_group_id"]
        entry_ids = graph["entry_ids"]
        durations = graph["durations"]
        edges = graph["edges"]
        group_sla_ms = graph["group_sla_ms"]
        ctx_to_jce = graph["ctx_to_jce"]

        if not entry_ids:
            raise ValueError(f"No ENTRY contexts found for JobGroupExecution={job_group_execution_id}")

        # Build adjacency
        succ: Dict[str, List[str]] = defaultdict(list)
        pred: Dict[str, List[str]] = defaultdict(list)

        nodes: Set[str] = set(durations.keys())
        for a, b in edges:
            if a in nodes and b in nodes:
                succ[a].append(b)
                pred[b].append(a)

        # Restrict to ENTRY-reachable nodes (avoid orphans)
        reachable = self._reachable_from_entries(entry_ids, succ)
        if not reachable:
            raise ValueError(f"No nodes reachable from ENTRY for JobGroupExecution={job_group_execution_id}")

        topo = self._toposort(reachable, pred, succ)

        # Forward pass
        es: Dict[str, int] = {}
        ef: Dict[str, int] = {}
        entry_set = set(entry_ids)

        for n in topo:
            if n in entry_set or len([p for p in pred.get(n, []) if p in reachable]) == 0:
                es[n] = 0
            else:
                es[n] = max(ef[p] for p in pred.get(n, []) if p in reachable)
            ef[n] = es[n] + int(durations.get(n, 0))

        # Completion is max EF among sinks
        sinks = [n for n in reachable if len([s for s in succ.get(n, []) if s in reachable]) == 0]
        completion_ms = max(ef[n] for n in sinks) if sinks else max(ef.values())

        # Project finish / buffer
        if group_sla_ms is not None and group_sla_ms > 0:
            project_finish = group_sla_ms
            total_buffer_ms = group_sla_ms - completion_ms
        else:
            project_finish = completion_ms
            total_buffer_ms = None

        # Backward pass
        lf: Dict[str, int] = {}
        ls: Dict[str, int] = {}

        for n in sinks:
            lf[n] = project_finish
            ls[n] = lf[n] - int(durations.get(n, 0))

        for n in reversed(topo):
            if n in sinks:
                continue
            nexts = [s for s in succ.get(n, []) if s in reachable]
            lf[n] = project_finish if not nexts else min(ls[s] for s in nexts)
            ls[n] = lf[n] - int(durations.get(n, 0))

        slack: Dict[str, int] = {n: int(ls[n] - es[n]) for n in reachable}

        # Longest path reconstruction
        end = max(sinks, key=lambda x: ef[x]) if sinks else max(reachable, key=lambda x: ef[x])
        longest_path = self._backtrack_longest_path(end, pred, ef, reachable)
        critical_path = longest_path[:]

        node_metrics: Dict[str, Dict[str, int]] = {}
        for n in reachable:
            node_metrics[n] = {
                "dur": int(durations.get(n, 0)),
                "es": int(es[n]),
                "ef": int(ef[n]),
                "ls": int(ls[n]),
                "lf": int(lf[n]),
                "slack": int(slack[n]),
            }

        result = ExecCPMResult(
            job_group_execution_id=job_group_execution_id,
            job_group_id=job_group_id,
            group_sla_ms=group_sla_ms,
            completion_ms=completion_ms,
            total_buffer_ms=total_buffer_ms,
            longest_path=longest_path,
            critical_path=critical_path,
            node_metrics=node_metrics,
            ctx_to_jce=ctx_to_jce
        )

        if persist:
            self._persist_run_cpm(result)

        return result

    # ---------------------------------------------------------------------
    # Graph fetch (per run)
    # ---------------------------------------------------------------------
    def _fetch_run_graph(self, job_group_execution_id: str) -> Dict[str, Any]:
        """
        Returns:
          - job_group_id
          - entry_ids
          - group_sla_ms
          - durations: {ctxId: durMs}  (durMs derived from JobContextExecution for this run)
          - ctx_to_jce: {ctxId: selectedJceId or None}
          - edges: [(fromCtxId, toCtxId)]
        """
        query = """
        MATCH (jge:JobGroupExecution {id:$jgeId})-[:EXECUTES_JOB_GROUP]->(jg:JobGroup)

        OPTIONAL MATCH (jg)-[:HAS_SLA]->(sla:SLA)
        WITH jge, jg, collect(sla) AS slas

        OPTIONAL MATCH (jg)-[:ENTRY]->(entry:ScheduleInstanceContext)
        WITH jge, jg, slas, collect(distinct entry.id) AS entryIds

        // contexts + edges inside this jobgroup
        MATCH (ctx:ScheduleInstanceContext)-[:FOR_GROUP]->(jg)
        OPTIONAL MATCH (ctx)-[:PRECEDES]->(sctx:ScheduleInstanceContext)-[:FOR_GROUP]->(jg)
        WITH jge, jg, slas, entryIds,
             collect(distinct ctx.id) AS ctxIds,
             collect(distinct {from: ctx.id, to: sctx.id}) AS edges

        // choose best execution per ctx for THIS JobGroupExecution
        CALL (jge, ctxIds) {
          UNWIND ctxIds AS ctxId
          OPTIONAL MATCH (jge)-[:EXECUTES_JOB_CONTEXT]->(jce:JobContextExecution)-[:EXECUTES_CONTEXT]->(:ScheduleInstanceContext {id: ctxId})
          WITH ctxId, collect(jce) AS execs

          WITH ctxId,
               [e IN execs WHERE e.status IN ['COMPLETED','SUCCESS'] AND e.durationMs IS NOT NULL] AS good,
               execs

          WITH ctxId, CASE WHEN size(good) > 0 THEN good ELSE execs END AS candidates
          UNWIND candidates AS c
          WITH ctxId, c
          ORDER BY ctxId, toInteger(coalesce(c.durationMs, 0)) DESC

          WITH ctxId, collect(c)[0] AS best
          RETURN collect({
            ctxId: ctxId,
            jceId: best.id,
            dur: toInteger(coalesce(best.durationMs, 0))
          }) AS perCtx
        }

        RETURN
          jg.id AS jobGroupId,
          entryIds AS entryIds,
          reduce(minSla = NULL,
                 s IN slas |
                 CASE
                   WHEN s.durationMs IS NULL THEN minSla
                   WHEN minSla IS NULL THEN toInteger(s.durationMs)
                   WHEN toInteger(s.durationMs) < minSla THEN toInteger(s.durationMs)
                   ELSE minSla
                 END) AS groupSlaMs,
          edges AS edges,
          perCtx AS perCtx
        """

        with self.driver.session() as session:
            rec = session.run(query, jgeId=job_group_execution_id).single()
            if rec is None:
                raise ValueError(f"JobGroupExecution not found: {job_group_execution_id}")

            per_ctx = rec["perCtx"] or []
            durations: Dict[str, int] = {}
            ctx_to_jce: Dict[str, Optional[str]] = {}
            for r in per_ctx:
                ctx_id = r.get("ctxId")
                if not ctx_id:
                    continue
                durations[ctx_id] = int(r.get("dur") or 0)
                ctx_to_jce[ctx_id] = r.get("jceId")

            edges_raw = rec["edges"] or []
            edges: List[Tuple[str, str]] = []
            for e in edges_raw:
                a = e.get("from")
                b = e.get("to")
                if a and b:
                    edges.append((a, b))

            return {
                "job_group_id": rec["jobGroupId"],
                "entry_ids": rec["entryIds"] or [],
                "group_sla_ms": rec["groupSlaMs"],
                "durations": durations,
                "ctx_to_jce": ctx_to_jce,
                "edges": edges,
            }

    # ---------------------------------------------------------------------
    # CPM helpers
    # ---------------------------------------------------------------------
    def _reachable_from_entries(self, entry_ids: List[str], succ: Dict[str, List[str]]) -> Set[str]:
        seen: Set[str] = set()
        dq = deque(entry_ids)
        while dq:
            n = dq.popleft()
            if n in seen:
                continue
            seen.add(n)
            for s in succ.get(n, []):
                if s not in seen:
                    dq.append(s)
        return seen

    def _toposort(self, nodes: Set[str], pred: Dict[str, List[str]], succ: Dict[str, List[str]]) -> List[str]:
        indeg = {n: len([p for p in pred.get(n, []) if p in nodes]) for n in nodes}
        q = deque([n for n in nodes if indeg[n] == 0])
        topo: List[str] = []

        while q:
            n = q.popleft()
            topo.append(n)
            for s in succ.get(n, []):
                if s not in nodes:
                    continue
                indeg[s] -= 1
                if indeg[s] == 0:
                    q.append(s)

        if len(topo) != len(nodes):
            missing = nodes - set(topo)
            raise ValueError(f"Graph is not a DAG (cycle or broken deps). Missing in topo: {sorted(missing)}")
        return topo

    def _backtrack_longest_path(self, end: str, pred: Dict[str, List[str]], ef: Dict[str, int], nodes: Set[str]) -> List[str]:
        path = [end]
        cur = end
        while True:
            preds = [p for p in pred.get(cur, []) if p in nodes]
            if not preds:
                break
            best = max(preds, key=lambda p: ef[p])
            path.append(best)
            cur = best
        path.reverse()
        return path

    # ---------------------------------------------------------------------
    # Persistence (per run)
    # ---------------------------------------------------------------------
    def _persist_run_cpm(self, result: ExecCPMResult) -> None:
        """
        Persists:
          - CPI per selected JobContextExecution (FOR_RUN -> JobContextExecution)
          - CPC per JobGroupExecution (HAS_CRITICAL_PATH_CALCULATED)
          - CPS per JobGroup (unique library) + occurrenceCount incremented per JobGroupExecution
        """
        critical_path_str = "->".join(result.critical_path)
        signature_hash = hashlib.sha256(critical_path_str.encode("utf-8")).hexdigest()

        cpc_id = "CPC_" + result.job_group_execution_id
        cps_id = "CPS_" + result.job_group_id + "_" + signature_hash

        # Build CPI rows for nodes where we have a selected JCE id
        cpi_rows = []
        longest_set = set(result.longest_path)

        for ctx_id, metrics in result.node_metrics.items():
            jce_id = result.ctx_to_jce.get(ctx_id)
            if not jce_id:
                continue
            cpi_rows.append({
                "cpiId": "CPI_" + jce_id,
                "jceId": jce_id,
                "ctxId": ctx_id,
                "es": metrics["es"], "ef": metrics["ef"],
                "ls": metrics["ls"], "lf": metrics["lf"],
                "slack": metrics["slack"],
                "dur": metrics["dur"],
                "isLongest": ctx_id in longest_set
            })

        q_cpi = """
        UNWIND $rows AS r
        MERGE (cpi:CriticalPathInstance {id: r.cpiId})
        SET cpi.es = r.es,
            cpi.ef = r.ef,
            cpi.ls = r.ls,
            cpi.lf = r.lf,
            cpi.slack = r.slack,
            cpi.dur = r.dur,
            cpi.isLongest = r.isLongest,
            cpi.computedAt = datetime()
        WITH cpi, r
        MATCH (jce:JobContextExecution {id: r.jceId})
        MERGE (cpi)-[:FOR_RUN]->(jce)
        WITH cpi, r
        MATCH (ctx:ScheduleInstanceContext {id: r.ctxId})
        MERGE (cpi)-[:FOR_CONTEXT]->(ctx)
        """

        q_cpc = """
        MATCH (jge:JobGroupExecution {id:$jgeId})-[:EXECUTES_JOB_GROUP]->(jg:JobGroup)
        MERGE (cpc:CriticalPathCalculated {id: $cpcId})
        SET cpc.cpm_completion_ms = $completion,
            cpc.cpm_total_buffer_ms = $buffer,
            cpc.cpm_longest_path = $longestPath,
            cpc.cpm_critical_path = $criticalPath,
            cpc.signatureHash = $signatureHash,
            cpc.signatureText = $signatureText,
            cpc.cpm_computed_at = datetime()
        WITH jge, cpc
        MERGE (jge)-[:HAS_CRITICAL_PATH_CALCULATED]->(cpc)
        """

        q_cps = """
        MATCH (jge:JobGroupExecution {id:$jgeId})-[:EXECUTES_JOB_GROUP]->(jg:JobGroup {id:$jobGroupId})
        MERGE (cps:CriticalPathSignature {id:$cpsId})
        ON CREATE SET cps.signatureHash = $signatureHash,
                      cps.signatureText = $signatureText,
                      cps.occurrenceCount = 0,
                      cps.firstSeenAt = datetime()
        SET cps.lastSeenAt = datetime()
        WITH jge, jg, cps
        MERGE (jg)-[:HAS_CRITICAL_PATH_SIGNATURE]->(cps)
        WITH jge, cps
        MERGE (jge)-[r:HAS_CRITICAL_PATH_SIGNATURE]->(cps)
        ON CREATE SET cps.occurrenceCount = cps.occurrenceCount + 1,
                      r.firstSeenAt = datetime()
        """

        q_link_cpc_cps = """
        MATCH (cpc:CriticalPathCalculated {id:$cpcId})
        MATCH (cps:CriticalPathSignature {id:$cpsId})
        MERGE (cpc)-[:HAS_CRITICAL_PATH_SIGNATURE]->(cps)
        """

        with self.driver.session() as session:
            if cpi_rows:
                session.execute_write(lambda tx: tx.run(q_cpi, rows=cpi_rows))

            session.execute_write(lambda tx: tx.run(
                q_cpc,
                jgeId=result.job_group_execution_id,
                cpcId=cpc_id,
                completion=result.completion_ms,
                buffer=result.total_buffer_ms,
                longestPath=result.longest_path,
                criticalPath=result.critical_path,
                signatureHash=signature_hash,
                signatureText=critical_path_str
            ))

            session.execute_write(lambda tx: tx.run(
                q_cps,
                jgeId=result.job_group_execution_id,
                jobGroupId=result.job_group_id,
                cpsId=cps_id,
                signatureHash=signature_hash,
                signatureText=critical_path_str
            ))

            session.execute_write(lambda tx: tx.run(
                q_link_cpc_cps,
                cpcId=cpc_id,
                cpsId=cps_id
            ))
