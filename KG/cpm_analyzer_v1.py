from dataclasses import dataclass
from typing import Dict, List, Tuple, Set, Optional
from collections import defaultdict, deque
import hashlib

import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - [%(pathname)s:%(lineno)d %(funcName)s] - %(message)s"
)
logger = logging.getLogger(__name__)

@dataclass
class CPMResult:
    job_group_id: str
    group_sla_ms: Optional[int]
    completion_ms: int
    total_buffer_ms: Optional[int]
    longest_path: List[str]          # list of ctx ids
    critical_path: List[str]         # phase-1 == longest_path
    node_metrics: Dict[str, Dict[str, int]]  # {ctxId: {es,ef,ls,lf,slack,dur}}

class CPMAnalyzer:
    """
    Computes CPM on ScheduleInstanceContext graph for a JobGroup using:
      (JobGroup)-[:ENTRY]->(ScheduleInstanceContext)
      (ScheduleInstanceContext)-[:PRECEDES]->(ScheduleInstanceContext)
      ScheduleInstanceContext.estimatedDurationMs
    """

    def __init__(self, driver):
        self.driver = driver

    def compute_for_jobgroup(self, job_group_id: str, persist: bool = True) -> CPMResult:
        graph = self._fetch_jobgroup_graph(job_group_id)
        entry_ids = graph["entry_ids"]
        durations = graph["durations"]
        edges = graph["edges"]
        group_sla_ms = graph["group_sla_ms"]

        if not entry_ids:
            raise ValueError(f"No ENTRY contexts found for JobGroup={job_group_id}")

        # Build adjacency
        succ = defaultdict(list)
        pred = defaultdict(list)
        nodes: Set[str] = set(durations.keys())

        for a, b in edges:
            if a in nodes and b in nodes:
                succ[a].append(b)
                pred[b].append(a)

        # Restrict to ENTRY-reachable nodes (so orphan contexts don’t pollute CPM)
        reachable = self._reachable_from_entries(entry_ids, succ)
        if not reachable:
            raise ValueError(f"No nodes reachable from ENTRY for JobGroup={job_group_id}")

        # Topological order on reachable subgraph
        topo = self._toposort(reachable, pred, succ)

        # Forward pass
        es: Dict[str, int] = {}
        ef: Dict[str, int] = {}
        entry_set = set(entry_ids)

        for n in topo:
            if n in entry_set or len([p for p in pred[n] if p in reachable]) == 0:
                es[n] = 0
            else:
                es[n] = max(ef[p] for p in pred[n] if p in reachable)
            ef[n] = es[n] + int(durations.get(n, 0))

        # Completion is max EF among sinks (no successors within reachable)
        sinks = [n for n in reachable if len([s for s in succ[n] if s in reachable]) == 0]
        completion_ms = max(ef[n] for n in sinks) if sinks else max(ef.values())

        # Choose project finish:
        # - If group SLA is duration-based (durationMs), use it for LS/LF and buffer
        # - Else (no duration), treat finish = completion (classic CPM)
        if group_sla_ms is not None and group_sla_ms > 0:
            project_finish = group_sla_ms
            total_buffer_ms = group_sla_ms - completion_ms
        else:
            project_finish = completion_ms
            total_buffer_ms = None

        # Backward pass
        lf: Dict[str, int] = {}
        ls: Dict[str, int] = {}

        # initialize sinks
        for n in sinks:
            lf[n] = project_finish
            ls[n] = lf[n] - int(durations.get(n, 0))

        # reverse topo for predecessors
        for n in reversed(topo):
            if n in sinks:
                continue
            nexts = [s for s in succ[n] if s in reachable]
            if not nexts:
                lf[n] = project_finish
            else:
                lf[n] = min(ls[s] for s in nexts)
            ls[n] = lf[n] - int(durations.get(n, 0))

        slack: Dict[str, int] = {n: ls[n] - es[n] for n in reachable}

        # Longest path reconstruction (one of them):
        # pick sink with max EF, then walk backwards choosing predecessor with max EF
        end = max(sinks, key=lambda x: ef[x]) if sinks else max(reachable, key=lambda x: ef[x])
        longest_path = self._backtrack_longest_path(end, pred, ef, reachable)

        # Phase-1: define critical path as the longest path
        critical_path = longest_path[:]

        node_metrics = {}
        for n in reachable:
            node_metrics[n] = {
                "dur": int(durations.get(n, 0)),
                "es": int(es[n]),
                "ef": int(ef[n]),
                "ls": int(ls[n]),
                "lf": int(lf[n]),
                "slack": int(slack[n]),
            }

        result = CPMResult(
            job_group_id=job_group_id,
            group_sla_ms=group_sla_ms,
            completion_ms=completion_ms,
            total_buffer_ms=total_buffer_ms,
            longest_path=longest_path,
            critical_path=critical_path,
            node_metrics=node_metrics
        )

        if persist:
            self._persist_cpm(result)

        return result

    def _fetch_jobgroup_graph(self, job_group_id: str) -> Dict:
        query = """
        MATCH (jg:JobGroup {id:$jobGroupId})

        OPTIONAL MATCH (jg)-[:HAS_SLA]->(sla:SLA)
        WITH jg, collect(sla) AS slas

        OPTIONAL MATCH (jg)-[:ENTRY]->(entry:ScheduleInstanceContext)
        WITH jg, slas, collect(distinct entry.id) AS entryIds

        MATCH (ctx:ScheduleInstanceContext)-[:FOR_GROUP]->(jg)
        OPTIONAL MATCH (ctx)-[:PRECEDES]->(sctx:ScheduleInstanceContext)-[:FOR_GROUP]->(jg)
        RETURN
          entryIds AS entryIds,
          // choose the strictest positive durationMs if multiple SLAs are attached
          reduce(minSla = NULL,
                 s IN slas |
                 CASE
                   WHEN s.durationMs IS NULL THEN minSla
                   WHEN minSla IS NULL THEN toInteger(s.durationMs)
                   WHEN toInteger(s.durationMs) < minSla THEN toInteger(s.durationMs)
                   ELSE minSla
                 END) AS groupSlaMs,
          collect(distinct {id: ctx.id, dur: toInteger(coalesce(ctx.estimatedDurationMs,0))}) AS nodes,
          collect(distinct {from: ctx.id, to: sctx.id}) AS edges
        """
        with self.driver.session() as session:
            rec = session.run(query, jobGroupId=job_group_id).single()
            if rec is None:
                raise ValueError(f"JobGroup not found: {job_group_id}")

            nodes = rec["nodes"] or []
            durations = {n["id"]: int(n["dur"]) for n in nodes}
            edges_raw = rec["edges"] or []
            edges = [(e["from"], e["to"]) for e in edges_raw if e["from"] and e["to"]]

            return {
                "entry_ids": rec["entryIds"] or [],
                "group_sla_ms": rec["groupSlaMs"],
                "durations": durations,
                "edges": edges
            }

    def _reachable_from_entries(self, entry_ids: List[str], succ) -> Set[str]:
        seen = set()
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

    def _toposort(self, nodes: Set[str], pred, succ) -> List[str]:
        indeg = {n: 0 for n in nodes}
        for n in nodes:
            indeg[n] = len([p for p in pred.get(n, []) if p in nodes])

        q = deque([n for n in nodes if indeg[n] == 0])
        topo = []
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
            # cycle or broken graph
            missing = nodes - set(topo)
            raise ValueError(f"Graph is not a DAG (cycle or disconnected deps). Missing in topo: {sorted(missing)}")

        return topo

    def _backtrack_longest_path(self, end: str, pred, ef, nodes: Set[str]) -> List[str]:
        path = [end]
        cur = end
        while True:
            preds = [p for p in pred.get(cur, []) if p in nodes]
            if not preds:
                break
            # pick predecessor that maximizes EF (ties arbitrary)
            best = max(preds, key=lambda p: ef[p])
            path.append(best)
            cur = best
        path.reverse()
        return path

    def _persist_cpm(self, result: CPMResult):
        # store metrics on each ScheduleInstanceContext node
        rows = []
        for ctx_id, m in result.node_metrics.items():
            rows.append({
                "id": 'CPI_' + ctx_id,
                "sICtxId": ctx_id,
                "es": m["es"], "ef": m["ef"],
                "ls": m["ls"], "lf": m["lf"],
                "slack": m["slack"],
                "dur": m["dur"],
                "isLongest": ctx_id in set(result.longest_path),
            })

        q1 = """
        UNWIND $rows AS r
        MERGE (cpi:CriticalPathInstance {id: r.id})
        SET cpi.es = r.es,
            cpi.ef = r.ef,
            cpi.ls = r.ls,
            cpi.lf = r.lf,
            cpi.slack = r.slack,
            cpi.dur = r.dur,
            cpi.isLongest = r.isLongest,
            cpi.computedAt = datetime()
        WITH cpi, r
        MATCH (ctx:ScheduleInstanceContext {id:r.sICtxId})
        MERGE (cpi)-[:FOR_RUN]->(ctx)
        """
        q2 = """
        MERGE (cpi:CriticalPathCalculated {id: $id})
        SET cpi.cpm_completion_ms = $completion,
            cpi.cpm_total_buffer_ms = $buffer,
            cpi.cpm_longest_path = $longestPath,
            cpi.cpm_critical_path = $criticalPath,
            cpi.cpm_computed_at = datetime()
        WITH cpi
        MATCH (jg:JobGroup {id:$jobGroupId})
        MERGE (jg)-[:HAS_CRITICAL_PATH_CALCULATED]->(cpi)
        """

        q3 = """
        MERGE (cps:CriticalPathSignature {id: $id})
        SET cps.signatureHash = $signatureHash,
            cps.signatureText = $signatureText,
            cps.signature_computed_at = datetime()
        WITH cps
        MATCH (cpi:CriticalPathCalculated {id:$cpid})
        MERGE (cpi)-[:HAS_CRITICAL_PATH_SIGNATURE]->(cps)
        """

        with self.driver.session() as session:
            session.execute_write(lambda tx: tx.run(q1, rows=rows))
            session.execute_write(lambda tx: tx.run(
                q2,
                id='CPC_' + result.job_group_id,
                jobGroupId=result.job_group_id,
                completion=result.completion_ms,
                buffer=result.total_buffer_ms,
                longestPath=result.longest_path,
                criticalPath=result.critical_path
            ))
            # Create checksum string for critical_path
            critical_path_str = '->'.join(result.critical_path)
            signatureHash = hashlib.sha256(critical_path_str.encode('utf-8')).hexdigest()
            #print("Critical Path Signature Hash:", signatureHash)
            #print("Critical Path String:", critical_path_str)
            session.execute_write(lambda tx: tx.run(
                q3,
                id='CPS_' + result.job_group_id,
                cpid='CPC_' + result.job_group_id,
                signatureHash=signatureHash,
                signatureText=critical_path_str
            ))
