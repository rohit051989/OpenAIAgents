"""
neo4j_service.py
~~~~~~~~~~~~~~~~
All Neo4j graph queries for the Batch-IG-Extension-APIs.

Configuration is loaded exclusively from the YAML file whose path is defined
in app.config.Settings.config_path.  No values are hardcoded in this module.
"""

import logging
from pathlib import Path
from typing import Optional

import yaml
from fastapi import HTTPException
from neo4j import AsyncGraphDatabase, AsyncDriver

from app.config import settings
from app.models.schemas import GapInfo, GapsResponse, JavaMethodInfo, Job, Repository, Step

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App config loader
# ---------------------------------------------------------------------------

_cached_app_config: Optional[dict] = None


def _load_app_config() -> dict:
    """
    Load config/app_config.yaml once and cache it.
    Raises RuntimeError if the file cannot be read.
    """
    global _cached_app_config
    if _cached_app_config is not None:
        return _cached_app_config

    config_path = settings.config_path
    resolved = Path(config_path)
    if not resolved.is_absolute():
        resolved = Path.cwd() / config_path

    if not resolved.exists():
        raise RuntimeError(
            f"Application config file not found: {resolved}\n"
            "Make sure CONFIG_PATH in .env points to a valid app_config.yaml."
        )

    try:
        with open(resolved, "r", encoding="utf-8") as fh:
            cfg: dict = yaml.safe_load(fh) or {}
        logger.info("Loaded app config from %s", resolved)
        _cached_app_config = cfg
        return cfg
    except Exception as exc:
        raise RuntimeError(f"Failed to parse app config at {resolved}: {exc}") from exc


def _get_keywords(cfg: dict) -> dict:
    """Return the grey_area_keywords section (required in config)."""
    kw = cfg.get("grey_area_keywords")
    if not kw:
        raise RuntimeError("Missing 'grey_area_keywords' section in app_config.yaml.")
    return kw


def _get_scan_options(cfg: dict) -> dict:
    """Return the scan_options section with safe defaults."""
    opts = cfg.get("scan_options", {})
    return {
        "build_all_jobs": opts.get("build_all_jobs", True),
        "jobs_to_build": opts.get("jobs_to_build") or [],
    }


def _get_query_settings(cfg: dict) -> dict:
    """Return the graph_query section (required in config)."""
    gq = cfg.get("graph_query")
    if not gq:
        raise RuntimeError("Missing 'graph_query' section in app_config.yaml.")
    entry_methods = gq.get("entry_method_names")
    max_depth = gq.get("max_call_depth")
    if not entry_methods:
        raise RuntimeError("Missing 'graph_query.entry_method_names' in app_config.yaml.")
    if max_depth is None:
        raise RuntimeError("Missing 'graph_query.max_call_depth' in app_config.yaml.")
    return {"entry_method_names": entry_methods, "max_call_depth": int(max_depth)}


# ---------------------------------------------------------------------------
# Neo4j async driver (singleton)
# ---------------------------------------------------------------------------

_driver: Optional[AsyncDriver] = None


def get_driver() -> AsyncDriver:
    global _driver
    if _driver is None:
        if not settings.neo4j_password:
            raise HTTPException(
                status_code=500,
                detail="NEO4J_PASSWORD is not configured in .env.",
            )
        _driver = AsyncGraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
        )
    return _driver


async def close_driver() -> None:
    global _driver
    if _driver is not None:
        await _driver.close()
        _driver = None


# ---------------------------------------------------------------------------
# Service functions
# ---------------------------------------------------------------------------

async def test_connection() -> bool:
    try:
        driver = get_driver()
        async with driver.session(database=settings.neo4j_database) as session:
            await session.run("RETURN 1")
        return True
    except Exception as exc:
        logger.error("Neo4j connection test failed: %s", exc)
        return False


async def get_all_jobs() -> list[Job]:
    cfg = _load_app_config()
    scan = _get_scan_options(cfg)

    if not scan["build_all_jobs"] and scan["jobs_to_build"]:
        logger.info("getAllJobs - source: config %s", scan["jobs_to_build"])
        return [Job(name=n, jobId="") for n in scan["jobs_to_build"]]

    driver = get_driver()
    async with driver.session(database=settings.neo4j_database) as session:
        result = await session.run(
            """
            MATCH (j:Job)
            RETURN j.name AS name, elementId(j) AS jobId
            ORDER BY name
            """
        )
        records = await result.data()

    jobs = [Job(name=r["name"], jobId=r["jobId"]) for r in records]
    logger.info("getAllJobs - source: graph, returned %d job(s)", len(jobs))
    return jobs


async def get_steps_for_job(job_name: str) -> list[Step]:
    cfg = _load_app_config()
    kw = _get_keywords(cfg)

    # Upper-cased keyword lists for case-insensitive Cypher CONTAINS checks
    db_keywords    = [k.upper() for k in kw.get("core", []) + kw.get("db_operations", [])]
    proc_keywords  = [k.upper() for k in kw.get("core", []) + kw.get("procedure_calls", [])]
    shell_keywords = [k.upper() for k in kw.get("core", []) + kw.get("shell_executions", []) + kw.get("script_quality", [])]

    # Count gaps directly from Step-level aggregated arrays — no graph traversal needed.
    # Format mirrors JavaMethod arrays:
    #   stepDbOperations    → operation_type:table_name:confidence  (keyword in [1])
    #   stepProcedureCalls  → schema:package:procedure_name:...    (keyword in [2])
    #   stepShellExecutions → execution_method:script_name:conf    (keyword in [1])
    steps_query = """
        MATCH (j:Job {name: $jobName})-[:CONTAINS]->(s:Step)
        WITH s,
          size([op IN coalesce(s.stepDbOperations, [])
                WHERE size(split(op, ':')) >= 2
                  AND ANY(kw IN $dbKeywords WHERE toUpper(split(op, ':')[1]) CONTAINS kw)]) +
          size([pr IN coalesce(s.stepProcedureCalls, [])
                WHERE size(split(pr, ':')) >= 3
                  AND ANY(kw IN $procKeywords WHERE toUpper(split(pr, ':')[2]) CONTAINS kw)]) +
          size([sh IN coalesce(s.stepShellExecutions, [])
                WHERE size(split(sh, ':')) >= 2
                  AND ANY(kw IN $shellKeywords WHERE toUpper(split(sh, ':')[1]) CONTAINS kw)])
          AS gap_count
        RETURN s.name AS name, elementId(s) AS stepId,
               s.stepKind AS stepKind, gap_count
        ORDER BY s.name
    """

    driver = get_driver()
    async with driver.session(database=settings.neo4j_database) as session:
        result = await session.run(
            steps_query,
            jobName=job_name,
            dbKeywords=db_keywords,
            procKeywords=proc_keywords,
            shellKeywords=shell_keywords,
        )
        records = await result.data()

    return [
        Step(
            name=r["name"],
            stepId=r["stepId"],
            stepKind=r.get("stepKind"),
            gap_count=int(r["gap_count"]),
        )
        for r in records
    ]


async def get_gaps_for_step(step_name: str) -> GapsResponse:
    cfg = _load_app_config()
    kw = _get_keywords(cfg)
    qs = _get_query_settings(cfg)

    db_keywords = kw.get("core", []) + kw.get("db_operations", [])
    proc_keywords = kw.get("core", []) + kw.get("procedure_calls", [])
    shell_keywords = (
        kw.get("core", [])
        + kw.get("shell_executions", [])
        + kw.get("script_quality", [])
    )

    # max_call_depth cannot be a Cypher parameter for variable-length paths,
    # so it is safely embedded at query-build time from the validated config int.
    max_depth: int = qs["max_call_depth"]
    entry_methods: list = qs["entry_method_names"]

    gaps_query = f"""
        MATCH (s:Step {{name: $stepName}})-[:IMPLEMENTED_BY]->(jc:JavaClass)
        MATCH (jc)-[:HAS_METHOD]->(entry:JavaMethod)
        WHERE entry.methodName IN $entryMethods

        CALL (entry) {{
            MATCH path = (entry)-[:CALLS*0..{max_depth}]->(m:JavaMethod)
            RETURN m
        }}

        WITH m, m.dbOperations AS dbOps, m.procedureCalls AS procCalls,
             m.shellExecutions AS shellExecs, m.furtherAnalysisRequired AS needsAnalysis
        WHERE (
            size(dbOps) > 0 OR size(procCalls) > 0 OR size(shellExecs) > 0
            OR needsAnalysis = true
        )

        RETURN DISTINCT m.fqn AS methodFqn,
               dbOps,
               procCalls,
               shellExecs,
               needsAnalysis
        ORDER BY m.fqn
    """

    driver = get_driver()
    async with driver.session(database=settings.neo4j_database) as session:
        result = await session.run(
            gaps_query,
            stepName=step_name,
            entryMethods=entry_methods,
        )
        records = await result.data()

    gaps = GapsResponse()

    for r in records:
        method_fqn: str = r["methodFqn"]
        db_ops: list = r.get("dbOps") or []
        proc_calls: list = r.get("procCalls") or []
        shell_execs: list = r.get("shellExecs") or []
        needs_analysis: bool = r.get("needsAnalysis") or False

        # DB gaps ? format: operation_type:table_name:confidence
        for op in db_ops:
            parts = op.split(":")
            if len(parts) >= 2:
                table_name = parts[1]
                if any(kw_item.upper() in table_name.upper() for kw_item in db_keywords):
                    gaps.db.append(
                        GapInfo(
                            category="db",
                            operation=op,
                            methodFqn=method_fqn,
                            furtherAnalysisRequired=needs_analysis,
                        )
                    )

        # Procedure gaps ? format: schema:package:procedure_name:...
        for proc in proc_calls:
            parts = proc.split(":")
            if len(parts) >= 3:
                procedure_name = parts[2]
                if any(kw_item.upper() in procedure_name.upper() for kw_item in proc_keywords):
                    gaps.procedure.append(
                        GapInfo(
                            category="procedure",
                            operation=proc,
                            methodFqn=method_fqn,
                            furtherAnalysisRequired=needs_analysis,
                        )
                    )

        # Shell gaps ? format: execution_method:script_name:confidence
        for shell in shell_execs:
            parts = shell.split(":")
            if len(parts) >= 2:
                script_name = parts[1]
                script_lower = script_name.lower()
                is_shell_gap = any(
                    kw_item.lower() in script_lower or kw_item.upper() in script_name.upper()
                    for kw_item in shell_keywords
                )
                if is_shell_gap:
                    gaps.shell.append(
                        GapInfo(
                            category="shell",
                            operation=shell,
                            methodFqn=method_fqn,
                            furtherAnalysisRequired=needs_analysis,
                        )
                    )

    logger.info(
        "Gaps for step %s ? db: %d, procedure: %d, shell: %d",
        step_name, len(gaps.db), len(gaps.procedure), len(gaps.shell),
    )
    return gaps


async def get_java_file_for_method(method_fqn: str) -> Optional[JavaMethodInfo]:
    driver = get_driver()
    logger.info("Querying graph for method info: %s", method_fqn)
    async with driver.session(database=settings.neo4j_database) as session:
        result = await session.run(
            """
            MATCH (jc:JavaClass)-[:HAS_METHOD]->(m:JavaMethod {fqn: $methodFqn})
            RETURN m.fqn          AS methodFqn,
                   m.methodName   AS methodName,
                   m.lineCount    AS javaLineCount,
                   m.sourceCode   AS sourceCode,
                   jc.path        AS filePath,
                   jc.fqn         AS classFqn,
                   jc.gitBranchName   AS gitBranchName,
                   jc.gitRepoName AS gitRepoName
            LIMIT 1
            """,
            methodFqn=method_fqn,
        )
        records = await result.data()

    if not records:
        return None

    r = records[0]
    return JavaMethodInfo(
        methodFqn=r.get("methodFqn") or method_fqn,
        methodName=r.get("methodName"),
        javaLineCount=int(r["javaLineCount"]) if r.get("javaLineCount") is not None else None,
        sourceCode=r.get("sourceCode"),
        filePath=r.get("filePath"),
        classFqn=r.get("classFqn"),
        gitBranchName=r.get("gitBranchName"),
        gitRepoName=r.get("gitRepoName"),
    )


async def get_all_repositories() -> list[Repository]:
    driver = get_driver()
    async with driver.session(database=settings.neo4j_database) as session:
        result = await session.run(
            """
            MATCH (n:Repository)
            RETURN n.name       AS name,
                   n.repoName   AS repoName,
                   n.repoUrl    AS repoUrl,
                   n.branchName AS branchName,
                   n.path       AS path,
                   n.repoType   AS repoType
            ORDER BY n.name
            LIMIT 25
            """
        )
        records = await result.data()

    repos = [
        Repository(
            name=r.get("name") or r.get("repoName") or "",
            repoName=r.get("repoName"),
            repoUrl=r.get("repoUrl"),
            branchName=r.get("branchName"),
            path=r.get("path"),
            repoType=r.get("repoType"),
        )
        for r in records
    ]
    logger.info("get_all_repositories returned %d repo(s)", len(repos))
    return repos
