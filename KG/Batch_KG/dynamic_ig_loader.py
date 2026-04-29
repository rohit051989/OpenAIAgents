"""
Dynamic Job Loader — Information Graph
=======================================
Loads dynamic batch jobs into the *Information Graph* (informationgraph).

Dynamic jobs have no custom Java logic; they run a shared DynamicTasklet class
that executes a shell script or calls a stored procedure depending on the
Excel configuration.

Nodes created in the IG
-----------------------
Per step  (one dedicated Bean/JavaClass/JavaMethod per dynamic step):
  Bean          beanId=dynamicTasklet_{STEP_IDENT}, compositeKey unique per step
  JavaClass     fqn={BASE_FQN}_{STEP_IDENT}, className={BASE_CLASS}_{STEP_IDENT}
                shares the same physical source path as the base tasklet file
  JavaMethod    fqn={BASE_FQN}_{STEP_IDENT}.execute()
                carries only THIS step's shellExecutions / procedureCalls

Per dynamic job:
  Job           name=JOB_NAME, id=JOB_ID, dynamicJob=true

Per step  (summary arrays only — no script/procedure details on Step):
  Step          name=STEP_NAME, stepShellExecutions=[...], stepShellExecutionCount,
                stepProcedureCalls=[...], stepProcedureCallCount, dynamicJob=true

Per FILE param  -> SHELL_SCRIPT Resource  (all script details live here, not on Step):
  Resource      name=FILE, type=SHELL_SCRIPT, scriptPath=DIR/FILE,
                scriptType, scriptParams (list, split by space), executionUser
  Smart match:  if the Excel path matches *common/<Folder>/<FILE> and an existing
                Resource or File:ShellScript node in the IG has the same
                <Folder>/<FILE> suffix under a *common segment, that node is
                enriched and linked — no duplicate Resource is created.

Per PROC_NAME param -> PROCEDURE/FUNCTION Resource:
  Resource      name=PROC_NAME, type=PROCEDURE|FUNCTION,
                schemaName=PROC_SCHEMA, packageName=PROC_PACKAGE

Relationships
-------------
  Bean       -[:IMPLEMENTS]->                   JavaClass
  JavaClass  -[:HAS_METHOD]->                   JavaMethod
  JavaMethod -[:EXECUTES {scriptType,...}]->    Resource (SHELL_SCRIPT)
  JavaMethod -[:INVOKES  {databaseType,...}]->  Resource (PROCEDURE|FUNCTION)
  Step       -[:USES_BEAN]->                    Bean
  Step       -[:IMPLEMENTED_BY]->               JavaClass
  Job        -[:CONTAINS]->                     Step
  Job        -[:ENTRY]->                        Step  (first by STEP_ORDER)
  Step       -[:PRECEDES {on: COMPLETED}]->     Step  (ordered chain)

Excel KEY_PARAM values supported
----------------------------------
  Shell:      DIR, FILE, PARAMS, USER
  Procedure:  PROC_NAME, PROC_SCHEMA, PROC_PACKAGE, PROC_PARAMS

Per-step identity naming scheme
--------------------------------
  STEP_IDENT   = step name with non-alphanumeric chars replaced by '_'
                 e.g. "EXECUTE_CUSTOMER_STEP" → "EXECUTE_CUSTOMER_STEP"
                      "Run Report Step"       → "Run_Report_Step"
  Bean         beanId          = dynamicTasklet_{STEP_IDENT}
               compositeKey    = dynamicTasklet_{STEP_IDENT}___{BASE_FQN}_{STEP_IDENT}
  JavaClass    fqn             = {BASE_FQN}_{STEP_IDENT}
               className       = {BASE_CLASS}_{STEP_IDENT}
               path            = same physical file as base tasklet
  JavaMethod   fqn             = {BASE_FQN}_{STEP_IDENT}.execute()
               shellExecutions = only THIS step's shell executions
               procedureCalls  = only THIS step's procedure calls

DataClasses used
----------------
  JobDef               — job node construction
  StepDef              — step node construction (impl_bean/class_name set per-step)
  BeanDef              — bean node construction
  ClassInfo            — JavaClass node construction
  MethodDef            — JavaMethod node construction
  ShellScriptExecution — encode per-step shell execution info
  ProcedureCall        — encode per-step procedure call info
  ResourceNodeDef      — resource node construction (both shell and procedure)
"""

import os
import uuid
import logging
from pathlib import Path
from typing import Dict, List, Optional

import yaml
import openpyxl
from dotenv import load_dotenv
from neo4j import GraphDatabase

from classes.DataClasses import (
    JobDef, StepDef, BeanDef, ClassInfo, MethodDef,
    ShellScriptExecution, ProcedureCall,
)
from classes.KGNodeDefs import ResourceNodeDef

load_dotenv()

logger = logging.getLogger(__name__)


# ─────────────────────── helpers ──────────────────────────────────────────────

def _detect_script_type(script_name: str) -> str:
    """Infer script type from file extension."""
    lower = (script_name or "").lower()
    if lower.endswith(".sh"):                            return "BASH"
    if lower.endswith(".py"):                            return "PYTHON"
    if lower.endswith(".ps1"):                           return "POWERSHELL"
    if lower.endswith(".bat") or lower.endswith(".cmd"): return "BATCH"
    if lower.endswith(".pl"):                            return "PERL"
    return "SHELL"


def _parse_dynamic_jobs_excel(excel_file: str) -> Dict[str, Dict]:
    """
    Parse Dynamic_Jobs.xlsx into::

        { job_name: { id, steps: { step_name: { order, params: {KEY: VALUE} } } } }

    Supported KEY_PARAM values:
      Shell     : DIR, FILE, PARAMS, USER
      Procedure : PROC_NAME, PROC_SCHEMA, PROC_PACKAGE, PROC_PARAMS
    """
    wb = openpyxl.load_workbook(excel_file, data_only=True)
    ws = wb["Dynamic_Jobs_Details"]

    jobs: Dict[str, Dict] = {}
    for row in ws.iter_rows(min_row=2, values_only=True):
        if not row or row[0] is None:
            continue
        job_name, job_id, step_name, step_order, value_param, key_param = row
        job_name    = str(job_name).strip()
        job_id      = str(int(job_id)) if job_id is not None else ""
        step_name   = str(step_name).strip()
        step_order  = int(step_order) if step_order else 1
        value_param = str(value_param).strip() if value_param else ""
        key_param   = str(key_param).strip().upper() if key_param else ""

        if job_name not in jobs:
            jobs[job_name] = {"id": job_id, "steps": {}}
        if step_name not in jobs[job_name]["steps"]:
            jobs[job_name]["steps"][step_name] = {"order": step_order, "params": {}}
        if key_param:
            jobs[job_name]["steps"][step_name]["params"][key_param] = value_param

    logger.info(f"  Parsed {len(jobs)} dynamic job(s) from {excel_file}")
    return jobs


# ─────────────────────── loader class ─────────────────────────────────────────

class DynamicIGLoader:
    """Writes dynamic-job nodes and relationships into the Information Graph."""

    def __init__(self, config_path: str = "config/information_graph_config.yaml"):
        with open(config_path, "r", encoding="utf-8") as fh:
            self.config = yaml.safe_load(fh)

        neo4j_cfg = self.config["neo4j"]
        self.driver = GraphDatabase.driver(
            neo4j_cfg["uri"],
            auth=(neo4j_cfg["user"], neo4j_cfg["password"]),
        )
        self.database = neo4j_cfg["database_ig"]

        dj_cfg = self.config.get("dynamic_jobs", {})
        self.enabled            = dj_cfg.get("enabled", True)
        self.excel_file         = dj_cfg.get("excel_file", "sample_data/Dynamic_Jobs.xlsx")
        self.tasklet_fqn        = dj_cfg.get("dynamic_tasklet_class_fqn",
                                              "com.batch.dynamic.DynamicTasklet")
        self.tasklet_bean_id    = dj_cfg.get("dynamic_tasklet_bean_id", "dynamicTasklet")
        self.tasklet_path       = dj_cfg.get("dynamic_tasklet_path",
                                              "dynamic/DynamicTasklet.java")
        self.spring_config_path = dj_cfg.get("dynamic_spring_config_path",
                                              "dynamic/dynamic-spring-config.xml")

        self.tasklet_class_name = self.tasklet_fqn.split(".")[-1]
        self.tasklet_package    = ".".join(self.tasklet_fqn.split(".")[:-1])
        # Bean/JavaClass/JavaMethod identifiers are per-step — use _step_* helpers

    def close(self):
        if self.driver:
            self.driver.close()

    # ── per-step identity helpers ──────────────────────────────────────────────

    @staticmethod
    def _step_ident(step_name: str) -> str:
        """Sanitize a step name into a valid Java identifier suffix."""
        import re
        return re.sub(r"[^A-Za-z0-9_]", "_", step_name)

    def _step_fqn(self, step_ident: str) -> str:
        return f"{self.tasklet_fqn}_{step_ident}"

    def _step_bean_id(self, step_ident: str) -> str:
        return f"{self.tasklet_bean_id}_{step_ident}"

    def _step_composite_key(self, step_ident: str) -> str:
        return f"{self._step_bean_id(step_ident)}___{self._step_fqn(step_ident)}"

    def _step_method_fqn(self, step_ident: str) -> str:
        return f"{self._step_fqn(step_ident)}.execute()"

    # ── common-path helpers for shell resource matching ────────────────────────

    @staticmethod
    def _extract_common_key(path: str) -> Optional[str]:
        """
        Given a path like /apps/apms-batch/common/SasDecom/runAPMSSASJob.sh
        or repo/scripts/jobs-common/SasDecom/runAPMSSASJob.sh, find the segment
        whose name ENDS with 'common' and return '<FolderName>/<FileName>'.
        Returns None if no such pattern is found.
        """
        import re
        parts = [p for p in re.split(r'[/\\]', path) if p]
        for i, part in enumerate(parts):
            if part.lower().endswith('common') and i + 2 < len(parts):
                return f"{parts[i + 1]}/{parts[i + 2]}"
        return None

    def _find_existing_shell_resource(
        self, session, filename: str, common_key: Optional[str]
    ):
        """
        Search the IG for a Resource or File:ShellScript node whose name matches
        *filename* AND whose stored path (or resourceLocation/repoFilePath) contains
        *common_key* ("<FolderName>/<FileName>").
        Returns the single() record if found, else None.
        """
        if not common_key:
            return None
        result = session.run(
            """
            MATCH (r)
            WHERE (r:Resource OR r.extension IN ['.sh', '.bat', '.cmd', '.ps1', '.pl'])
              AND r.name = $filename
              AND (
                replace(coalesce(r.path, ''), $bs, '/') CONTAINS $folderFile
                OR replace(coalesce(r.resourceLocation, ''), $bs, '/') CONTAINS $folderFile
                OR replace(coalesce(r.repoFilePath, ''), $bs, '/') CONTAINS $folderFile
              )
            RETURN r
            LIMIT 1
            """,
            filename=filename,
            folderFile=common_key,
            bs='\\',
        )
        return result.single()

    # ── per-step infrastructure nodes ─────────────────────────────────────────

    def _ensure_step_nodes(self, session, step_name: str, has_shell: bool, has_procedure: bool):
        """
        Create/update the Bean, JavaClass, and JavaMethod for a single dynamic step.
        Each step gets its own uniquely-named set so execution arrays remain
        step-scoped (avoids one giant execute() method accumulating 1000+ entries).
        """
        step_ident    = self._step_ident(step_name)
        step_fqn      = self._step_fqn(step_ident)
        bean_id       = self._step_bean_id(step_ident)
        composite_key = self._step_composite_key(step_ident)
        method_fqn    = self._step_method_fqn(step_ident)
        class_name    = f"{self.tasklet_class_name}_{step_ident}"

        logger.debug(f"    [IG] Ensuring nodes for step '{step_name}' (ident={step_ident})")

        # Bean
        bean = BeanDef(
            bean_id=bean_id,
            bean_class=step_fqn,
            bean_class_name=class_name,
            source_xml_file=self.spring_config_path,
        )
        session.run(
            """
            MERGE (b:Bean {compositeKey: $compositeKey})
            ON CREATE SET
                b.beanId          = $beanId,
                b.beanClass       = $beanClass,
                b.simpleClassName = $simpleClassName,
                b.path            = $path,
                b.hasSource       = false,
                b.dynamicJob      = true,
                b.dynamicBean     = true,
                b.created_at      = datetime()
            ON MATCH SET
                b.dynamicJob  = true,
                b.dynamicBean = true
            """,
            compositeKey=composite_key,
            beanId=bean.bean_id,
            beanClass=bean.bean_class,
            simpleClassName=bean.bean_class_name,
            path=self.tasklet_path,
        )

        # JavaClass
        cls_info = ClassInfo(
            package=self.tasklet_package,
            class_name=class_name,
            fqn=step_fqn,
            source_path=self.tasklet_path,
            isShellExecutorClass=has_shell,
        )
        session.run(
            """
            MERGE (c:JavaClass {fqn: $fqn})
            ON CREATE SET
                c.className            = $className,
                c.package              = $package,
                c.path                 = $path,
                c.extends              = '',
                c.isInterface          = false,
                c.isDAOClass           = $isDAOClass,
                c.isShellExecutorClass = $isShellExecutorClass,
                c.isTestClass          = false,
                c.method_count         = 1,
                c.dynamicJob           = true,
                c.dynamicJavaClass     = true,
                c.created_at           = datetime()
            ON MATCH SET
                c.isShellExecutorClass = $isShellExecutorClass,
                c.dynamicJob           = true,
                c.dynamicJavaClass     = true
            """,
            fqn=cls_info.fqn,
            className=cls_info.class_name,
            package=cls_info.package,
            path=cls_info.source_path,
            isDAOClass=cls_info.isDAOClass,
            isShellExecutorClass=cls_info.isShellExecutorClass,
        )

        # Bean -[:IMPLEMENTS]-> JavaClass
        session.run(
            """
            MATCH (b:Bean {compositeKey: $compositeKey})
            MATCH (c:JavaClass {fqn: $fqn})
            MERGE (b)-[:IMPLEMENTS]->(c)
            """,
            compositeKey=composite_key,
            fqn=step_fqn,
        )

        # JavaMethod
        method = MethodDef(
            class_fqn=step_fqn,
            method_name="execute",
            return_type="RepeatStatus",
            modifiers=["public"],
        )
        session.run(
            """
            MERGE (m:JavaMethod {fqn: $fqn})
            ON CREATE SET
                m.methodName          = $methodName,
                m.classFqn            = $classFqn,
                m.returnType          = $returnType,
                m.signature           = $signature,
                m.modifiers           = $modifiers,
                m.sourceCode          = '',
                m.shellExecutionCount = 0,
                m.shellExecutions     = [],
                m.dbOperationCount    = 0,
                m.procedureCallCount  = 0,
                m.dbOperations        = [],
                m.procedureCalls      = [],
                m.dynamicJob          = true,
                m.dynamicJavaMethod   = true,
                m.created_at          = datetime()
            ON MATCH SET
                m.dynamicJob        = true,
                m.dynamicJavaMethod = true
            """,
            fqn=method_fqn,
            methodName=method.method_name,
            classFqn=step_fqn,
            returnType=method.return_type,
            signature="RepeatStatus execute(StepContribution, ChunkContext)",
            modifiers=" ".join(method.modifiers),
        )

        # JavaClass -[:HAS_METHOD]-> JavaMethod
        session.run(
            """
            MATCH (c:JavaClass {fqn: $classFqn})
            MATCH (m:JavaMethod {fqn: $methodFqn})
            MERGE (c)-[:HAS_METHOD]->(m)
            """,
            classFqn=step_fqn,
            methodFqn=method_fqn,
        )

    # ── per-job ────────────────────────────────────────────────────────────────

    def _create_job(self, session, job_def: JobDef):
        """Write a Job node using JobDef dataclass fields."""
        session.run(
            """
            MERGE (j:Job {name: $name})
            ON CREATE SET
                j.id         = $id,
                j.enabled    = $enabled,
                j.dynamicJob = true,
                j.sourceFile = $sourceFile,
                j.createdAt  = datetime()
            ON MATCH SET
                j.id         = $id,
                j.dynamicJob = true
            """,
            name=job_def.name,
            id=job_def.id,
            enabled=job_def.enabled,
            sourceFile=job_def.source_file,
        )

    # ── per-step ───────────────────────────────────────────────────────────────

    def _create_step(
        self,
        session,
        step_def: StepDef,
        step_order: int,
        shell_execs: List[ShellScriptExecution],
        proc_calls: List[ProcedureCall],
        sql_invocations: List[str],
    ):
        """
        Write a Step node using StepDef fields.

        Step carries ONLY summary execution arrays (stepShellExecutions,
        stepProcedureCalls and their counts).  Per-resource detail properties
        like scriptPath, scriptParams, remoteUser, schemaName, manuallyResolved etc. live on
        Resource nodes — NOT on the Step.
        """
        shell_exec_strs = [
            f"{se.execution_method or 'RESOLVED'}:{se.script_name}:{se.confidence}"
            for se in shell_execs if se.script_name
        ]
        proc_call_strs = [
            f"{pc.database_type}:{pc.procedure_name}:{pc.confidence}"
            for pc in proc_calls if pc.procedure_name
        ]

        session.run(
            """
            MERGE (s:Step {name: $name})
            SET s.stepKind                = $stepKind,
                s.implBean                = $implBean,
                s.className               = $className,
                s.path                    = $path,
                s.dynamicJob              = true,
                s.dynamicStep             = true,
                s.stepOrder               = $stepOrder,
                s.stepShellExecutions     = $shellExecs,
                s.stepShellExecutionCount = $shellCount,
                s.stepProcedureCalls          = $procCalls,
                s.stepProcedureCallCount      = $procCount,
                s.stepSqlFileInvocations      = $sqlFiles,
                s.stepSqlFileInvocationCount  = $sqlCount
            """,
            name=step_def.name,
            stepKind=step_def.step_kind,
            implBean=step_def.impl_bean,
            className=step_def.class_name,
            path=step_def.class_source_path,
            stepOrder=step_order,
            shellExecs=shell_exec_strs,
            shellCount=len(shell_exec_strs),
            procCalls=proc_call_strs,
            procCount=len(proc_call_strs),
            sqlFiles=sql_invocations,
            sqlCount=len(sql_invocations),
        )

        step_ident    = self._step_ident(step_def.name)
        composite_key = self._step_composite_key(step_ident)
        step_fqn      = self._step_fqn(step_ident)

        # Step -[:USES_BEAN]-> Bean  (step-specific bean)
        session.run(
            """
            MATCH (s:Step {name: $stepName})
            MATCH (b:Bean {compositeKey: $compositeKey})
            MERGE (s)-[:USES_BEAN {role: 'tasklet'}]->(b)
            """,
            stepName=step_def.name,
            compositeKey=composite_key,
        )

        # Step -[:IMPLEMENTED_BY]-> JavaClass  (step-specific class)
        session.run(
            """
            MATCH (s:Step {name: $stepName})
            MATCH (c:JavaClass {fqn: $fqn})
            MERGE (s)-[:IMPLEMENTED_BY]->(c)
            """,
            stepName=step_def.name,
            fqn=step_fqn,
        )

    # ── shell resource ─────────────────────────────────────────────────────────

    def _create_shell_resource_and_link(
        self,
        session,
        resource: ResourceNodeDef,
        shell_exec: ShellScriptExecution,
        script_params: List[str],
        exec_user: str,
        method_fqn: str,
    ):
        """
        Create or locate a SHELL_SCRIPT Resource, then link from the step-specific
        JavaMethod:
          JavaMethod -[:EXECUTES {scriptType, confidence, executionType}]-> Resource

        Smart-match: if the Excel path contains *common/<Folder>/<File> and an
        existing IG node (Resource or File:ShellScript) has the same
        <Folder>/<File> portion, THAT node is enriched and linked — no duplicate
        Resource is created.  If no match is found, a new Resource node is merged.
        """
        common_key = self._extract_common_key(
            resource.resourceLocation or resource.name
        )
        existing = self._find_existing_shell_resource(
            session, resource.name, common_key
        )

        existing_path: Optional[str] = None
        if existing:
            existing_path = existing["r"]["path"]
            logger.debug(
                f"    [IG] Shell '{resource.name}' matched existing IG node "
                f"(path={existing_path}) via common-key '{common_key}'"
            )
            # Enrich existing node with dynamic-job execution properties only
            session.run(
                """
                MATCH (r) WHERE r.path = $path
                SET r.scriptParams  = $scriptParams,
                    r.scriptPath    = $scriptPath,
                    r.scriptType    = $scriptType,
                    r.executionUser = $execUser,
                    r.type          = 'SHELL_SCRIPT'
                """,
                path=existing_path,
                scriptParams=script_params,
                scriptPath=resource.resourceLocation,
                scriptType=shell_exec.script_type,
                execUser=exec_user,
            )
            # Link step-specific JavaMethod to the existing node
            session.run(
                """
                MATCH (m:JavaMethod {fqn: $methodFqn})
                MATCH (r) WHERE r.path = $path
                MERGE (m)-[:EXECUTES {
                    scriptType:    $scriptType,
                    confidence:    $confidence,
                    executionType: 'REMOTE',
                    dynamicJob:    true
                }]->(r)
                """,
                methodFqn=method_fqn,
                path=existing_path,
                scriptType=shell_exec.script_type,
                confidence=shell_exec.confidence,
            )
        else:
            # No matching node found — create a new Resource
            session.run(
                """
                MERGE (r:Resource {name: $name, type: 'SHELL_SCRIPT'})
                ON CREATE SET
                    r.id            = $id,
                    r.enabled       = true,
                    r.scriptType    = $scriptType,
                    r.scriptPath    = $scriptPath,
                    r.scriptParams  = $scriptParams,
                    r.executionType = 'REMOTE',
                    r.executionUser = $execUser,
                    r.dynamicJob    = true,
                    r.foundInRepo   = false
                ON MATCH SET
                    r.scriptType    = $scriptType,
                    r.scriptPath    = COALESCE(r.scriptPath, $scriptPath),
                    r.scriptParams  = $scriptParams,
                    r.executionUser = $execUser,
                    r.dynamicJob    = true
                """,
                name=resource.name,
                id=resource.id,
                scriptType=shell_exec.script_type,
                scriptPath=resource.resourceLocation,
                scriptParams=script_params,
                execUser=exec_user,
            )
            session.run(
                """
                MATCH (m:JavaMethod {fqn: $methodFqn})
                MATCH (r:Resource {name: $name, type: 'SHELL_SCRIPT'})
                MERGE (m)-[:EXECUTES {
                    scriptType:    $scriptType,
                    confidence:    $confidence,
                    executionType: 'REMOTE',
                    dynamicJob:    true
                }]->(r)
                """,
                methodFqn=method_fqn,
                name=resource.name,
                scriptType=shell_exec.script_type,
                confidence=shell_exec.confidence,
            )

        return existing_path

    # ── sql invocations from shell ─────────────────────────────────────────────

    @staticmethod
    def _extract_sql_invocations(shell_content: str) -> List[str]:
        """
        Parse shell script content for SQL file paths invoked via the
        sqlplus '@/path/to/file.sql' syntax.  Only absolute paths (starting
        with '/') are matched to avoid false positives from TNS '@' tokens.
        """
        import re
        found: List[str] = []
        for m in re.finditer(r'@(["\']?/[^\s"\'>]+\.sql["\']?)', shell_content, re.IGNORECASE):
            found.append(m.group(1).strip("\"'"))
        return list(dict.fromkeys(found))  # deduplicate, preserve order

    def _find_existing_sql_resource(
        self, session, filename: str, common_key: Optional[str]
    ):
        """
        Search the IG for a Resource or SqlScript node whose name matches
        *filename* AND whose stored path contains *common_key*.
        Returns the single() record if found, else None.
        """
        if not common_key:
            return None
        result = session.run(
            """
            MATCH (r)
            WHERE (r:Resource OR r.extension IN ['.sql', '.ddl'])
              AND r.name = $filename
              AND (
                replace(coalesce(r.path, ''), $bs, '/') CONTAINS $folderFile
                OR replace(coalesce(r.resourceLocation, ''), $bs, '/') CONTAINS $folderFile
              )
            RETURN r
            LIMIT 1
            """,
            filename=filename,
            folderFile=common_key,
            bs='\\',
        )
        return result.single()

    def _to_absolute_path(self, relative_path: str) -> Optional[str]:
        """
        Convert a repo-relative IG path (e.g. 'my_repo/batch/.../file.sh')
        back to an absolute filesystem path using the loaded repository config.
        """
        if not relative_path:
            return None
        for repo in self.config.get('repositories', []):
            repo_name = repo.get('name', '')
            repo_base = repo.get('path', '')
            prefix = repo_name + '/'
            if relative_path.startswith(prefix):
                suffix = relative_path[len(prefix):]
                return str(Path(repo_base) / suffix.replace('/', os.sep))
        return None

    def _process_sql_invocations(
        self,
        session,
        sql_paths: List[str],
        shell_existing_path: Optional[str],
        shell_resource_name: str,
    ) -> List[str]:
        """
        For each SQL file path extracted from a shell script:
          - Find an existing IG SQL node (via common-key match) or create a new Resource
          - Create shell_resource -[:INVOKES {executionType:'SQL_SCRIPT'}]-> sql_resource
        Returns list of SQL filenames for Step-level tracking.
        """
        sql_filenames: List[str] = []
        for sql_path in sql_paths:
            sql_filename = Path(sql_path).name
            if not sql_filename:
                continue
            common_key = self._extract_common_key(sql_path)
            existing_sql = self._find_existing_sql_resource(session, sql_filename, common_key)

            if existing_sql:
                sql_node_path = existing_sql["r"]["path"]
                # Ensure type property is set on existing node
                session.run(
                    "MATCH (r) WHERE r.path = $path SET r.type = 'SQL_SCRIPT'",
                    path=sql_node_path,
                )
                if shell_existing_path:
                    session.run(
                        """
                        MATCH (sh) WHERE sh.path = $shPath
                        MATCH (sql) WHERE sql.path = $sqlPath
                        MERGE (sh)-[:INVOKES {executionType: 'SQL_SCRIPT', dynamicJob: true}]->(sql)
                        """,
                        shPath=shell_existing_path, sqlPath=sql_node_path,
                    )
                else:
                    session.run(
                        """
                        MATCH (sh:Resource {name: $shName, type: 'SHELL_SCRIPT'})
                        MATCH (sql) WHERE sql.path = $sqlPath
                        MERGE (sh)-[:INVOKES {executionType: 'SQL_SCRIPT', dynamicJob: true}]->(sql)
                        """,
                        shName=shell_resource_name, sqlPath=sql_node_path,
                    )
            else:
                session.run(
                    """
                    MERGE (r:Resource {name: $name, type: 'SQL_SCRIPT'})
                    ON CREATE SET
                        r.id          = $id,
                        r.enabled     = true,
                        r.scriptPath  = $scriptPath,
                        r.dynamicJob  = true,
                        r.foundInRepo = false
                    ON MATCH SET
                        r.scriptPath = COALESCE(r.scriptPath, $scriptPath),
                        r.type       = 'SQL_SCRIPT'
                    """,
                    name=sql_filename,
                    id=f"RES_SQL_{uuid.uuid4().hex[:8].upper()}",
                    scriptPath=sql_path,
                )
                if shell_existing_path:
                    session.run(
                        """
                        MATCH (sh) WHERE sh.path = $shPath
                        MATCH (sql:Resource {name: $sqlName, type: 'SQL_SCRIPT'})
                        MERGE (sh)-[:INVOKES {executionType: 'SQL_SCRIPT', dynamicJob: true}]->(sql)
                        """,
                        shPath=shell_existing_path, sqlName=sql_filename,
                    )
                else:
                    session.run(
                        """
                        MATCH (sh:Resource {name: $shName, type: 'SHELL_SCRIPT'})
                        MATCH (sql:Resource {name: $sqlName, type: 'SQL_SCRIPT'})
                        MERGE (sh)-[:INVOKES {executionType: 'SQL_SCRIPT', dynamicJob: true}]->(sql)
                        """,
                        shName=shell_resource_name, sqlName=sql_filename,
                    )

            sql_filenames.append(sql_filename)
            logger.debug(
                f"    [IG] Shell '{shell_resource_name}' -> SQL '{sql_filename}' "
                f"({'matched existing' if existing_sql else 'new resource'})"
            )
        return sql_filenames

    # ── procedure resource ─────────────────────────────────────────────────────

    def _create_procedure_resource_and_link(
        self,
        session,
        resource: ResourceNodeDef,
        proc_call: ProcedureCall,
        method_fqn: str,
    ):
        """
        Create a PROCEDURE/FUNCTION Resource with procedure detail properties, then
        link from the step-specific JavaMethod:
          JavaMethod -[:INVOKES {databaseType, confidence}]-> Resource
        """
        resource_type = "FUNCTION" if proc_call.is_function else "PROCEDURE"
        session.run(
            """
            MERGE (r:Resource {name: $name, type: $rtype})
            ON CREATE SET
                r.id           = $id,
                r.enabled      = true,
                r.databaseType = $dbType,
                r.schemaName   = $schemaName,
                r.packageName  = $packageName,
                r.dynamicJob   = true,
                r.foundInRepo  = false
            ON MATCH SET
                r.databaseType = COALESCE(r.databaseType, $dbType),
                r.schemaName   = COALESCE(r.schemaName, $schemaName),
                r.dynamicJob   = true
            """,
            name=resource.name,
            rtype=resource_type,
            id=resource.id,
            dbType=proc_call.database_type,
            schemaName=resource.schemaName,
            packageName=resource.packageName,
        )
        session.run(
            """
            MATCH (m:JavaMethod {fqn: $methodFqn})
            MATCH (r:Resource {name: $name, type: $rtype})
            MERGE (m)-[:INVOKES {
                databaseType: $dbType,
                confidence:   $confidence,
                dynamicJob:   true
            }]->(r)
            """,
            methodFqn=method_fqn,
            name=resource.name,
            rtype=resource_type,
            dbType=proc_call.database_type,
            confidence=proc_call.confidence,
        )

    # ── job-step structure ─────────────────────────────────────────────────────

    def _create_job_step_relationships(self, session, job_name: str, steps: Dict):
        ordered = sorted(steps.items(), key=lambda x: x[1]["order"])

        for step_name, _ in ordered:
            session.run(
                """
                MATCH (j:Job {name: $jobName})
                MATCH (s:Step {name: $stepName})
                MERGE (j)-[:CONTAINS]->(s)
                """,
                jobName=job_name, stepName=step_name,
            )

        if ordered:
            session.run(
                """
                MATCH (j:Job {name: $jobName})
                MATCH (s:Step {name: $stepName})
                MERGE (j)-[:ENTRY]->(s)
                """,
                jobName=job_name, stepName=ordered[0][0],
            )
            for i in range(len(ordered) - 1):
                session.run(
                    """
                    MATCH (src:Step {name: $srcName})
                    MATCH (dst:Step {name: $dstName})
                    MERGE (src)-[:PRECEDES {on: 'COMPLETED'}]->(dst)
                    """,
                    srcName=ordered[i][0], dstName=ordered[i + 1][0],
                )

    # ── per-step execute() method update ─────────────────────────────────────

    def _update_step_method_executions(
        self,
        session,
        step_ident: str,
        shell_execs: List[ShellScriptExecution],
        proc_calls: List[ProcedureCall],
    ):
        """Set this step's execute() shellExecutions and procedureCalls arrays."""
        shell_strs = [
            f"{se.execution_method or 'RESOLVED'}:{se.script_name}:{se.confidence}"
            for se in shell_execs if se.script_name
        ]
        proc_strs = [
            f"{pc.database_type}:{pc.procedure_name}:{pc.confidence}"
            for pc in proc_calls if pc.procedure_name
        ]
        session.run(
            """
            MATCH (m:JavaMethod {fqn: $fqn})
            SET m.shellExecutions     = $shellExecs,
                m.shellExecutionCount = $shellCount,
                m.procedureCalls      = $procCalls,
                m.procedureCallCount  = $procCount
            """,
            fqn=self._step_method_fqn(step_ident),
            shellExecs=shell_strs,
            shellCount=len(shell_strs),
            procCalls=proc_strs,
            procCount=len(proc_strs),
        )

    # ── public API ─────────────────────────────────────────────────────────────

    def load(self):
        """
        Parse the Excel file and write all dynamic-job IG nodes + relationships.
        Safe to call multiple times - all writes use MERGE (idempotent).
        """
        logger.info("=" * 80)
        logger.info("DYNAMIC JOB LOADER - Information Graph")
        logger.info("=" * 80)

        if not self.enabled:
            logger.info("  dynamic_jobs.enabled = false - skipping.")
            return

        if not Path(self.excel_file).exists():
            logger.error(f"  Excel file not found: {self.excel_file}")
            return

        raw_jobs = _parse_dynamic_jobs_excel(self.excel_file)

        total_shell = 0
        total_proc  = 0

        with self.driver.session(database=self.database) as session:
            for job_name, job_raw in raw_jobs.items():
                job_def = JobDef(
                    name=job_name,
                    id=job_raw["id"],
                    source_file=self.spring_config_path,
                    enabled=True,
                )
                logger.info(
                    f"    [IG] Job '{job_def.name}' (id={job_def.id}, "
                    f"{len(job_raw['steps'])} step(s))"
                )
                self._create_job(session, job_def)

                for step_name, step_raw in job_raw["steps"].items():
                    params     = step_raw.get("params", {})
                    step_order = step_raw.get("order", 1)

                    step_ident         = self._step_ident(step_name)
                    step_method_fqn    = self._step_method_fqn(step_ident)
                    step_has_shell     = "FILE" in params
                    step_has_procedure = "PROC_NAME" in params

                    # Ensure per-step Bean, JavaClass, JavaMethod
                    self._ensure_step_nodes(
                        session, step_name, step_has_shell, step_has_procedure
                    )

                    step_shell_execs: List[ShellScriptExecution] = []
                    step_proc_calls:  List[ProcedureCall] = []
                    step_sql_invocations: List[str] = []

                    # ── shell execution ──────────────────────────────────────
                    script_file = params.get("FILE", "")
                    if script_file:
                        script_dir         = params.get("DIR",  "")
                        exec_user          = params.get("USER", "")
                        script_type        = _detect_script_type(script_file)
                        script_path        = (
                            f"{script_dir.rstrip('/')}/{script_file}"
                            if script_dir else script_file
                        )
                        # PARAMS split by whitespace → stored as a list on Resource
                        raw_params         = params.get("PARAMS", "")
                        script_params_list = raw_params.split() if raw_params else []

                        sh_exec = ShellScriptExecution(
                            script_name=script_file,
                            method_fqn=step_method_fqn,
                            script_type=script_type,
                            execution_method="RESOLVED",
                            confidence="HIGH",
                        )
                        step_shell_execs.append(sh_exec)

                        shell_res = ResourceNodeDef(
                            id=f"RES_SHELL_{uuid.uuid4().hex[:8].upper()}",
                            name=script_file,
                            type="SHELL_SCRIPT",
                            enabled=True,
                            foundInRepo=False,
                            resourceLocation=script_path,
                        )
                        shell_existing_path = self._create_shell_resource_and_link(
                            session, shell_res, sh_exec,
                            script_params=script_params_list,
                            exec_user=exec_user,
                            method_fqn=step_method_fqn,
                        )
                        total_shell += 1

                        # Parse SQL invocations from shell script if file is in the IG
                        abs_shell_path = self._to_absolute_path(shell_existing_path) if shell_existing_path else None
                        if abs_shell_path:
                            try:
                                shell_content = Path(abs_shell_path).read_text(encoding='utf-8', errors='ignore')
                                sql_paths_found = self._extract_sql_invocations(shell_content)
                                if sql_paths_found:
                                    found_sql = self._process_sql_invocations(
                                        session, sql_paths_found, shell_existing_path, script_file
                                    )
                                    step_sql_invocations.extend(found_sql)
                                    logger.debug(
                                        f"    [IG] Step '{step_name}': "
                                        f"{len(found_sql)} SQL invocation(s) via shell"
                                    )
                            except Exception as e:
                                logger.debug(f"    [IG] Could not parse SQL from '{abs_shell_path}': {e}")

                    # ── procedure call ───────────────────────────────────────
                    proc_name = params.get("PROC_NAME", "")
                    if proc_name:
                        proc_schema  = params.get("PROC_SCHEMA",  "UNKNOWN")
                        proc_package = params.get("PROC_PACKAGE", "")
                        pc = ProcedureCall(
                            procedure_name=proc_name.upper(),
                            database_type="ORACLE",
                            method_fqn=step_method_fqn,
                            schema_name=proc_schema.upper(),
                            package_name=proc_package.upper() if proc_package else None,
                            confidence="HIGH",
                        )
                        step_proc_calls.append(pc)

                        proc_res = ResourceNodeDef(
                            id=f"RES_PROC_{uuid.uuid4().hex[:8].upper()}",
                            name=pc.procedure_name,
                            type="FUNCTION" if pc.is_function else "PROCEDURE",
                            enabled=True,
                            foundInRepo=False,
                            schemaName=pc.schema_name or "",
                            packageName=pc.package_name or "",
                        )
                        self._create_procedure_resource_and_link(
                            session, proc_res, pc,
                            method_fqn=step_method_fqn,
                        )
                        total_proc += 1

                    # ── step node (after resources so links can be created) ──
                    step_def = StepDef(
                        name=step_name,
                        step_kind="TASKLET",
                        impl_bean=self._step_bean_id(step_ident),
                        class_name=self._step_fqn(step_ident),
                        class_source_path=self.tasklet_path,
                    )
                    self._create_step(
                        session, step_def, step_order,
                        step_shell_execs, step_proc_calls,
                        step_sql_invocations,
                    )

                    # Update this step's execute() with its own execution summary
                    self._update_step_method_executions(
                        session, step_ident, step_shell_execs, step_proc_calls
                    )

                self._create_job_step_relationships(session, job_name, job_raw["steps"])

        logger.info(
            f"  [IG] Dynamic jobs loaded: {len(raw_jobs)} job(s), "
            f"{total_shell} shell resource(s), "
            f"{total_proc} procedure resource(s)."
        )
        logger.info("=" * 80)


# ── standalone entry point ─────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - [%(pathname)s:%(lineno)d %(funcName)s] - %(message)s",
    )
    _config = os.getenv("KG_CONFIG_FILE", "config/information_graph_config.yaml")
    loader  = DynamicIGLoader(_config)
    try:
        loader.load()
    finally:
        loader.close()
