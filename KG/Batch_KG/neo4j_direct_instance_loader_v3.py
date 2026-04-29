"""
Spring Batch Instance Data - Neo4j Direct Loader V2
===================================================
Loads instance-level execution data into Neo4j with JobContext support.

New architecture:
- JobContextExecution -[:EXECUTES_CONTEXT]-> ScheduleInstanceContext -[:FOR_JOB]-> Job
- StepExecution -[:EXECUTES]-> Step

Features:
- Direct Neo4j connection via official driver
- Batch inserts for performance
- Transaction management
- Support for JobContext-based dependencies

Author: Rohit Khanna
Date: 2025-12-01
"""

import pandas as pd
from neo4j import GraphDatabase
from typing import Dict
import logging
from pathlib import Path
import yaml
import os
from dotenv import load_dotenv
from execution_cpm_analyzer_v3 import ExecutionCPMAnalyzer
from classes.KGNodeDefs import (
    JobGroupExecutionNodeDef, JobContextExecutionNodeDef, ResourceAvailabilityEventNodeDef
)


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - [%(pathname)s:%(lineno)d %(funcName)s] - %(message)s"
)
logger = logging.getLogger(__name__)


class Neo4jInstanceLoaderV2:
    """Load Spring Batch instance data into Neo4j with JobContext support"""
    
    def __init__(self, config_path: str = None):
        """
        Initialize Neo4j connection
        
        Args:
            config_path: Path to YAML config file (preferred method)
        """
        # Load from config file if provided
        if config_path:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            
            neo4j_config = config['neo4j']
            uri = neo4j_config['uri']
            user = neo4j_config['user']
            password = neo4j_config['password']
            database = neo4j_config['database_kg']
            self.instance_excel_path = config.get('instance_data', {}).get('excel_file', '')
            logger.info(f"Loaded configuration from {config_path}")
        
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.database = database
        # In-memory cache of JobGroupExecution IDs already created/confirmed this session.
        # Key: "{jobGroupId}_{businessDate}" — avoids redundant JobGroup reverse-lookups
        # and write attempts for the same JobGroupExecution across multiple JobContextExecution rows.
        self._jge_cache: set = set()
        logger.info(f"Connected to Neo4j at {uri} (Database: {database})")
        
    def close(self):
        """Close Neo4j connection"""
        self.driver.close()
        logger.info("Neo4j connection closed")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    # ========================================================================
    # CONSTRAINT & INDEX CREATION
    # ========================================================================
    
    def create_instance_constraints_and_indexes(self):
        """Create constraints and indexes for instance layer"""
        logger.info("Creating instance layer constraints and indexes...")
        
        constraints = [
            "CREATE CONSTRAINT jobgroup_exec_id IF NOT EXISTS FOR (n:JobGroupExecution) REQUIRE n.execId IS UNIQUE",
            "CREATE CONSTRAINT jobcontext_exec_id IF NOT EXISTS FOR (n:JobContextExecution) REQUIRE n.execId IS UNIQUE",
            "CREATE CONSTRAINT step_exec_id IF NOT EXISTS FOR (n:StepExecution) REQUIRE n.execId IS UNIQUE",
            "CREATE CONSTRAINT action_exec_id IF NOT EXISTS FOR (n:StepActionExecution) REQUIRE n.execId IS UNIQUE",
            "CREATE CONSTRAINT resource_event_id IF NOT EXISTS FOR (n:ResourceAvailabilityEvent) REQUIRE n.id IS UNIQUE",
        ]
        
        indexes = [
            "CREATE INDEX jg_exec_status_idx IF NOT EXISTS FOR (n:JobGroupExecution) ON (n.status)",
            "CREATE INDEX jctx_exec_status_idx IF NOT EXISTS FOR (n:JobContextExecution) ON (n.status)",
            "CREATE INDEX step_exec_status_idx IF NOT EXISTS FOR (n:StepExecution) ON (n.status)",
            "CREATE INDEX action_exec_status_idx IF NOT EXISTS FOR (n:StepActionExecution) ON (n.status)",
            "CREATE INDEX jg_exec_time_idx IF NOT EXISTS FOR (n:JobGroupExecution) ON (n.startTime)",
            "CREATE INDEX jctx_exec_time_idx IF NOT EXISTS FOR (n:JobContextExecution) ON (n.startTime)",
        ]
        
        with self.driver.session(database=self.database) as session:
            for constraint in constraints:
                try:
                    session.run(constraint)
                    logger.info(f"   {constraint.split('IF NOT EXISTS')[0].strip()}")
                except Exception as e:
                    logger.warning(f"  ⚠ Constraint already exists or error: {e}")
            
            for index in indexes:
                try:
                    session.run(index)
                    logger.info(f"   {index.split('IF NOT EXISTS')[0].strip()}")
                except Exception as e:
                    logger.warning(f"  ⚠ Index already exists or error: {e}")
        
        logger.info(" Constraints and indexes created")
    
    # ========================================================================
    # INSTANCE DATA LOADING
    # ========================================================================
    
    def load_instance_data(self, excel_file: str):
        """Load all instance-level data from Excel"""
        logger.info(f"Loading instance data from {excel_file}...")
        
        if not Path(excel_file).exists():
            raise FileNotFoundError(f"Excel file not found: {excel_file}")
        
        

        # Load resource events if the sheet exists (optional)
        try:
            self._load_job_group_executions(excel_file)
            #self._load_resource_events(excel_file)
        except Exception as e:
            logger.warning(f"Failure in loading instance data: {e}")

        logger.info(" All instance data loaded")
    
    def _load_job_group_executions(self, excel_file):
        """Load JobGroupExecution nodes"""
        df = pd.read_excel(excel_file, 'JobContextExecutions')
        logger.info(f"Loading {len(df)} JobContextExecutions...")
        
        with self.driver.session(database=self.database) as session:
            for _, row in df.iterrows():
                data = row.to_dict()
                data = {k: v for k, v in data.items() if pd.notna(v)}
                session.execute_write(self._create_job_group_execution, data)
                if 'jobGroupExecId' in data:
                    logger.info(f"Creating JobContextExecution for jobGroupExecId='{data['jobGroupExecId']}'...")
                    session.execute_write(self._create_jobcontext_execution, data)
                else:
                    logger.error(f" Missing jobGroupExecId for row with jobName='{data.get('jobName', '')}' and startTime='{data.get('startTime', '')}' — cannot create JobContextExecution without it")
        
        logger.info(f" Loaded {len(df)} JobContextExecutions")
    
    def _create_job_group_execution(self, tx, data: Dict):
        """Create JobGroupExecution derived from JobContextExecution row data.

        Derives the JobGroupExecution from two fields:
          - jobName   : used to reverse-lookup the owning JobGroup via HAS_JOB
          - startTime : datetime containing both the businessDate and the start time

        JobGroupExecution.id is constructed as "{jobGroupId}_{businessDate}".

        Skips creation and logs a warning when:
          - jobName or startTime are missing
          - no JobGroup is found for the given jobName
          - more than one JobGroup is found (ambiguous mapping)
          - the same id was already created this session (cache hit)
        """
        job_name = str(data.get('jobName', data.get('JobName', ''))).strip()
        start_time_raw = data.get('startTime', data.get('StartTime', ''))
        logger.info(f"Processing JobContextExecution for jobName='{job_name}' with startTime='{start_time_raw}' to create JobGroupExecution...")
        if not start_time_raw:
            logger.warning(
                f"Skipping JobGroupExecution: missing startTime "
                f"(jobName={job_name!r}, startTime={start_time_raw!r})"
            )
            return

        # Parse the datetime value that pandas delivers from Excel
        start_dt = pd.Timestamp(start_time_raw)
        start_time_str = start_dt.strftime('%H:%M:%S')
        # business_date default: derived from startTime; overridden if jge_id carries it
        business_date = start_dt.strftime('%Y-%m-%d')

        # ── Derive job_group_id and jge_id — three strategies ────────────────────────
        if 'jobGroupId' in data:
            # Excel supplies the JobGroup ID directly — combine with business_date from startTime
            job_group_id = str(data['jobGroupId']).strip()
            jge_id = f"{job_group_id}_{business_date}"
            data['jobGroupExecId'] = jge_id
        elif 'jobContextId' in data:
            # Use ScheduleInstanceContext → FOR_GROUP → JobGroup
            job_context_id_raw = str(data['jobContextId']).strip()
            result = tx.run(
                """
                MATCH (sic:ScheduleInstanceContext {id: $jobContextId})-[:FOR_GROUP]->(jg:JobGroup)
                RETURN jg.id AS jobGroupId
                """,
                jobContextId=job_context_id_raw
            )
            records = result.data()
            if len(records) == 0:
                logger.warning(
                    f"No JobGroup found via ScheduleInstanceContext id='{job_context_id_raw}' "
                    f"— skipping JobGroupExecution for businessDate={business_date}"
                )
                return
            if len(records) > 1:
                jg_ids = [r['jobGroupId'] for r in records]
                logger.warning(
                    f"Ambiguous JobGroup lookup via ScheduleInstanceContext id='{job_context_id_raw}': "
                    f"found {len(records)} JobGroups {jg_ids} "
                    f"— skipping JobGroupExecution for businessDate={business_date}"
                )
                return
            job_group_id = records[0]['jobGroupId']
            jge_id = f"{job_group_id}_{business_date}"
            data['jobGroupExecId'] = jge_id
        else:
            # Fallback: reverse-lookup via Job → JobGroup
            if not job_name:
                logger.warning(
                    f"Skipping JobGroupExecution: missing jobName, jobGroupExecId, and jobContextId "
                    f"(startTime={start_time_raw!r})"
                )
                return
            result = tx.run(
                """
                MATCH (jg:JobGroup)-[:HAS_JOB]->(j:Job {id: $jobName})
                RETURN jg.id AS jobGroupId
                """,
                jobName=job_name
            )
            records = result.data()
            if len(records) == 0:
                logger.warning(
                    f"No JobGroup found for jobName='{job_name}' "
                    f"— skipping JobGroupExecution for businessDate={business_date}"
                )
                return
            if len(records) > 1:
                jg_ids = [r['jobGroupId'] for r in records]
                logger.warning(
                    f"Ambiguous JobGroup lookup for jobName='{job_name}': "
                    f"found {len(records)} JobGroups {jg_ids} "
                    f"— skipping JobGroupExecution for businessDate={business_date} "
                    f"to avoid incorrect associations"
                )
                return
            job_group_id = records[0]['jobGroupId']
            jge_id = f"{job_group_id}_{business_date}"
            data['jobGroupExecId'] = jge_id
        # ── End: derive job_group_id and jge_id ──────────────────────────────────────
        logger.info(f"Adding jobGroupExecId in the data dict for JobContextExecution: {jge_id}")
        # Cache check — this combination was already created earlier this session
        if jge_id in self._jge_cache:
            logger.debug(f"JobGroupExecution '{jge_id}' already in cache — skipping")
            return

        node = JobGroupExecutionNodeDef(
            id=jge_id,
            startTime=start_time_str,
            businessDate=business_date
        )

        query = """
        MERGE (jge:JobGroupExecution {id: $id})
        SET jge.businessDate = date($businessDate),
            jge.startTime = time($startTime)
        WITH jge
        MATCH (jg:JobGroup {id: $jobGroupId})
        MERGE (jge)-[:EXECUTES_JOB_GROUP]->(jg)
        RETURN jge, jg
        """
        tx.run(query, id=node.id, businessDate=node.businessDate,
               startTime=node.startTime, jobGroupId=job_group_id)
        logger.info(f"Created JobGroupExecution with id='{node.id}' for JobGroup '{job_group_id}' and businessDate '{business_date}'")
        # tagId is not yet present in JobContextExecutions but preserved for when it appears
        if 'tagId' in data:
            tagIds = data.get('tagId', None)
            for tagId in tagIds.strip('[]').split(","):
                tagIdStrip = tagId.strip()
                tag_query = """
                    MATCH (jge:JobGroupExecution {id: $id})
                    MATCH (tg:Tag {id: $tagId})
                    MERGE (jge)-[:HAS_TAG]->(tg)
                """
                tx.run(tag_query, id=node.id, tagId=tagIdStrip)

        self._jge_cache.add(jge_id)
        logger.info(f"Added JobGroupExecution '{jge_id}' to cache")
    @staticmethod
    def _create_jobcontext_execution(tx, data: Dict):
        """Create JobContextExecution and link to JobContext, Job, and JobGroupExecution.

        jobContextId is derived by reverse-lookup rather than read from Excel:
          - jobGroupId  : extracted from jobGroupExecId by stripping the trailing "_YYYY-MM-DD"
          - jobName     : direct field from Excel
          Finds the ScheduleInstanceContext that has BOTH:
            (sic)-[:FOR_GROUP]->(JobGroup {id: jobGroupId})
            (sic)-[:FOR_JOB]  ->(Job     {id: jobName})
          Skips if 0 or >1 matches (not found / ambiguous).
        """
        jge_id = data.get('jobGroupExecId', '')
        job_name = str(data.get('jobName', data.get('JobName', ''))).strip()

        if not jge_id or not job_name:
            logger.warning(
                f"Skipping JobContextExecution: missing jobGroupExecId or jobName "
                f"(jobGroupExecId={jge_id!r}, jobName={job_name!r})"
            )
            return

        # jobGroupExecId format: "{jobGroupId}_{YYYY-MM-DD}" — date is always last 10 chars
        job_group_id = jge_id[:-11]  # strip trailing "_YYYY-MM-DD" (11 chars)

        # If jobContextId is already provided (from Excel or injected via the jobContextId
        # path in _create_job_group_execution), use it directly — no graph query needed
        if 'jobContextId' in data:
            job_context_id = str(data['jobContextId']).strip()
        else:
            # Reverse-lookup: ScheduleInstanceContext linked to BOTH the JobGroup and the Job
            result = tx.run(
                """
                MATCH (sic:ScheduleInstanceContext)-[:FOR_GROUP]->(jg:JobGroup {id: $jobGroupId})
                MATCH (sic)-[:FOR_JOB]->(j:Job {id: $jobName})
                RETURN sic.id AS jobContextId
                """,
                jobGroupId=job_group_id,
                jobName=job_name
            )
            records = result.data()

            if len(records) == 0:
                logger.warning(
                    f"No ScheduleInstanceContext found for jobName='{job_name}' "
                    f"and jobGroupId='{job_group_id}' — skipping JobContextExecution"
                )
                return

            if len(records) > 1:
                sic_ids = [r['jobContextId'] for r in records]
                logger.warning(
                    f"Ambiguous ScheduleInstanceContext lookup for jobName='{job_name}' "
                    f"and jobGroupId='{job_group_id}': found {len(records)} entries {sic_ids} "
                    f"— skipping JobContextExecution to avoid incorrect associations"
                )
                return

            job_context_id = records[0]['jobContextId']

        # businessDate: derive from jobGroupExecId (last 10 chars = YYYY-MM-DD)
        business_date = jge_id[-10:]

        # startTime / endTime: now arrive as full datetime "YYYY-MM-DD H:MM:SS AM/PM".
        # Extract the time-only portion as HH:MM:SS (24-hour) for Neo4j time().
        def _extract_time(raw) -> str:
            """Parse any time/datetime string and return HH:MM:SS (24-hour)."""
            try:
                return pd.Timestamp(str(raw)).strftime('%H:%M:%S')
            except Exception:
                return ''

        # expectedStartTime: may arrive without seconds ("6:00 AM" or "6:00:00 AM").
        # Normalise to HH:MM:SS so Neo4j time() never chokes on a missing seconds part.
        def _extract_time_with_seconds_fallback(raw) -> str:
            raw_str = str(raw).strip()
            try:
                return pd.Timestamp(raw_str).strftime('%H:%M:%S')
            except Exception:
                return ''

        start_time_str = _extract_time(data.get('startTime', ''))
        end_time_str   = _extract_time(data.get('endTime', ''))
        expected_start = _extract_time_with_seconds_fallback(data.get('expectedStartTime', ''))

        # durationMs: compute from the full startTime/endTime datetimes so we are not
        # dependent on the Excel 'duration' column whose format changed to m.ss notation.
        try:
            start_ts = pd.Timestamp(str(data.get('startTime', '')))
            end_ts   = pd.Timestamp(str(data.get('endTime', '')))
            duration_ms = int((end_ts - start_ts).total_seconds() * 1000)
            if duration_ms < 0:
                duration_ms = 0
        except Exception:
            duration_ms = 0

        node = JobContextExecutionNodeDef(
            id=str(data.get('id', '')),
            status=str(data.get('status', '')),
            startTime=start_time_str,
            endTime=end_time_str,
            businessDate=business_date,
            durationMs=duration_ms,
            exitCode=str(data.get('exitCode', '')),
            exitMessage=str(data.get('exitMessage', '')),
            expectedStartTime=expected_start
        )
        # Build SET clause — only convert non-empty strings to time()
        time_sets = []
        if start_time_str:
            time_sets.append("jce.startTime = time($startTime)")
        if end_time_str:
            time_sets.append("jce.endTime = time($endTime)")
        if expected_start:
            time_sets.append("jce.expectedStartTime = time($expectedStartTime)")
        time_set_clause = ("\n            " + ",\n            ".join(time_sets) + ",") if time_sets else ""

        logger.info(f"Creating JobContextExecution with id='{node.id}' linked to jobContextId='{job_context_id}' and jobGroupExecId='{jge_id}'...")
        query = f"""
        MERGE (jce:JobContextExecution {{id: $id}})
        SET jce.businessDate = date($businessDate),{time_set_clause}
            jce.durationMs = $durationMs,
            jce.status = $status,
            jce.exitCode = $exitCode,
            jce.exitMessage = $exitMessage
        WITH jce
        MATCH (jc:ScheduleInstanceContext {id: $jobContextId})
        MERGE (jce)-[:EXECUTES_CONTEXT]->(jc)
        WITH jce, jc
        MATCH (jc)-[:FOR_JOB]->(j:Job)
        MERGE (jce)-[:EXECUTES_JOB]->(j)
        WITH jce, jc
        MATCH (jge:JobGroupExecution {id: $jobGroupExecId})
        MERGE (jge)-[:EXECUTES_JOB_CONTEXT]->(jce)
        RETURN jce
        """
        tx.run(query,
               id=node.id, businessDate=node.businessDate, startTime=node.startTime,
               endTime=node.endTime, durationMs=node.durationMs,
               status=node.status, exitCode=node.exitCode, exitMessage=node.exitMessage,
               expectedStartTime=node.expectedStartTime,
               jobContextId=job_context_id, jobGroupExecId=jge_id)
        logger.info(f"Created JobContextExecution with id='{node.id}' linked to ScheduleInstanceContext '{job_context_id}' and JobGroupExecution '{jge_id}'")
    
    def _load_resource_events(self, excel_file):
        """Load ResourceAvailabilityEvent nodes"""
        df = pd.read_excel(excel_file, 'ResourceAvailabilityEvents')
        logger.info(f"Loading {len(df)} ResourceAvailabilityEvents...")
        
        with self.driver.session(database=self.database) as session:
            for _, row in df.iterrows():
                data = row.to_dict()
                data = {k: v for k, v in data.items() if pd.notna(v)}
                session.execute_write(self._create_resource_event, data)
                session.execute_write(self._associate_resource_event_with_jobgroup, data)
                session.execute_write(self._associate_resource_event_with_job, data)
        
        logger.info(f" Loaded {len(df)} ResourceAvailabilityEvents")
    
    @staticmethod
    def _create_resource_event(tx, data: Dict):
        """Create ResourceAvailabilityEvent and link to Resource and JobContext"""
        node = ResourceAvailabilityEventNodeDef(
            id=str(data.get('id', '')),
            businessDate=str(data.get('businessDate', '')),
            sizemb=float(data.get('sizemb', 0.0)),
            checksum=str(data.get('checksum', '')),
            detectedBy=str(data.get('detectedBy', '')),
            availabilityTime=str(data.get('availabilityTime', ''))
        )
        query = """
        MERGE (rae:ResourceAvailabilityEvent {id: $id})
        SET rae.businessDate = date($businessDate),
            rae.sizemb = $sizemb,
            rae.checksum = $checksum,
            rae.detectedBy = $detectedBy
        """
        if node.availabilityTime:
            query += ", rae.availabilityTime = time($availabilityTime)"
        query += """
        WITH rae
        MATCH (r:Resource {id: $resourceId})
        MERGE (rae)-[:FOR_RESOURCE]->(r)
        RETURN rae
        """
        tx.run(query, id=node.id, businessDate=node.businessDate, sizemb=node.sizemb,
               checksum=node.checksum, detectedBy=node.detectedBy,
               availabilityTime=node.availabilityTime, resourceId=data.get('resourceId'))

    @staticmethod
    def _associate_resource_event_with_jobgroup(tx, data: Dict):
        """Create ResourceAvailabilityEvent and link to Resource and JobContext"""
        
        query = """
        MATCH (rae:ResourceAvailabilityEvent {id: $id})
        MATCH (rae:ResourceAvailabilityEvent)-[:FOR_RESOURCE]->(r:Resource)
        MATCH (jg:JobGroup)-[:Require_Resource]->(r)
        MATCH (jge:JobGroupExecution)-[:EXECUTES_JOB_GROUP]->(jg)
        WHERE date(jge.businessDate) =  date(rae.businessDate)
        MERGE (rae)-[:FOR_RUN]->(jge)
        WITH rae,jge
        WHERE time(jge.startTime) < time(rae.availabilityTime)
        MERGE (rae)-[:IMPACTED]->(jge)
        RETURN rae, jge
        """
        
        tx.run(query, **data)

        
    @staticmethod
    def _associate_resource_event_with_job(tx, data: Dict):
        """Create ResourceAvailabilityEvent and link to Resource and JobContext"""
        query = """
        MATCH (rae:ResourceAvailabilityEvent {id: $id})
        MATCH (rae:ResourceAvailabilityEvent)-[:FOR_RESOURCE]->(r:Resource)
        MATCH (sic:ScheduleInstanceContext)-[:Require_Resource]->(r)
        MATCH (jce:JobContextExecution)-[:EXECUTES_CONTEXT]->(sic)
        WHERE date(jce.businessDate) =  date(rae.businessDate)
        MERGE (rae)-[:FOR_RUN]->(jce)
        WITH rae,jce
        WHERE time(jce.expectedStartTime) < time(rae.availabilityTime)
        MERGE (rae)-[:IMPACTED]->(jce)
        RETURN rae, jce
        """
        tx.run(query, **data)
    
    # ========================================================================
    # UTILITY METHODS
    # ========================================================================
    
    def clear_instance_data(self):
        """Clear only instance layer nodes (keep class layer)"""
        logger.warning("Clearing instance layer data...")
        with self.driver.session(database=self.database) as session:
            session.run("""
                MATCH (n)
                WHERE n:JobGroupExecution OR 
                      n:JobContextExecution OR 
                      n:StepExecution OR 
                      n:ResourceAvailabilityEvent
                DETACH DELETE n
            """)
        logger.info(" Instance data cleared")
    
    def compute_cpm_for_jobgroup_execution(self, analyzer: ExecutionCPMAnalyzer):
        """Compute CPM for every JobGroupExecution currently in the KG.

        JobGroupExecution IDs are fetched directly from Neo4j — the 'JobGroupExecutions'
        Excel tab no longer exists; IDs are generated dynamically during instance loading.
        """
        with self.driver.session(database=self.database) as session:
            result = session.run(
                "MATCH (jge:JobGroupExecution) RETURN jge.id AS id ORDER BY jge.id"
            )
            jge_ids = [record["id"] for record in result]

        logger.info(f"Computing CPM for {len(jge_ids)} JobGroupExecution(s) from KG...")

        for jobgroup_execution_id in jge_ids:
            try:
                res = analyzer.compute_for_jobgroup_execution(jobgroup_execution_id, persist=True)
                logger.info(f"\n=== CPM Summary for {jobgroup_execution_id} ===")
                logger.info(f"  SLA(ms):        {res.group_sla_ms}")
                logger.info(f"  Completion(ms): {res.completion_ms}")
                logger.info(f"  Total Buffer(ms): {res.total_buffer_ms}")
                logger.info(f"  Longest Path:   {' -> '.join(res.longest_path)}")
            except Exception as e:
                logger.warning(f"  CPM skipped for '{jobgroup_execution_id}': {e}")   


def main():
    """Main execution function"""
    
    load_dotenv()
    config_path = os.getenv("KG_CONFIG_FILE")
    
    logger.info("=" * 80)
    logger.info("Spring Batch Instance Data - Neo4j Direct Loader V2")
    logger.info("=" * 80)
    
    try:
        # Create loader using config file
        with Neo4jInstanceLoaderV2(config_path=config_path) as loader:
            
            # Determine Excel file path (command line arg overrides config)
            excel_file = loader.instance_excel_path
            
            
            # Create constraints and indexes
            #logger.info("📐 Creating constraints and indexes...")
            #loader.create_instance_constraints_and_indexes()
            
            # Load instance data
            logger.info(f" Loading instance data from {excel_file}...")
            loader.load_instance_data(excel_file)
            analyzer = ExecutionCPMAnalyzer(loader.driver, database=loader.database)
            loader.compute_cpm_for_jobgroup_execution(analyzer)
            logger.info("=" * 80)
            logger.info(" LOADING COMPLETE!")
            logger.info("=" * 80)
            logger.info("🎉 Instance data is now in Neo4j!")
    
    except Exception as e:
        logger.error(f"Error during loading: {str(e)}", exc_info=True)
        raise


if __name__ == "__main__":
    main()
