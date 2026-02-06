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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
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
                    logger.info(f"  ✓ {constraint.split('IF NOT EXISTS')[0].strip()}")
                except Exception as e:
                    logger.warning(f"  ⚠ Constraint already exists or error: {e}")
            
            for index in indexes:
                try:
                    session.run(index)
                    logger.info(f"  ✓ {index.split('IF NOT EXISTS')[0].strip()}")
                except Exception as e:
                    logger.warning(f"  ⚠ Index already exists or error: {e}")
        
        logger.info("✓ Constraints and indexes created")
    
    # ========================================================================
    # INSTANCE DATA LOADING
    # ========================================================================
    
    def load_instance_data(self, excel_file: str):
        """Load all instance-level data from Excel"""
        logger.info(f"Loading instance data from {excel_file}...")
        
        if not Path(excel_file).exists():
            raise FileNotFoundError(f"Excel file not found: {excel_file}")
        
        try:
            self._load_job_group_executions(excel_file)
            # Load in sequence
            self._load_jobcontext_executions(excel_file)
            # Load resource events if they exist
            self._load_resource_events(excel_file)
            
        except Exception as e:
            logger.warning(f"No resource events to load or error: {e}")
        
        logger.info("✓ All instance data loaded")
    
    def _load_job_group_executions(self, excel_file):
        """Load JobGroupExecution nodes"""
        df = pd.read_excel(excel_file, 'JobGroupExecutions')
        logger.info(f"Loading {len(df)} JobGroupExecutions...")
        
        with self.driver.session(database=self.database) as session:
            for _, row in df.iterrows():
                data = row.to_dict()
                data = {k: v for k, v in data.items() if pd.notna(v)}
                session.execute_write(self._create_job_group_execution, data)
        
        logger.info(f"✓ Loaded {len(df)} JobGroupExecutions")
    
    @staticmethod
    def _create_job_group_execution(tx, data: Dict):
        """Create JobGroupExecution and link to JobContext, Job, and JobGroupExecution"""
        query = """
        MERGE (jge:JobGroupExecution {id: $id})
        SET jge.businessDate = date($businessDate),
            jge.startTime = time($startTime)
        WITH jge
        MATCH (jg:JobGroup {id: $jobGroupId})
        MERGE (jge)-[:EXECUTES_JOB_GROUP]->(jg)
        """
        if 'tagId' in data:
            tagIds = data.get('tagId', None)
            for tagId in tagIds.strip('[]').split(","):
                tagIdStrip = tagId.strip()
                query += f"""
                    WITH jge, jg
                    MATCH (tg:Tag {{id: "{tagIdStrip}"}})
                    MERGE (jge)-[:HAS_TAG]->(tg)
                """
                #query += " RETURN jge, jg, tg"
                tx.run(query, **data)
        else:
            query += " RETURN jge, jg"
            tx.run(query, **data)
        
    def _load_jobcontext_executions(self, excel_file):
        """Load JobContextExecution nodes"""
        df = pd.read_excel(excel_file, 'JobContextExecutions')
        logger.info(f"Loading {len(df)} JobContextExecutions...")
        
        with self.driver.session(database=self.database) as session:
            for _, row in df.iterrows():
                data = row.to_dict()
                data = {k: v for k, v in data.items() if pd.notna(v)}
                session.execute_write(self._create_jobcontext_execution, data)
        
        logger.info(f"✓ Loaded {len(df)} JobContextExecutions")
    
    @staticmethod
    def _create_jobcontext_execution(tx, data: Dict):
        """Create JobContextExecution and link to JobContext, Job, and JobGroupExecution"""
        query = """
        MERGE (jce:JobContextExecution {id: $id})
        SET jce.businessDate = date($businessDate),
            jce.startTime = time($startTime),
            jce.endTime = time($endTime),
            jce.durationMs = $durationMs,
            jce.volume = $volume,
            jce.status = $status,            
            jce.exitCode = $exitCode,
            jce.exitMessage = $exitMessage,
            jce.retryCount = $retryCount,
            jce.expectedStartTime = time($expectedStartTime)
        WITH jce
        MATCH (jc:ScheduleInstanceContext {id: $jobContextId})
        MERGE (jce)-[:EXECUTES_CONTEXT]->(jc)
        WITH jce, jc
        MATCH (jc)-[:FOR_JOB]->(j:Job)
        MERGE (jce)-[:EXECUTES_JOB]->(j)
        WITH jce,jc
        MATCH (jge:JobGroupExecution {id: $jobGroupExecId})
        MERGE (jge)-[:EXECUTES_JOB_CONTEXT]->(jce)
        RETURN jce
        """
        
        tx.run(query, **data)
    
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
        
        logger.info(f"✓ Loaded {len(df)} ResourceAvailabilityEvents")
    
    @staticmethod
    def _create_resource_event(tx, data: Dict):
        """Create ResourceAvailabilityEvent and link to Resource and JobContext"""
        query = """
        MERGE (rae:ResourceAvailabilityEvent {id: $id})
        SET rae.businessDate = date($businessDate),
            rae.sizemb = $sizemb,
            rae.checksum = $checksum,
            rae.detectedBy = $detectedBy
        """
        
        if 'availabilityTime' in data:
            query += ", rae.availabilityTime = time($availabilityTime)"
        
        query += """
        WITH rae
        MATCH (r:Resource {id: $resourceId})
        MERGE (rae)-[:FOR_RESOURCE]->(r)
        RETURN rae
        """
        
        tx.run(query, **data)

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
        logger.info("✓ Instance data cleared")
    
    def compute_cpm_for_jobgroup_execution(self, excel_file: str, analyzer: ExecutionCPMAnalyzer):
        df = pd.read_excel(excel_file, 'JobGroupExecutions')
        logger.info(f"Loading {len(df)} JobGroupExecutions...")
        for _, row in df.iterrows():
            data = row.to_dict()
            data = {k: v for k, v in data.items() if pd.notna(v)}
            if 'id' in data:
                jobgroup_execution_id = data.get('id', '')
                res = analyzer.compute_for_jobgroup_execution(jobgroup_execution_id, persist=True)
                print(f"\n=== CPM Summary for {jobgroup_execution_id} ===")
                print("SLA(ms):", res.group_sla_ms)
                print("Completion(ms):", res.completion_ms)
                print("Total Buffer(ms):", res.total_buffer_ms)
                print("Longest Path:", " -> ".join(res.longest_path))   


def main():
    """Main execution function"""
    
    load_dotenv()
    config_path = os.getenv("KG_CONFIG_FILE")
    
    print("=" * 80)
    print("Spring Batch Instance Data - Neo4j Direct Loader V2")
    print("=" * 80)
    print()
    
    try:
        # Create loader using config file
        with Neo4jInstanceLoaderV2(config_path=config_path) as loader:
            
            # Determine Excel file path (command line arg overrides config)
            excel_file = loader.instance_excel_path
            
            
            # Create constraints and indexes
            #print("📐 Creating constraints and indexes...")
            #loader.create_instance_constraints_and_indexes()
            #print()
            
            # Load instance data
            print(f"📦 Loading instance data from {excel_file}...")
            loader.load_instance_data(excel_file)
            print()
            analyzer = ExecutionCPMAnalyzer(loader.driver, database=loader.database)
            loader.compute_cpm_for_jobgroup_execution(excel_file, analyzer)
            print("=" * 80)
            print("✅ LOADING COMPLETE!")
            print("=" * 80)
            print()
            print("🎉 Instance data is now in Neo4j!")
            print()
    
    except Exception as e:
        logger.error(f"Error during loading: {str(e)}", exc_info=True)
        raise


if __name__ == "__main__":
    main()
