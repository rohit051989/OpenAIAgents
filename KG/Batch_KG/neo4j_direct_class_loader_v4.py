"""
Spring Batch Knowledge Graph - Neo4j Direct Loader
===================================================
This script reads Excel files and directly inserts data into Neo4j
(similar to RDBMS insert statements - no Cypher file generation)

Features:
- Direct Neo4j connection via official driver
- Batch inserts for performance
- Transaction management
- Error handling and rollback
- Progress tracking
- Both class and instance level loading

Author: Rohit Khanna
Date: 2025-01-03
"""

import pandas as pd
from neo4j import GraphDatabase
from typing import Dict, List, Tuple
import logging
import yaml
import os
from dotenv import load_dotenv
from cpm_analyzer_v1 import CPMAnalyzer
from classes.DataClasses import JobDef
from classes.KGNodeDefs import (
    JobGroupNodeDef, TagNodeDef, ScheduleInstanceContextNodeDef,
    SLANodeDef, CalendarNodeDef, HolidayNodeDef, ResourceNodeDef
)


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - [%(pathname)s:%(lineno)d %(funcName)s] - %(message)s"
)
logger = logging.getLogger(__name__)


class Neo4jLoader:
    """Load Spring Batch data from Excel directly into Neo4j"""
    
    def __init__(self, config_path: str = None,
                 uri: str = None, 
                 user: str = None, 
                 password: str = None,
                 database: str = None,
                 info_database: str = None):
        """
        Initialize Neo4j connection
        
        Args:
            config_path: Path to YAML config file (preferred method)
            uri: Neo4j connection URI (fallback if config_path not provided)
            user: Username (fallback)
            password: Password (fallback)
            database: Target database for knowledge graph (fallback)
            info_database: Source database for information graph queries (fallback)
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
            info_database = neo4j_config['database_ig']
            logger.info(f"Loaded configuration from {config_path}")
        else:
            # Use provided parameters or defaults
            uri = uri or "bolt://localhost:7687"
            user = user or "neo4j"
            password = password or "password"
            database = database or "neo4j"
            info_database = info_database or "informationgraph"
        
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.database = database
        self.info_database = info_database
        logger.info(f"Connected to Neo4j at {uri} (KG: {database}, Info: {info_database})")
        
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
    
    def create_constraints_and_indexes(self):
        """Create all necessary constraints and indexes"""
        logger.info("Creating constraints and indexes...")
        
        constraints = [
            # Class layer
            "CREATE CONSTRAINT jobgroup_id IF NOT EXISTS FOR (n:JobGroup) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT job_id IF NOT EXISTS FOR (n:Job) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT step_id IF NOT EXISTS FOR (n:Step) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT sic_id IF NOT EXISTS FOR (n:ScheduleInstanceContext) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT tag_id IF NOT EXISTS FOR (n:Tag) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT block_id IF NOT EXISTS FOR (n:Block) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT decision_id IF NOT EXISTS FOR (n:Decision) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT res_id IF NOT EXISTS FOR (n:Resource) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT sla_id IF NOT EXISTS FOR (n:SLA) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT listener_id IF NOT EXISTS FOR (n:Listener) REQUIRE n.id IS UNIQUE",
            "CREATE CONSTRAINT holiday_id IF NOT EXISTS FOR (n:Holiday) REQUIRE n.id IS UNIQUE",
            
            # Instance layer
            "CREATE CONSTRAINT jobgroup_exec_id IF NOT EXISTS FOR (n:JobGroupExecution) REQUIRE n.execId IS UNIQUE",
            "CREATE CONSTRAINT jobcontext_exec_id IF NOT EXISTS FOR (n:JobContextExecution) REQUIRE n.execId IS UNIQUE",
        ]
        
        indexes = [
            # Class layer
            "CREATE INDEX job_name_idx IF NOT EXISTS FOR (n:Job) ON (n.name)",
            "CREATE INDEX step_name_idx IF NOT EXISTS FOR (n:Step) ON (n.name)",
            "CREATE INDEX resource_type_idx IF NOT EXISTS FOR (n:Resource) ON (n.type)",
            "CREATE INDEX sla_scope_idx IF NOT EXISTS FOR (n:SLA) ON (n.scope)",
            
            
        ]
        
        with self.driver.session(database=self.database) as session:
            for constraint in constraints:
                try:
                    session.run(constraint)
                    #logger.debug(f"Created: {constraint[:50]}...")
                except Exception as e:
                    logger.warning(f"Constraint may already exist: {str(e)[:100]}")
            
            for index in indexes:
                try:
                    session.run(index)
                    #logger.debug(f"Created: {index[:50]}...")
                except Exception as e:
                    logger.warning(f"Index may already exist: {str(e)[:100]}")
        
        logger.info(" Constraints and indexes created")
    
    def compute_cpm_for_jobgroup(self, jobgroup_id: str, analyzer: CPMAnalyzer):
        res = analyzer.compute_for_jobgroup(jobgroup_id, persist=True)
        logger.info(f"\n=== CPM Summary for {jobgroup_id} ===")
        logger.info("SLA(ms):", res.group_sla_ms)
        logger.info("Completion(ms):", res.completion_ms)
        logger.info("Total Buffer(ms):", res.total_buffer_ms)
        logger.info("Longest Path:", " -> ".join(res.longest_path))
            


    # ========================================================================
    # CLASS LEVEL LOADING
    # ========================================================================
    
    def load_class_level_data(self, excel_path: str):
        """
        Load all class-level data from Excel
        
        Args:
            excel_path: Path to class_level_data.xlsx
        """
        logger.info(f"Loading class-level data from {excel_path}")
        
        excel_file = pd.ExcelFile(excel_path)
        
        # Load in dependency order
        self._load_tags(excel_file)
        self._load_resources(excel_file)
        self._load_job_groups(excel_file)
        self._load_jobs(excel_file)
        self._load_jobs_association(excel_file)
        self._load_job_contexts(excel_file)
        self._load_job_successors(excel_file)
        self._load_steps_directly_from_IG()
        self._copy_step_db_operations_from_info_graph()
        self._copy_step_shell_and_procedure_executions_from_info_graph()
        self._copy_sql_resource_invokes_from_info_graph()
        self._load_resource_dependency(excel_file)
        self._load_slas(excel_file)
        self._load_calendar(excel_file)
        self._load_associate_calendar(excel_file)
        self._load_holidays(excel_file)
        logger.info(" Class-level data loaded successfully")
    
    def _load_job_groups(self, excel_file):
        """Load JobGroups and create PRECEDES relationships"""
        df = pd.read_excel(excel_file, 'JobGroups')
        logger.info(f"Loading {len(df)} JobGroups...")
        
        # Step 1: Create all JobGroup nodes
        with self.driver.session(database=self.database) as session:
            for _, row in df.iterrows():
                session.execute_write(self._create_job_group, row.to_dict())
        
        logger.info(f" Loaded {len(df)} JobGroups")
        
        # Step 2: Create PRECEDES relationships based on successor column
        logger.info(f"Creating PRECEDES relationships between JobGroups...")
        precedes_count = 0
        
        with self.driver.session(database=self.database) as session:
            for _, row in df.iterrows():
                data = row.to_dict()
                # Handle NaN values
                data = {k: v for k, v in data.items() if pd.notna(v)}
                
                if 'successor' in data:
                    session.execute_write(self._create_job_group_precedes, data)
                    precedes_count += 1
        
        logger.info(f" Created {precedes_count} PRECEDES relationships between JobGroups")
    
    @staticmethod
    def _create_job_group(tx, data: Dict):
        """Transaction function to create JobGroup"""
        node = JobGroupNodeDef(
            id=str(data.get('id', '')),
            name=str(data.get('name', '')),
            description=str(data.get('description', '')),
            priority=str(data.get('priority', '')),
            enabled=bool(data.get('enabled', True))
        )
        query = """
        MERGE (jg:JobGroup {id: $id})
        SET jg.name = $name,
            jg.description = $description,
            jg.priority = $priority,
            jg.enabled = $enabled,
            jg.createdAt = datetime()
        RETURN jg
        """
        tx.run(query, id=node.id, name=node.name, description=node.description,
               priority=node.priority, enabled=node.enabled)
    
    @staticmethod
    def _create_job_group_precedes(tx, data: Dict):
        """Transaction function to create PRECEDES relationship between JobGroups"""
        successor = data.get('successor', None)
        
        if successor is None:
            return
        
        # Handle multiple successors (comma-separated)
        if ',' in str(successor):
            # Multiple parallel successors
            for succ in str(successor).split(','):
                successor_id = succ.strip()
                query = """
                MATCH (jg1:JobGroup {id: $id})
                MATCH (jg2:JobGroup {id: $successorId})
                MERGE (jg1)-[:PRECEDES {on: 'COMPLETED'}]->(jg2)
                RETURN jg1, jg2
                """
                tx.run(query, id=data['id'], successorId=successor_id)
        else:
            # Single successor
            query = """
            MATCH (jg1:JobGroup {id: $id})
            MATCH (jg2:JobGroup {id: $successor})
            MERGE (jg1)-[:PRECEDES {on: 'COMPLETED'}]->(jg2)
            RETURN jg1, jg2
            """
            tx.run(query, **data)
    
    def _load_tags(self, excel_file):
        """Load Tags"""
        df = pd.read_excel(excel_file, 'Tags')
        logger.info(f"Loading {len(df)} Tags...")
        
        with self.driver.session(database=self.database) as session:
            for _, row in df.iterrows():
                data = row.to_dict()
                session.execute_write(self._create_tag, data)
        
        logger.info(f" Loaded {len(df)} Tags")
    
    @staticmethod
    def _create_tag(tx, data: Dict):
        """Transaction function to create Tag"""
        node = TagNodeDef(
            id=str(data.get('id', '')),
            name=str(data.get('name', '')),
            description=str(data.get('description', '')),
            tagType=str(data.get('tagType', '')),
            enabled=bool(data.get('enabled', True))
        )
        query = """
        MERGE (tg:Tag {id: $id})
        SET tg.name = $name,
            tg.description = $description,
            tg.tagType = $tagType,
            tg.enabled = $enabled,
            tg.createdAt = datetime()
        RETURN tg
        """
        tx.run(query, id=node.id, name=node.name, description=node.description,
               tagType=node.tagType, enabled=node.enabled)
    
    def _load_jobs_from_graph(self):
        """Load Job nodes from information graph"""
        logger.info("Loading Job nodes from information graph...")
        
        query = """
        MATCH (j:Job)
        WHERE j.id IS NOT NULL AND j.name IS NOT NULL
        RETURN j.id           as id,
               j.name         as name,
               j.enabled      as enabled,
               j.sourceFile   as sourceFile,
               j.dynamicJob   as dynamicJob
        ORDER BY j.name
        """
        
        jobs = []
        with self.driver.session(database=self.info_database) as session:
            result = session.run(query)
            for record in result:
                jobs.append({
                    'id':         record['id'],
                    'name':       record['name'],
                    'enabled':    record.get('enabled', True),
                    'sourceFile': record.get('sourceFile', ''),
                    'dynamicJob': record.get('dynamicJob', False) or False,
                })
        
        logger.info(f"  Found {len(jobs)} Job nodes in information graph")
        return jobs
    
    def _load_jobs(self, excel_file=None):
        """Load Jobs from information graph (excel_file parameter kept for compatibility)"""
        jobs = self._load_jobs_from_graph()
        
        if not jobs:
            logger.warning("No Job nodes found in information graph")
            return
        
        logger.info(f"Loading {len(jobs)} Jobs into knowledge graph...")
        
        with self.driver.session(database=self.database) as session:
            for job_data in jobs:
                session.execute_write(self._create_job, job_data)
        
        logger.info(f" Loaded {len(jobs)} Jobs")
    

    @staticmethod
    def _create_job(tx, data: Dict):
        """Transaction function to create Job from information graph data"""
        node = JobDef(
            name=str(data.get('name', '')),
            id=str(data.get('id', '')),
            enabled=bool(data.get('enabled', True)),
            source_file=str(data.get('sourceFile', ''))
        )
        dynamic_job = bool(data.get('dynamicJob', False))
        query = """
        MERGE (j:Job {name: $name})
        SET j.id         = $id,
            j.enabled    = $enabled,
            j.dynamicJob = $dynamicJob,
            j.createdAt  = datetime()
        """
        if node.source_file:
            query += ", j.sourceFile = $sourceFile"
        query += " RETURN j"
        tx.run(query, name=node.name, id=node.id, enabled=node.enabled,
               sourceFile=node.source_file, dynamicJob=dynamic_job)
    
    def _load_jobs_association(self, excel_file):
        """Load Jobs and create relationships to JobGroups"""
        df = pd.read_excel(excel_file, 'AssociatedJobs')
        logger.info(f"Loading {len(df)} Jobs Association...")
        
        with self.driver.session(database=self.database) as session:
            for _, row in df.iterrows():
                data = row.to_dict()
                session.execute_write(self._create_job_association, data)
        
        logger.info(f" Loaded {len(df)} Jobs Association")

    @staticmethod
    def _create_job_association(tx, data: Dict):
        """Transaction function to create Job and link to JobGroup"""
        # Match by name OR id: regular jobs have id==name, dynamic jobs have
        # a numeric id but the AssociatedJobs sheet stores the job name.
        query = """
        MATCH (j:Job)
        WHERE j.id = $jobId OR j.name = $jobId
        MATCH (jg:JobGroup {id: $jobGroupId})
        MERGE (jg)-[:HAS_JOB]->(j)
        RETURN j
        """
        tx.run(query, **data)
        
    
    
    def _load_steps_directly_from_IG(self):
        """
        Load Steps, Blocks, Decisions, Listeners, and all their relationships 
        directly from the information graph to the knowledge graph.
        
        This avoids duplicate XML parsing since the information graph already 
        contains the complete call hierarchy built during the scanning phase.
        
        Entities loaded:
        - Steps (TASKLET and CHUNK types)
        - Blocks (FLOW, SPLIT, BRANCH types)
        - Decisions
        - Listeners
        
        Relationships loaded:
        - Job CONTAINS Steps/Blocks
        - Job ENTRY to first node
        - Block CONTAINS Steps/Blocks
        - Block ENTRY to first node
        - PRECEDES edges between nodes
        - HAS_LISTENER relationships
        """
        logger.info("Loading Steps and related entities directly from information graph...")
        
        # Step 1: Load all Steps
        logger.info("  Querying Steps from information graph...")
        steps_query = """
        MATCH (s:Step)
        RETURN s.name                              as name,
               s.stepKind                         as stepKind,
               s.readerBean                       as readerBean,
               s.readerClass                      as readerClass,
               s.readerSourcePath                 as readerSourcePath,
               s.processorBean                    as processorBean,
               s.processorClass                   as processorClass,
               s.processorSourcePath              as processorSourcePath,
               s.writerBean                       as writerBean,
               s.writerClass                      as writerClass,
               s.writerSourcePath                 as writerSourcePath,
               s.implBean                         as implBean,
               s.className                        as className,
               s.path                             as path,
               coalesce(s.dynamicJob,  false)     as dynamicJob,
               coalesce(s.dynamicStep, false)     as dynamicStep,
               coalesce(s.stepOrder,   0)         as stepOrder,
               s.lastUpdated                      as lastUpdated,
               coalesce(s.stepDbOperationCount,       0)  as stepDbOperationCount,
               coalesce(s.stepDbOperations,       [])     as stepDbOperations,
               coalesce(s.stepProcedureCallCount,     0)  as stepProcedureCallCount,
               coalesce(s.stepProcedureCalls,     [])     as stepProcedureCalls,
               coalesce(s.stepShellExecutionCount,    0)  as stepShellExecutionCount,
               coalesce(s.stepShellExecutions,    [])     as stepShellExecutions,
               coalesce(s.stepSqlFileInvocationCount, 0)  as stepSqlFileInvocationCount,
               coalesce(s.stepSqlFileInvocations, [])     as stepSqlFileInvocations
        ORDER BY s.name
        """
        
        steps = []
        with self.driver.session(database=self.info_database) as session:
            result = session.run(steps_query)
            for record in result:
                steps.append(dict(record))
        
        logger.info(f"    Found {len(steps)} Steps in information graph")
        
        # Step 2: Load all Blocks
        logger.info("  Querying Blocks from information graph...")
        blocks_query = """
        MATCH (b:Block)
        RETURN b.id as id,
               b.blockType as blockType
        ORDER BY b.id
        """
        
        blocks = []
        with self.driver.session(database=self.info_database) as session:
            result = session.run(blocks_query)
            for record in result:
                blocks.append(dict(record))
        
        logger.info(f"    Found {len(blocks)} Blocks in information graph")
        
        # Step 3: Load all Decisions
        logger.info("  Querying Decisions from information graph...")
        decisions_query = """
        MATCH (d:Decision)
        RETURN d.name as name,
               d.deciderBean as deciderBean,
               d.className as className,
               d.path as path
        ORDER BY d.name
        """
        
        decisions = []
        with self.driver.session(database=self.info_database) as session:
            result = session.run(decisions_query)
            for record in result:
                decisions.append(dict(record))
        
        logger.info(f"    Found {len(decisions)} Decisions in information graph")
        
        # Step 4: Load all Listeners
        logger.info("  Querying Listeners from information graph...")
        listeners_query = """
        MATCH (l:Listener)
        RETURN l.name as name,
               l.scope as scope,
               l.implBean as implBean,
               l.path as path
        ORDER BY l.name
        """
        
        listeners = []
        with self.driver.session(database=self.info_database) as session:
            result = session.run(listeners_query)
            for record in result:
                listeners.append(dict(record))
        
        logger.info(f"    Found {len(listeners)} Listeners in information graph")
        
        # Step 5: Load all relationships
        logger.info("  Querying relationships from information graph...")
        
        # CONTAINS relationships (Job->Step, Job->Block, Block->Step, Block->Block)
        contains_query = """
        MATCH (source)-[r:CONTAINS]->(target)
        WHERE (source:Job OR source:Block) AND (target:Step OR target:Block)
        WITH source, target, labels(source) as sourceLabels, labels(target) as targetLabels
        RETURN 
            CASE WHEN 'Job' IN sourceLabels THEN source.name ELSE source.id END as sourceName,
            sourceLabels,
            CASE WHEN 'Step' IN targetLabels THEN target.name ELSE target.id END as targetName,
            targetLabels
        """
        
        contains_rels = []
        with self.driver.session(database=self.info_database) as session:
            result = session.run(contains_query)
            for record in result:
                contains_rels.append(dict(record))
        
        logger.info(f"    Found {len(contains_rels)} CONTAINS relationships")
        
        # ENTRY relationships (Job->Step/Block, Block->Step/Decision)
        entry_query = """
        MATCH (source)-[r:ENTRY]->(target)
        WHERE (source:Job OR source:Block) AND (target:Step OR target:Block OR target:Decision)
        WITH source, target, labels(source) as sourceLabels, labels(target) as targetLabels
        RETURN 
            CASE WHEN 'Job' IN sourceLabels THEN source.name ELSE source.id END as sourceName,
            sourceLabels,
            CASE WHEN 'Step' IN targetLabels OR 'Decision' IN targetLabels THEN target.name ELSE target.id END as targetName,
            targetLabels
        """
        
        entry_rels = []
        with self.driver.session(database=self.info_database) as session:
            result = session.run(entry_query)
            for record in result:
                entry_rels.append(dict(record))
        
        logger.info(f"    Found {len(entry_rels)} ENTRY relationships")
        
        # PRECEDES relationships (with 'on' property)
        precedes_query = """
        MATCH (source)-[r:PRECEDES]->(target)
        WHERE (source:Step OR source:Block OR source:Decision) AND (target:Step OR target:Block OR target:Decision)
        WITH source, r, target, labels(source) as sourceLabels, labels(target) as targetLabels
        RETURN 
            CASE WHEN 'Step' IN sourceLabels OR 'Decision' IN sourceLabels THEN source.name ELSE source.id END as sourceName,
            sourceLabels,
            CASE WHEN 'Step' IN targetLabels OR 'Decision' IN targetLabels THEN target.name ELSE target.id END as targetName,
            targetLabels,
            r.on as onValue
        """
        
        precedes_rels = []
        with self.driver.session(database=self.info_database) as session:
            result = session.run(precedes_query)
            for record in result:
                precedes_rels.append(dict(record))
        
        logger.info(f"    Found {len(precedes_rels)} PRECEDES relationships")
        
        # HAS_LISTENER relationships
        listener_rels_query = """
        MATCH (j:Job)-[r:HAS_LISTENER]->(l:Listener)
        RETURN j.name as jobName,
               l.name as listenerName
        """
        
        listener_rels = []
        with self.driver.session(database=self.info_database) as session:
            result = session.run(listener_rels_query)
            for record in result:
                listener_rels.append(dict(record))
        
        logger.info(f"    Found {len(listener_rels)} HAS_LISTENER relationships")
        
        # Step 6: Write everything to knowledge graph
        logger.info("  Writing entities and relationships to knowledge graph...")
        
        with self.driver.session(database=self.database) as session:
            # Shared execution-summary properties added to every Step regardless of kind
            _STEP_STATS_CLAUSE = """
                        s.dynamicJob                  = $dynamicJob,
                        s.dynamicStep                 = $dynamicStep,
                        s.stepOrder                   = $stepOrder,
                        s.lastUpdated                 = $lastUpdated,
                        s.stepDbOperationCount        = $stepDbOperationCount,
                        s.stepDbOperations            = $stepDbOperations,
                        s.stepProcedureCallCount      = $stepProcedureCallCount,
                        s.stepProcedureCalls          = $stepProcedureCalls,
                        s.stepShellExecutionCount     = $stepShellExecutionCount,
                        s.stepShellExecutions         = $stepShellExecutions,
                        s.stepSqlFileInvocationCount  = $stepSqlFileInvocationCount,
                        s.stepSqlFileInvocations      = $stepSqlFileInvocations
            """

            # Create Steps
            for step in steps:
                if step.get('stepKind') == 'CHUNK':
                    query = (
                        """
                    MERGE (s:Step {name: $name})
                    SET s.stepKind            = $stepKind,
                        s.readerBean          = $readerBean,
                        s.readerClass         = $readerClass,
                        s.readerSourcePath    = $readerSourcePath,
                        s.processorBean       = $processorBean,
                        s.processorClass      = $processorClass,
                        s.processorSourcePath = $processorSourcePath,
                        s.writerBean          = $writerBean,
                        s.writerClass         = $writerClass,
                        s.writerSourcePath    = $writerSourcePath,
                    """ + _STEP_STATS_CLAUSE
                    )
                else:  # TASKLET
                    query = (
                        """
                    MERGE (s:Step {name: $name})
                    SET s.stepKind  = $stepKind,
                        s.implBean  = $implBean,
                        s.className = $className,
                        s.path      = $path,
                    """ + _STEP_STATS_CLAUSE
                    )
                session.run(query, **step)
            
            logger.info(f"    Created {len(steps)} Steps")
            
            # Create Blocks
            for block in blocks:
                query = """
                MERGE (b:Block {id: $id})
                SET b.blockType = $blockType
                """
                session.run(query, **block)
            
            logger.info(f"    Created {len(blocks)} Blocks")
            
            # Create Decisions
            for decision in decisions:
                query = """
                MERGE (d:Decision {name: $name})
                SET d.deciderBean = $deciderBean,
                    d.className = $className,
                    d.path = $path
                """
                session.run(query, **decision)
            
            logger.info(f"    Created {len(decisions)} Decisions")
            
            # Create Listeners
            for listener in listeners:
                query = """
                MERGE (l:Listener {name: $name})
                SET l.scope = $scope,
                    l.implBean = $implBean,
                    l.path = $path
                """
                session.run(query, **listener)
            
            logger.info(f"    Created {len(listeners)} Listeners")
            
            # Create CONTAINS relationships
            for rel in contains_rels:
                source_label = 'Job' if 'Job' in rel['sourceLabels'] else 'Block'
                target_label = 'Step' if 'Step' in rel['targetLabels'] else 'Block'
                
                if source_label == 'Job':
                    source_match = "(source:Job {name: $sourceName})"
                else:
                    source_match = "(source:Block {id: $sourceName})"
                
                if target_label == 'Step':
                    target_match = "(target:Step {name: $targetName})"
                else:
                    target_match = "(target:Block {id: $targetName})"
                
                query = f"""
                MATCH {source_match}
                MATCH {target_match}
                MERGE (source)-[:CONTAINS]->(target)
                """
                session.run(query, sourceName=rel['sourceName'], targetName=rel['targetName'])
            
            logger.info(f"    Created {len(contains_rels)} CONTAINS relationships")
            
            # Create ENTRY relationships
            for rel in entry_rels:
                source_label = 'Job' if 'Job' in rel['sourceLabels'] else 'Block'
                target_labels = rel['targetLabels']
                
                if 'Step' in target_labels:
                    target_label = 'Step'
                elif 'Decision' in target_labels:
                    target_label = 'Decision'
                else:
                    target_label = 'Block'
                
                if source_label == 'Job':
                    source_match = "(source:Job {name: $sourceName})"
                else:
                    source_match = "(source:Block {id: $sourceName})"
                
                if target_label == 'Block':
                    target_match = "(target:Block {id: $targetName})"
                else:
                    target_match = f"(target:{target_label} {{name: $targetName}})"
                
                query = f"""
                MATCH {source_match}
                MATCH {target_match}
                MERGE (source)-[:ENTRY]->(target)
                """
                session.run(query, sourceName=rel['sourceName'], targetName=rel['targetName'])
            
            logger.info(f"    Created {len(entry_rels)} ENTRY relationships")
            
            # Create PRECEDES relationships
            for rel in precedes_rels:
                source_labels = rel['sourceLabels']
                target_labels = rel['targetLabels']
                
                # Determine source label
                if 'Step' in source_labels:
                    source_label = 'Step'
                    source_match = "(source:Step {name: $sourceName})"
                elif 'Decision' in source_labels:
                    source_label = 'Decision'
                    source_match = "(source:Decision {name: $sourceName})"
                else:
                    source_label = 'Block'
                    source_match = "(source:Block {id: $sourceName})"
                
                # Determine target label
                if 'Step' in target_labels:
                    target_label = 'Step'
                    target_match = "(target:Step {name: $targetName})"
                elif 'Decision' in target_labels:
                    target_label = 'Decision'
                    target_match = "(target:Decision {name: $targetName})"
                else:
                    target_label = 'Block'
                    target_match = "(target:Block {id: $targetName})"
                
                query = f"""
                MATCH {source_match}
                MATCH {target_match}
                MERGE (source)-[:PRECEDES {{on: $onValue}}]->(target)
                """
                session.run(query, sourceName=rel['sourceName'], targetName=rel['targetName'], onValue=rel['onValue'])
            
            logger.info(f"    Created {len(precedes_rels)} PRECEDES relationships")
            
            # Create HAS_LISTENER relationships
            for rel in listener_rels:
                query = """
                MATCH (j:Job {name: $jobName})
                MATCH (l:Listener {name: $listenerName})
                MERGE (j)-[:HAS_LISTENER]->(l)
                """
                session.run(query, jobName=rel['jobName'], listenerName=rel['listenerName'])
            
            logger.info(f"    Created {len(listener_rels)} HAS_LISTENER relationships")
        
        logger.info(" Steps and related entities loaded successfully from information graph")
    
    def _copy_step_db_operations_from_info_graph(self):
        """
        Copy DB operations from the information graph into the knowledge graph.

        Structure created (direct, no DataAsset intermediary):
          Step -[:DB_OPERATION {operationType, tableName, confidence, methodReference}]-> Resource {type:'TABLE'|'FILE'}
        """
        logger.info("Linking Steps to DB-operation Resources in knowledge graph...")
        
        # Query information graph for Steps with JavaMethods that have DB operations.
        # Two paths to JavaClass are handled:
        #   TASKLET: Step -[:IMPLEMENTED_BY]-> JavaClass
        #   CHUNK  : Step -[:USES_BEAN]-> Bean -[:IMPLEMENTS]-> JavaClass
        query_step_methods = """
        MATCH (s:Step)
        MATCH (jc:JavaClass)
        WHERE (s)-[:IMPLEMENTED_BY]->(jc)
           OR (s)-[:USES_BEAN]->(:Bean)-[:IMPLEMENTS]->(jc)
        MATCH (jc)-[:HAS_METHOD]->(m:JavaMethod)
        WHERE m.dbOperations IS NOT NULL AND m.dbOperationCount > 0
        RETURN s.name as stepName,
               collect(DISTINCT {
                   methodName: m.methodName,
                   methodFqn: m.fqn,
                   dbOperations: m.dbOperations
               }) as methodsWithOps

        UNION

        MATCH (s:Step)
        MATCH (jc:JavaClass)
        WHERE (s)-[:IMPLEMENTED_BY]->(jc)
           OR (s)-[:USES_BEAN]->(:Bean)-[:IMPLEMENTS]->(jc)
        MATCH (jc)-[:HAS_METHOD]->(entry:JavaMethod)
        MATCH (entry)-[:CALLS*]->(called:JavaMethod)
        WHERE called.dbOperations IS NOT NULL AND called.dbOperationCount > 0
        RETURN s.name as stepName,
               collect(DISTINCT {
                   methodName: called.methodName,
                   methodFqn: called.fqn,
                   dbOperations: called.dbOperations
               }) as methodsWithOps
        """
        
        with self.driver.session(database=self.info_database) as session:
            result = session.run(query_step_methods)
            steps_data = {}
            for record in result:
                step_name = record['stepName']
                methods = record['methodsWithOps']
                if step_name not in steps_data:
                    steps_data[step_name] = []
                steps_data[step_name].extend(methods)
        
        if not steps_data:
            logger.info("  No Steps with DB operations found in information graph")
            return
        
        logger.info(f"  Found {len(steps_data)} Steps with DB operations")
        
        # Helper function to determine operation type
        def get_operation_type(db_op: str) -> str:
            """Map database operation to relationship type"""
            db_op_upper = db_op.upper()
            if 'SELECT' in db_op_upper or 'READ' in db_op_upper or 'QUERY' in db_op_upper:
                return 'READ'
            elif 'INSERT' in db_op_upper or 'CREATE' in db_op_upper:
                return 'INSERT'
            elif 'DELETE' in db_op_upper or 'REMOVE' in db_op_upper:
                return 'DELETE'
            elif 'UPDATE' in db_op_upper or 'MERGE' in db_op_upper:
                return 'INSERT'  # Treat UPDATE as INSERT for now
            elif 'AGGREGATE' in db_op_upper or 'COUNT' in db_op_upper or 'SUM' in db_op_upper:
                return 'AGGREGATE'
            else:
                return 'READ'  # Default to READ
        
        # Helper function to determine resource type from operation
        def get_resource_type(db_op: str) -> str:
            """Determine if operation is on DATABASE or FILE"""
            db_op_upper = db_op.upper()
            if any(keyword in db_op_upper for keyword in ['SQL', 'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TABLE']):
                return 'TABLE'
            elif any(keyword in db_op_upper for keyword in ['FILE', 'CSV', 'XML', 'JSON']):
                return 'FILE'
            else:
                return 'TABLE'  # Default to TABLE
        
        # Build deduplicated (stepName, db_op, method_fqn) tuples
        unique_ops: dict = {}   # (stepName, db_op) -> first methodFqn seen
        for step_name, methods in steps_data.items():
            for method_info in methods:
                method_fqn = method_info['methodFqn']
                for db_op in method_info['dbOperations']:
                    key = (step_name, db_op)
                    if key not in unique_ops:
                        unique_ops[key] = method_fqn

        created_count = 0
        with self.driver.session(database=self.database) as session:
            for (step_name, db_operation), method_fqn in unique_ops.items():
                # Parse: "SELECT:CUSTOMER:HIGH" or "INSERT:STAGE_COLLATERAL:HIGH"
                parts = db_operation.split(':')
                operation_type  = get_operation_type(db_operation)
                resource_type   = get_resource_type(db_operation)
                resource_name   = parts[1].strip() if len(parts) >= 2 else db_operation
                confidence      = parts[2].strip() if len(parts) >= 3 else 'MEDIUM'
                resource_id     = f"RESOURCE_{resource_type}_{resource_name}"

                # Ensure Resource node exists
                session.run(
                    """
                    MERGE (r:Resource {name: $name, type: $rtype})
                    ON CREATE SET r.id      = $rid,
                                  r.enabled = true
                    """,
                    name=resource_name, rtype=resource_type, rid=resource_id,
                )

                # Step -[:DB_OPERATION]-> Resource  (all info in rel props)
                session.run(
                    """
                    MATCH (s:Step     {name: $stepName})
                    MATCH (r:Resource {name: $resourceName, type: $resourceType})
                    MERGE (s)-[rel:DB_OPERATION {operationType: $opType, tableName: $tname}]->(r)
                    SET rel.confidence       = $confidence,
                        rel.methodReference  = $methodRef
                    """,
                    stepName=step_name,
                    resourceName=resource_name,
                    resourceType=resource_type,
                    opType=operation_type,
                    tname=resource_name,
                    confidence=confidence,
                    methodRef=method_fqn,
                )
                created_count += 1

        logger.info(f"   Created {created_count} Step-[:DB_OPERATION]->Resource link(s) in knowledge graph")

    def _copy_step_shell_and_procedure_executions_from_info_graph(self):
        """
        Copy shell-script and stored-procedure execution links from the Information
        Graph into the Knowledge Graph.

        IG source:
          JavaMethod -[:EXECUTES]->(r:Resource {type:'SHELL_SCRIPT'})
          JavaMethod -[:INVOKES]->(r:Resource {type:'PROCEDURE'|'FUNCTION'})

        KG structure created (direct, no DataAsset intermediary):
          Step -[:EXECUTES  {scriptType, confidence, scriptPath, executionUser, scriptParams}]-> Resource {type:'SHELL_SCRIPT'}
          Step -[:INVOKES   {databaseType, schemaName, packageName, confidence}]->             Resource {type:'PROCEDURE'|'FUNCTION'}
        """
        logger.info("Linking Steps to shell/procedure Resources in knowledge graph...")

        # Two paths to JavaClass are handled:
        #   TASKLET: Step -[:IMPLEMENTED_BY]-> JavaClass
        #   CHUNK  : Step -[:USES_BEAN]-> Bean -[:IMPLEMENTS]-> JavaClass
        #            (applies to reader, processor, and writer beans alike)

        # ── Shell executions ──────────────────────────────────────────────────
        shell_query = """
        MATCH (s:Step)
        MATCH (jc:JavaClass)
        WHERE (s)-[:IMPLEMENTED_BY]->(jc)
           OR (s)-[:USES_BEAN]->(:Bean)-[:IMPLEMENTS]->(jc)
        MATCH (jc)-[:HAS_METHOD]->(m:JavaMethod)-[:EXECUTES]->(r:Resource)
        WHERE r.type = 'SHELL_SCRIPT'
        RETURN s.name          AS stepName,
               r.name          AS resourceName,
               r.type          AS resourceType,
               r.scriptType    AS scriptType,
               r.scriptPath    AS scriptPath,
               r.scriptDir     AS scriptDir,
               r.scriptFile    AS scriptFile,
               r.executionUser AS executionUser,
               r.scriptParams  AS scriptParams,
               m.fqn           AS methodFqn

        UNION

        MATCH (s:Step)
        MATCH (jc:JavaClass)
        WHERE (s)-[:IMPLEMENTED_BY]->(jc)
           OR (s)-[:USES_BEAN]->(:Bean)-[:IMPLEMENTS]->(jc)
        MATCH (jc)-[:HAS_METHOD]->(entry:JavaMethod)
        MATCH (entry)-[:CALLS*]->(m:JavaMethod)-[:EXECUTES]->(r:Resource)
        WHERE r.type = 'SHELL_SCRIPT'
        RETURN s.name          AS stepName,
               r.name          AS resourceName,
               r.type          AS resourceType,
               r.scriptType    AS scriptType,
               r.scriptPath    AS scriptPath,
               r.scriptDir     AS scriptDir,
               r.scriptFile    AS scriptFile,
               r.executionUser AS executionUser,
               r.scriptParams  AS scriptParams,
               m.fqn           AS methodFqn
        """

        # ── Procedure / Function calls ────────────────────────────────────────
        proc_query = """
        MATCH (s:Step)
        MATCH (jc:JavaClass)
        WHERE (s)-[:IMPLEMENTED_BY]->(jc)
           OR (s)-[:USES_BEAN]->(:Bean)-[:IMPLEMENTS]->(jc)
        MATCH (jc)-[:HAS_METHOD]->(m:JavaMethod)-[:INVOKES]->(r:Resource)
        WHERE r.type IN ['PROCEDURE', 'FUNCTION']
        RETURN s.name           AS stepName,
               r.name           AS resourceName,
               r.type           AS resourceType,
               r.databaseType   AS databaseType,
               r.schemaName     AS schemaName,
               r.packageName    AS packageName,
               m.fqn            AS methodFqn

        UNION

        MATCH (s:Step)
        MATCH (jc:JavaClass)
        WHERE (s)-[:IMPLEMENTED_BY]->(jc)
           OR (s)-[:USES_BEAN]->(:Bean)-[:IMPLEMENTS]->(jc)
        MATCH (jc)-[:HAS_METHOD]->(entry:JavaMethod)
        MATCH (entry)-[:CALLS*]->(m:JavaMethod)-[:INVOKES]->(r:Resource)
        WHERE r.type IN ['PROCEDURE', 'FUNCTION']
        RETURN s.name           AS stepName,
               r.name           AS resourceName,
               r.type           AS resourceType,
               r.databaseType   AS databaseType,
               r.schemaName     AS schemaName,
               r.packageName    AS packageName,
               m.fqn            AS methodFqn
        """

        shell_rows = []
        proc_rows  = []
        with self.driver.session(database=self.info_database) as session:
            shell_rows = [dict(r) for r in session.run(shell_query)]
            proc_rows  = [dict(r) for r in session.run(proc_query)]

        if not shell_rows and not proc_rows:
            logger.info("  No shell/procedure executions found in information graph")
            return

        logger.info(
            f"  Found {len(shell_rows)} shell execution link(s) and "
            f"{len(proc_rows)} procedure execution link(s) in IG"
        )

        # Deduplicate by (stepName, resourceName) — UNION can produce duplicates
        def _deduplicate(rows):
            seen, unique = set(), []
            for row in rows:
                key = (row["stepName"], row["resourceName"])
                if key not in seen:
                    seen.add(key)
                    unique.append(row)
            return unique

        shell_rows = _deduplicate(shell_rows)
        proc_rows  = _deduplicate(proc_rows)

        created_count = 0

        with self.driver.session(database=self.database) as session:

            # ── Shell executions: Step -[:EXECUTES]-> Resource ────────────────
            for row in shell_rows:
                step_name     = row["stepName"]
                resource_name = row["resourceName"]
                script_type   = row.get("scriptType")    or "SHELL"
                script_path   = row.get("scriptPath")    or resource_name
                script_dir    = row.get("scriptDir")     or ""
                script_file   = row.get("scriptFile")    or resource_name
                exec_user     = row.get("executionUser") or ""
                script_params = row.get("scriptParams")  or ""

                resource_id = (
                    "RESOURCE_SHELL_"
                    + resource_name.replace(".", "_").replace("-", "_").upper()
                )

                # Ensure Resource node exists
                session.run(
                    """
                    MERGE (r:Resource {name: $name, type: 'SHELL_SCRIPT'})
                    ON CREATE SET r.id            = $resourceId,
                                  r.enabled       = true,
                                  r.scriptType    = $scriptType,
                                  r.scriptPath    = $scriptPath,
                                  r.scriptDir     = $scriptDir,
                                  r.scriptFile    = $scriptFile,
                                  r.executionUser = $execUser,
                                  r.scriptParams  = $scriptParams
                    ON MATCH SET  r.scriptType    = COALESCE(r.scriptType, $scriptType),
                                  r.scriptPath    = COALESCE(r.scriptPath, $scriptPath)
                    """,
                    name=resource_name, resourceId=resource_id,
                    scriptType=script_type, scriptPath=script_path,
                    scriptDir=script_dir, scriptFile=script_file,
                    execUser=exec_user, scriptParams=script_params,
                )

                # Step -[:EXECUTES {rel props}]-> Resource  (direct, no DataAsset)
                session.run(
                    """
                    MATCH (s:Step     {name: $stepName})
                    MATCH (r:Resource {name: $resourceName, type: 'SHELL_SCRIPT'})
                    MERGE (s)-[rel:EXECUTES {resourceName: $resourceName}]->(r)
                    SET rel.scriptType    = $scriptType,
                        rel.scriptFile    = $scriptFile,
                        rel.scriptParams  = $scriptParams,
                        rel.executionUser = $execUser,
                        rel.confidence    = 'HIGH'
                    """,
                    stepName=step_name, resourceName=resource_name,
                    scriptType=script_type, scriptFile=script_file,
                    scriptParams=script_params, execUser=exec_user,
                )
                created_count += 1

            # ── Procedure / Function calls: Step -[:INVOKES]-> Resource ───────
            for row in proc_rows:
                step_name     = row["stepName"]
                resource_name = row["resourceName"]
                resource_type = row["resourceType"]          # PROCEDURE or FUNCTION
                db_type       = row.get("databaseType") or ""
                schema_name   = row.get("schemaName")   or ""
                package_name  = row.get("packageName")  or ""

                resource_id = (
                    f"RESOURCE_{resource_type}_{schema_name}_{resource_name}"
                    .replace(" ", "_").upper()
                )

                # Ensure Resource node exists
                session.run(
                    """
                    MERGE (r:Resource {name: $name, type: $rtype})
                    ON CREATE SET r.id           = $resourceId,
                                  r.enabled      = true,
                                  r.databaseType = $dbType,
                                  r.schemaName   = $schemaName,
                                  r.packageName  = $packageName
                    ON MATCH SET  r.databaseType = COALESCE(r.databaseType, $dbType),
                                  r.schemaName   = COALESCE(r.schemaName, $schemaName)
                    """,
                    name=resource_name, rtype=resource_type, resourceId=resource_id,
                    dbType=db_type, schemaName=schema_name, packageName=package_name,
                )

                # Step -[:INVOKES {rel props}]-> Resource  (direct, no DataAsset)
                session.run(
                    """
                    MATCH (s:Step     {name: $stepName})
                    MATCH (r:Resource {name: $resourceName, type: $rtype})
                    MERGE (s)-[rel:INVOKES {resourceName: $resourceName}]->(r)
                    SET rel.databaseType = $dbType,
                        rel.schemaName   = $schemaName,
                        rel.packageName  = $packageName,
                        rel.confidence   = 'HIGH'
                    """,
                    stepName=step_name, resourceName=resource_name, rtype=resource_type,
                    dbType=db_type, schemaName=schema_name, packageName=package_name,
                )
                created_count += 1

        logger.info(
            f"   Created {created_count} direct Step->Resource link(s) "
            f"(shell EXECUTES + procedure INVOKES) in knowledge graph"
        )

    def _copy_sql_resource_invokes_from_info_graph(self):
        """
        Copy SQL_SCRIPT Resource nodes and the shell→SQL INVOKES relationship
        from the Information Graph into the Knowledge Graph.

        IG source:
          Resource {type:'SHELL_SCRIPT'} -[:INVOKES {executionType:'SQL_SCRIPT'}]->
          Resource {type:'SQL_SCRIPT'}

        KG structure created:
          Resource {type:'SHELL_SCRIPT'} -[:INVOKES {executionType:'SQL_SCRIPT'}]->
          Resource {type:'SQL_SCRIPT'}

        SQL Resource nodes are MERGEd so re-runs are idempotent.
        """
        logger.info("Copying SQL_SCRIPT Resource nodes and INVOKES links from information graph...")

        # ── 1. Fetch all SQL_SCRIPT Resource nodes from IG ──────────────────
        sql_resources_query = """
        MATCH (r:Resource {type: 'SQL_SCRIPT'})
        RETURN r.name       AS name,
               r.id         AS id,
               r.scriptPath AS scriptPath,
               r.enabled    AS enabled,
               r.dynamicJob AS dynamicJob
        """

        # ── 2. Fetch all shell→SQL INVOKES relationships from IG ────────────
        invokes_query = """
        MATCH (sh:Resource {type: 'SHELL_SCRIPT'})-[r:INVOKES]->(sql:Resource {type: 'SQL_SCRIPT'})
        RETURN sh.name                AS shellName,
               sql.name               AS sqlName,
               r.executionType        AS executionType,
               coalesce(r.dynamicJob, false) AS dynamicJob
        """

        sql_rows    = []
        invoke_rows = []
        with self.driver.session(database=self.info_database) as session:
            sql_rows    = [dict(r) for r in session.run(sql_resources_query)]
            invoke_rows = [dict(r) for r in session.run(invokes_query)]

        if not sql_rows and not invoke_rows:
            logger.info("  No SQL_SCRIPT resources or INVOKES links found in information graph")
            return

        logger.info(
            f"  Found {len(sql_rows)} SQL_SCRIPT Resource(s) and "
            f"{len(invoke_rows)} INVOKES link(s) in IG"
        )

        with self.driver.session(database=self.database) as session:

            # Create / update SQL_SCRIPT Resource nodes in KG
            for row in sql_rows:
                session.run(
                    """
                    MERGE (r:Resource {name: $name, type: 'SQL_SCRIPT'})
                    ON CREATE SET r.id          = $id,
                                  r.scriptPath  = $scriptPath,
                                  r.enabled     = $enabled,
                                  r.dynamicJob  = $dynamicJob
                    ON MATCH  SET r.scriptPath  = COALESCE(r.scriptPath, $scriptPath)
                    """,
                    name=row["name"],
                    id=row["id"] or f"RES_SQL_{row['name'].replace('.','_').upper()}",
                    scriptPath=row.get("scriptPath") or "",
                    enabled=row.get("enabled", True),
                    dynamicJob=row.get("dynamicJob", False) or False,
                )

            logger.info(f"    Merged {len(sql_rows)} SQL_SCRIPT Resource(s) into KG")

            # Create INVOKES relationships between shell and SQL Resources in KG
            created = 0
            for row in invoke_rows:
                session.run(
                    """
                    MATCH (sh:Resource {name: $shellName, type: 'SHELL_SCRIPT'})
                    MATCH (sql:Resource {name: $sqlName,  type: 'SQL_SCRIPT'})
                    MERGE (sh)-[:INVOKES {executionType: 'SQL_SCRIPT'}]->(sql)
                    """,
                    shellName=row["shellName"],
                    sqlName=row["sqlName"],
                )
                created += 1

            logger.info(f"    Created {created} INVOKES (shell→SQL) relationship(s) in KG")

    def _load_resource_dependency(self, excel_file):
        """Load Resources Dependency"""
        df = pd.read_excel(excel_file, 'ResourceDependency')
        logger.info(f"Loading {len(df)} ResourceDependency...")
        with self.driver.session(database=self.database) as session:
            for _, row in df.iterrows():
                data = row.to_dict()
                # Handle NaN values
                data = {k: v for k, v in data.items() if pd.notna(v)}
                session.execute_write(self._associate_resource, data)
        
        logger.info(f" Loaded {len(df)} ResourceDependency")
    
    @staticmethod
    def _associate_resource(tx, data: Dict):
        """Transaction function to create Resource"""

        contextType = data.get('contextType', None)
        query = f"""
            MATCH (r:Resource {{id: $resourceId}})
            MATCH (ctx:{contextType} {{id: $requiresContextId}})
            MERGE (ctx)-[:Require_Resource]->(r)
            RETURN ctx, r
            """
        tx.run(query, **data)
    
    def _load_resources_from_graph(self):
        """Load Resource nodes from information graph"""
        logger.info("Loading Resource nodes from information graph...")
        
        query = """
        MATCH (r:Resource)
        WHERE r.id IS NOT NULL AND r.name IS NOT NULL
        RETURN r.id as id,
               r.name as name,
               r.type as type,
               r.enabled as enabled,
               r.schemaName as schemaName,
               r.packageName as packageName,
               r.ddlSnippet as ddlSnippet,
               r.description as description
        ORDER BY r.name
        """
        
        resources = []
        with self.driver.session(database=self.info_database) as session:
            result = session.run(query)
            for record in result:
                resources.append({
                    'id': record['id'],
                    'name': record['name'],
                    'type': record.get('type', ''),
                    'enabled': record.get('enabled', True),
                    'schemaName': record.get('schemaName', ''),
                    'packageName': record.get('packageName', ''),
                    'ddlSnippet': record.get('ddlSnippet', ''),
                    'description': record.get('description', '')
                })
        
        logger.info(f"  Found {len(resources)} Resource nodes in information graph")
        return resources
    
    def _load_resources(self, excel_file):
        """
        Load Resources - first from information graph, then from Excel.
        Skip Excel records if resource name already exists from information graph.
        """
        # Step 1: Load resources from information graph
        loaded_resource_names = set()
        resources_from_graph = self._load_resources_from_graph()
        
        if resources_from_graph:
            logger.info(f"Loading {len(resources_from_graph)} Resources from information graph into knowledge graph...")
            
            with self.driver.session(database=self.database) as session:
                for resource_data in resources_from_graph:
                    session.execute_write(self._create_resource, resource_data)
                    loaded_resource_names.add(resource_data['name'])
            
            logger.info(f" Loaded {len(resources_from_graph)} Resources from information graph")
        else:
            logger.info("No Resources found in information graph")
        
        # Step 2: Load resources from Excel (skip if already loaded from info graph)
        df = pd.read_excel(excel_file, 'Resources')
        logger.info(f"Processing {len(df)} Resources from Excel...")
        
        skipped_count = 0
        loaded_count = 0
        
        with self.driver.session(database=self.database) as session:
            for _, row in df.iterrows():
                data = row.to_dict()
                # Handle NaN values
                data = {k: v for k, v in data.items() if pd.notna(v)}
                
                # Skip if resource already loaded from info graph (matching by name)
                resource_name = data.get('name', '')
                if resource_name in loaded_resource_names:
                    logger.debug(f"  Skipping resource '{resource_name}' - already loaded from information graph")
                    skipped_count += 1
                    continue
                
                session.execute_write(self._create_resource, data)
                loaded_count += 1
        
        logger.info(f" Loaded {loaded_count} Resources from Excel, skipped {skipped_count} (already in info graph)")
        
    @staticmethod
    def _create_resource(tx, data: Dict):
        """Transaction function to create Resource"""
        node = ResourceNodeDef(
            id=str(data.get('id', '')),
            name=str(data.get('name', '')),
            type=str(data.get('type', '')),
            enabled=bool(data.get('enabled', True)),
            checkInterval=int(data.get('checkInterval', 0)),
            resourceLocation=str(data.get('filePath', '')),
            schemaName=str(data.get('schemaName', '')),
            packageName=str(data.get('packageName', ''))
        )
        description = str(data.get('description', ''))
        query = """
        MERGE (r:Resource {id: $id})
        SET r.name = $name,
            r.type = $type,
            r.enabled = $enabled
        """
        if node.checkInterval:
            query += ", r.checkInterval = $checkInterval"
        if node.resourceLocation:
            query += ", r.resourceLocation = $resourceLocation"
        if node.schemaName:
            query += ", r.schemaName = $schemaName"
        if node.packageName:
            query += ", r.packageName = $packageName"
        if description:
            query += ", r.description = $description"
        if 'tagId' in data:
            tagIds = data.get('tagId', None)
            for tagId in tagIds.strip('[]').split(","):
                tagIdStrip = tagId.strip()
                query += f"""
                    WITH r
                    MATCH (tg:Tag {{id: "{tagIdStrip}"}})
                    MERGE (r)-[:HAS_TAG]->(tg)
                """
                query += " RETURN r"
                tx.run(query, id=node.id, name=node.name, type=node.type,
                       enabled=node.enabled, checkInterval=node.checkInterval,
                       resourceLocation=node.resourceLocation, schemaName=node.schemaName,
                       packageName=node.packageName, description=description)
        else:
            query += " RETURN r"
            tx.run(query, id=node.id, name=node.name, type=node.type,
                   enabled=node.enabled, checkInterval=node.checkInterval,
                   resourceLocation=node.resourceLocation, schemaName=node.schemaName,
                   packageName=node.packageName, description=description)
        
    
    def _load_job_successors(self, excel_file):
        """Load Job Successors and create relationships"""
        df = pd.read_excel(excel_file, 'JobContext')
        logger.info(f"Loading {len(df)} JobSuccessor...")
        
        with self.driver.session(database=self.database) as session:
            for _, row in df.iterrows():
                data = row.to_dict()
                # Handle NaN values
                data = {k: v for k, v in data.items() if pd.notna(v)}
                session.execute_write(self._create_job_successor, data)
        
        logger.info(f" Loaded {len(df)} JobSuccessor")
    
    @staticmethod
    def _create_job_successor(tx, data: Dict):
        """Transaction function to create Context for Job and Job Group"""
        query = ""   
        is_start_job = data.get('start', None)
        successor = data.get('successor', None)
        is_successor_simple_or_parallel = data.get('block', None)
        if successor is not None:
            if is_successor_simple_or_parallel == "SIMPLE":
                query = f"""
                    MERGE (ctx:ScheduleInstanceContext {{id: $id}})
                    WITH ctx
                        MATCH (sctx:ScheduleInstanceContext {{id: $successor}})
                        MERGE (ctx)-[:PRECEDES {{on: 'COMPLETED'}}]->(sctx)
                                                    
                """
                if is_start_job is not None:
                    query += f"""
                        WITH ctx
                            MATCH (groupEntity:JobGroup {{id: $jobGroupId}})                    
                            MERGE (groupEntity)-[:ENTRY]->(ctx) 
                    """

                query += " RETURN ctx"
                #logger.info(f" Query for JobContext {context_type} is {query}")
                tx.run(query, **data)

            elif is_successor_simple_or_parallel == "PARALLEL":
                for s in successor.split(","):
                    successor_id = "'" + s.strip() + "'"
                    query = f"""
                        MERGE (ctx:ScheduleInstanceContext {{id: $id}})
                        WITH ctx
                            MATCH (sctx:ScheduleInstanceContext {{id: {successor_id}}})
                            MERGE (ctx)-[:PRECEDES {{on: 'COMPLETED'}}]->(sctx)
                                                        
                    """
                    if is_start_job is not None:
                        query += f"""
                            WITH ctx
                                MATCH (groupEntity:JobGroup {{id: $jobGroupId}})                    
                                MERGE (groupEntity)-[:ENTRY]->(ctx) 
                        """

                    query += " RETURN ctx"
                    #logger.info(f" Query for JobContext {context_type} is {query}")
                    tx.run(query, **data)
    
    def _load_job_contexts(self, excel_file):
        """Load Events and create relationships"""
        df = pd.read_excel(excel_file, 'JobContext')
        logger.info(f"Loading {len(df)} JobContext...")
        
        with self.driver.session(database=self.database) as session:
            for _, row in df.iterrows():
                data = row.to_dict()
                # Handle NaN values
                data = {k: v for k, v in data.items() if pd.notna(v)}
                session.execute_write(self._create_job_context, data)

        logger.info(f" Loaded {len(df)} JobContext")

    @staticmethod
    def _create_job_context(tx, data: Dict):
        """Transaction function to create Context for Job and Job Group"""
        context_for_entity_id = data['contextForEntityId']
        node = ScheduleInstanceContextNodeDef(
            id=str(data.get('id', '')),
            name=f'Context_{context_for_entity_id}',
            description=f'Context for {context_for_entity_id}',
            enabled=True,
            contextForEntityId=str(context_for_entity_id),
            estimatedDurationMs=int(data.get('estimatedDurationMs', 0))
        )
        job_group_id = data.get('jobGroupId', None)
        query = """
            MERGE (ctx:ScheduleInstanceContext {id: $id})
            SET ctx.name = $name,
                ctx.description = $description,
                ctx.enabled = $enabled,
                ctx.contextForEntityId = $contextForEntityId,
                ctx.estimatedDurationMs = $estimatedDurationMs
                WITH ctx
                    MATCH (entity:Job {id: $contextForEntityId})
                    MERGE (ctx)-[:FOR_JOB]->(entity)
        """
        if job_group_id is not None:
            query += """
                WITH ctx
                    MATCH (groupEntity:JobGroup {id: $jobGroupId})
                    MERGE (ctx)-[:FOR_GROUP]->(groupEntity)
            """
        query += " RETURN ctx"
        tx.run(query, id=node.id, name=node.name, description=node.description,
               enabled=node.enabled, contextForEntityId=node.contextForEntityId,
               estimatedDurationMs=node.estimatedDurationMs,
               jobGroupId=job_group_id)

    def _load_slas(self, excel_file):
        """Load SLAs and create relationships"""
        df = pd.read_excel(excel_file, 'SLAs')
        logger.info(f"Loading {len(df)} SLAs...")
        
        with self.driver.session(database=self.database) as session:
            for _, row in df.iterrows():
                data = row.to_dict()
                data = {k: v for k, v in data.items() if pd.notna(v)}
                session.execute_write(self._create_sla, data)
        
        logger.info(f" Loaded {len(df)} SLAs")
    
    @staticmethod
    def _create_sla(tx, data: Dict):
        """Transaction function to create SLA"""
        node = SLANodeDef(
            id=str(data.get('id', '')),
            name=str(data.get('name', '')),
            policy=str(data.get('policy', '')),
            severity=str(data.get('severity', '')),
            enabled=bool(data.get('enabled', True)),
            type=str(data.get('type', '')),
            durationMs=int(data.get('durationMs', 0)),
            time=str(data.get('time', '')),
            tz=str(data.get('tz', ''))
        )
        query = """
        MERGE (sla:SLA {id: $id})
        SET sla.name = $name,
            sla.policy = $policy,
            sla.severity = $severity,
            sla.enabled = $enabled,
            sla.type = $type
        """
        if node.time:
            query += ", sla.time = $time"
        if node.durationMs:
            query += ", sla.durationMs = $durationMs"
        if node.tz:
            query += ", sla.tz = $tz"
        if 'relativeEntityId' in data:
            relative_entity_type = data['relativeEntityType']
            query += f"""
                WITH sla
                MATCH (relativeEntity:{relative_entity_type} {{id: $relativeEntityId}})
                MERGE (sla)-[:RELATIVE_TO]->(relativeEntity)
            """
        entity_type = data['forEntityType']
        query += f"""
        WITH sla
        MATCH (entity:{entity_type} {{id: $forEntityId}})
        MERGE (entity)-[:HAS_SLA]->(sla)
        RETURN sla
        """
        tx.run(query, id=node.id, name=node.name, policy=node.policy,
               severity=node.severity, enabled=node.enabled, type=node.type,
               time=node.time, durationMs=node.durationMs, tz=node.tz,
               relativeEntityId=data.get('relativeEntityId'),
               relativeEntityType=data.get('relativeEntityType'),
               forEntityId=data.get('forEntityId'))

    def _load_associate_calendar(self, excel_file):
        """Load Associate Calendar"""
        df = pd.read_excel(excel_file, 'AssociateCalendar')
        logger.info(f"Loading {len(df)} AssociateCalendar...")
        with self.driver.session(database=self.database) as session:
            for _, row in df.iterrows():
                data = row.to_dict()
                data = {k: v for k, v in data.items() if pd.notna(v)}
                session.execute_write(self._associate_calendar, data)
        
        logger.info(f" Loaded {len(df)} AssociateCalendar")
    
    @staticmethod
    def _associate_calendar(tx, data: Dict):
        """Transaction function to create Calendar associations.
        requiresContextId may be blank (skip) or comma-separated (multiple entities).
        """
        allowed = data.get('Allowed')
        contextType = data.get('contextType')

        if allowed not in ('Y', 'N') or not contextType:
            return

        rel_type = 'CAN_EXECUTE_ON' if allowed == 'Y' else 'CANNOT_EXECUTE_ON'

        # requiresContextId may be absent (blank cell filtered out) or comma-separated
        raw_context_id = data.get('requiresContextId', '')
        if not str(raw_context_id).strip():
            return  # No entity to associate — skip

        context_ids = [cid.strip() for cid in str(raw_context_id).split(',') if cid.strip()]

        for context_id in context_ids:
            query = f"""
            MATCH (c:Calendar {{id: $calId}})
            MATCH (entity:{contextType} {{id: $entityId}})
            MERGE (entity)-[:{rel_type}]->(c)
            """
            tx.run(query, calId=data.get('id'), entityId=context_id)

    def _load_calendar(self, excel_file):
        """Load Calendar"""
        df = pd.read_excel(excel_file, 'Calendar')
        logger.info(f"Loading {len(df)} Calendar...")
        
        with self.driver.session(database=self.database) as session:
            for _, row in df.iterrows():
                data = row.to_dict()
                data = {k: v for k, v in data.items() if pd.notna(v)}
                session.execute_write(self._create_calendar, data)

        logger.info(f" Loaded {len(df)} Calendar")

    @staticmethod
    def _create_calendar(tx, data: Dict):
        """Transaction function to create Calendar"""
        node = CalendarNodeDef(
            id=str(data.get('id', '')),
            name=str(data.get('name', '')),
            type=str(data.get('type', '')),
            description=str(data.get('description', '')),
            enabled=bool(data.get('enabled', True)),
            startTime=str(data.get('startTime', '')),
            endTime=str(data.get('endTime', '')),
            tz=str(data.get('tz', ''))
        )
        if 'blockedDays' in data:
            node.blockedDays = [d.strip() for d in str(data['blockedDays']).split(',') if d.strip()]
        query = """
        MERGE (c:Calendar {id: $id})
        SET c.name = $name,
            c.type = $type,
            c.description = $description,
            c.enabled = $enabled
        """
        if node.blockedDays:
            query += ", c.blockedDays = $blockedDays"
        if node.startTime:
            query += ", c.startTime = $startTime"
        if node.endTime:
            query += ", c.endTime = $endTime"
        if node.tz:
            query += ", c.tz = $tz"
        query += " RETURN c"
        tx.run(query, id=node.id, name=node.name, type=node.type,
               description=node.description, enabled=node.enabled,
               blockedDays=node.blockedDays, startTime=node.startTime,
               endTime=node.endTime, tz=node.tz)
    
    def _load_holidays(self, excel_file):
        """Load Holidays and link to constraints"""
        df = pd.read_excel(excel_file, 'Holidays')
        logger.info(f"Loading {len(df)} Holidays...")
        
        with self.driver.session(database=self.database) as session:
            for _, row in df.iterrows():
                data = row.to_dict()
                session.execute_write(self._create_holiday, data)
        
        logger.info(f" Loaded {len(df)} Holidays")
    
    @staticmethod
    def _create_holiday(tx, data: Dict):
        """Transaction function to create Holiday and link to one or more Calendars.
        calendarId may be a single value or comma-separated list.
        """
        node = HolidayNodeDef(
            id=str(data.get('id', '')),
            name=str(data.get('name', '')),
            date=str(data.get('date', '')),
            enabled=bool(data.get('enabled', True))
        )

        # Create / update the Holiday node
        tx.run(
            """
            MERGE (h:Holiday {id: $id})
            SET h.name    = $name,
                h.date    = date($date),
                h.enabled = $enabled
            """,
            id=node.id, name=node.name, date=node.date, enabled=node.enabled
        )

        # calendarId can be a single value or comma-separated; may also be NaN
        raw_cal_id = data.get('calendarId')
        if raw_cal_id is None or (isinstance(raw_cal_id, float) and pd.isna(raw_cal_id)):
            return
        cal_ids = [cid.strip() for cid in str(raw_cal_id).split(',') if cid.strip()]

        for cal_id in cal_ids:
            tx.run(
                """
                MATCH (h:Holiday {id: $holidayId})
                MATCH (c:Calendar {id: $calId})
                MERGE (c)-[:BLOCKS_ON]->(h)
                """,
                holidayId=node.id, calId=cal_id
            )
    
    # ========================================================================
    # UTILITY METHODS
    # ========================================================================
    
    def clear_database(self):
        """Clear all nodes and relationships (use with caution!)"""
        logger.warning("Clearing entire database...")
        with self.driver.session(database=self.database) as session:
            session.run("MATCH (n) DETACH DELETE n")
        logger.info(" Database cleared")
    
    def get_statistics(self):
        """Get database statistics"""
        with self.driver.session(database=self.database) as session:
            result = session.run("""
                MATCH (n)
                RETURN labels(n)[0] as nodeType, count(n) as count
                ORDER BY count DESC
            """)
            
            stats = {}
            for record in result:
                stats[record['nodeType']] = record['count']
            
            return stats

def main():
    """Main execution function"""
    logger.info("=" * 70)
    logger.info("Spring Batch Knowledge Graph - Neo4j Direct Loader")
    logger.info("=" * 70)
    
    load_dotenv()
    config_path = os.getenv("KG_CONFIG_FILE") #or DEFAULT_CONFIG_FILE

    # Read class Excel path from config (fallback to default)
    class_excel = ''
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            cfg = yaml.safe_load(f) or {}
        class_excel = cfg.get('class_data', {}).get('excel_file', '')
    except FileNotFoundError:
        logger.warning(f"Config file not found at {config_path}; using default class Excel path")
    
    try:
        # Create loader and connect to Neo4j using config file
        with Neo4jLoader(config_path=config_path) as loader:

            # Step 0: Clean the database state
            logger.info("\n🧹 Step 0: Cleaning database state...")
            loader.clear_database()
            logger.info("    Database cleaned successfully")

            # Step 1: Create constraints and indexes
            logger.info("\n📐 Step 1: Creating constraints and indexes...")
            #loader.create_constraints_and_indexes()
            
            # Step 2: Load class-level data
            logger.info("\n Step 2: Loading class-level data...")
            loader.load_class_level_data(class_excel)

            # Step 3: Compute CPM for Job Groups
            #logger.info("\n🕒 Step 3: Computing CPM for Job Groups...")
            #analyzer = CPMAnalyzer(loader.driver)
            #loader.compute_cpm_for_jobgroup("JG_EOD", analyzer)
            #loader.compute_cpm_for_jobgroup("JG_MID", analyzer)
            #loader.compute_cpm_for_jobgroup("JG_TEST", analyzer)
            
            # Step 4: Show statistics
            logger.info("\n📈 Step 4: Database statistics...")
            stats = loader.get_statistics()
            for node_type, count in stats.items():
                logger.info(f"  {node_type}: {count}")

            logger.info("\n" + "=" * 70)
            logger.info(" LOADING COMPLETE!")
            logger.info("=" * 70)
            logger.info("🎉 Your data is now in Neo4j!")
    
    except Exception as e:
        logger.error(f"Error during loading: {str(e)}", exc_info=True)
        raise


if __name__ == "__main__":
    main()
