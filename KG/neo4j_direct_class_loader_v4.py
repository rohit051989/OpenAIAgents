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
from typing import Dict, List
import logging
import yaml
import os
from dotenv import load_dotenv
from neo4j_direct_step_loader import generate_cypher
from cpm_analyzer_v1 import CPMAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
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
        
        logger.info("✓ Constraints and indexes created")
    
    def compute_cpm_for_jobgroup(self, jobgroup_id: str, analyzer: CPMAnalyzer):
        res = analyzer.compute_for_jobgroup(jobgroup_id, persist=True)
        print(f"\n=== CPM Summary for {jobgroup_id} ===")
        print("SLA(ms):", res.group_sla_ms)
        print("Completion(ms):", res.completion_ms)
        print("Total Buffer(ms):", res.total_buffer_ms)
        print("Longest Path:", " -> ".join(res.longest_path))
            


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
        self._load_steps()
        self._load_resource_dependency(excel_file)
        self._load_slas(excel_file)
        self._load_calendar(excel_file)
        self._load_associate_calendar(excel_file)
        self._load_holidays(excel_file)
        #self._load_step_interaction(excel_file)
        logger.info("✓ Class-level data loaded successfully")
    
    def _load_job_groups(self, excel_file):
        """Load JobGroups"""
        df = pd.read_excel(excel_file, 'JobGroups')
        logger.info(f"Loading {len(df)} JobGroups...")
        
        with self.driver.session(database=self.database) as session:
            for _, row in df.iterrows():
                session.execute_write(self._create_job_group, row.to_dict())
        
        logger.info(f"✓ Loaded {len(df)} JobGroups")
    
    @staticmethod
    def _create_job_group(tx, data: Dict):
        """Transaction function to create JobGroup"""
        query = """
        MERGE (jg:JobGroup {id: $id})
        SET jg.name = $name,
            jg.description = $description,
            jg.priority = $priority,
            jg.enabled = $enabled,
            jg.createdAt = datetime()
        RETURN jg
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
        
        logger.info(f"✓ Loaded {len(df)} Tags")
    
    @staticmethod
    def _create_tag(tx, data: Dict):
        """Transaction function to create Tag"""
        query = """
        MERGE (tg:Tag {id: $id})
        SET tg.name = $name,
            tg.description = $description,
            tg.tagType = $tagType,
            tg.enabled = $enabled,
            tg.createdAt = datetime()
        RETURN tg
        """
        tx.run(query, **data)
    
    def _load_jobs_from_graph(self):
        """Load Job nodes from information graph"""
        logger.info("Loading Job nodes from information graph...")
        
        query = """
        MATCH (j:Job)
        WHERE j.id IS NOT NULL AND j.name IS NOT NULL
        RETURN j.id as id,
               j.name as name,
               j.enabled as enabled,
               j.sourceFile as sourceFile
        ORDER BY j.name
        """
        
        jobs = []
        with self.driver.session(database=self.info_database) as session:
            result = session.run(query)
            for record in result:
                jobs.append({
                    'id': record['id'],
                    'name': record['name'],
                    'enabled': record.get('enabled', True),
                    'sourceFile': record.get('sourceFile', '')
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
        
        logger.info(f"✓ Loaded {len(jobs)} Jobs")
    

    @staticmethod
    def _create_job(tx, data: Dict):
        """Transaction function to create Job from information graph data"""
        query = """
        MERGE (j:Job {name: $name})
        SET j.id = $id,
            j.enabled = $enabled,
            j.createdAt = datetime()
        """
        
        # Add sourceFile if available
        if data.get('sourceFile'):
            query += ", j.sourceFile = $sourceFile"
        
        query += " RETURN j"
        
        tx.run(query, **data)
    
    def _load_jobs_association(self, excel_file):
        """Load Jobs and create relationships to JobGroups"""
        df = pd.read_excel(excel_file, 'AssociatedJobs')
        logger.info(f"Loading {len(df)} Jobs Association...")
        
        with self.driver.session(database=self.database) as session:
            for _, row in df.iterrows():
                data = row.to_dict()
                session.execute_write(self._create_job_association, data)
        
        logger.info(f"✓ Loaded {len(df)} Jobs Association")

    @staticmethod
    def _create_job_association(tx, data: Dict):
        """Transaction function to create Job and link to JobGroup"""
        query = """
        MATCH (j:Job {id: $jobId})
        MATCH (jg:JobGroup {id: $jobGroupId})
        MERGE (jg)-[:HAS_JOB]->(j)
        RETURN j
        """
        tx.run(query, **data)
        

    def _load_spring_xml_files_from_graph(self) -> List[str]:
        """
        Load Spring XML configuration files from the information graph.
        
        This method queries the graph for nodes with SpringConfig label
        instead of scanning the file system.
        
        Returns:
            List of absolute file paths to Spring XML configuration files
        """
        logger.info("Loading Spring XML files from information graph...")
        
        query = """
        MATCH (f:SpringConfig)
        WHERE f.path IS NOT NULL
        RETURN f.path as path, f.name as name
        ORDER BY f.path
        """
        
        spring_xml_files = []
        
        with self.driver.session(database=self.info_database) as session:
            result = session.run(query)
            for record in result:
                file_path = record['path']
                spring_xml_files.append(file_path)
        
        logger.info(f"  Found {len(spring_xml_files)} Spring XML files in information graph")
        return spring_xml_files
    
    def _find_java_source_from_graph(self, class_name: str) -> str:
        """
        Find Java source file path for a given class name from the information graph.
        
        This method queries the graph for JavaClass nodes with matching FQN
        instead of scanning the file system.
        
        Args:
            class_name: Fully qualified class name (e.g., "com.example.MyClass")
            
        Returns:
            Absolute path to the Java source file, or empty string if not found
        """
        if not class_name:
            return ""
        
        # Skip external library classes
        if not class_name.startswith("com."):
            return ""
        
        query = """
        MATCH (j:JavaClass)
        WHERE j.fqn = $class_name
        RETURN j.path as path
        LIMIT 1
        """
        
        with self.driver.session(database=self.info_database) as session:
            result = session.run(query, class_name=class_name)
            record = result.single()
            
            if record:
                return record.get('path', "")
        
        return ""
    
    def _build_global_bean_map_from_graph(self, spring_xml_files: List[str]) -> Dict[str, tuple]:
        """
        Build a global bean map from Spring XML files using information graph for source paths.
        
        This method parses Spring XML files but queries the information graph
        to resolve Java source file paths instead of scanning the file system.
        
        Args:
            spring_xml_files: List of Spring XML file paths
            
        Returns:
            Dictionary mapping bean ID to tuple of (class_name, source_path)
        """
        import xml.etree.ElementTree as ET
        
        logger.info("Building global bean map using information graph...")
        global_bean_map = {}
        
        BEANS_NS = "http://www.springframework.org/schema/beans"
        N_BEANS = f"{{{BEANS_NS}}}"
        
        for xml_file in spring_xml_files:
            try:
                tree = ET.parse(xml_file)
                root = tree.getroot()
                
                # Extract bean definitions
                for bean_el in root.findall(f".//{N_BEANS}bean"):
                    bean_id = bean_el.get("id")
                    bean_class = bean_el.get("class", "")
                    
                    if bean_id and bean_class:
                        # Query information graph for source path
                        source_path = self._find_java_source_from_graph(bean_class)
                        global_bean_map[bean_id] = (bean_class, source_path)
                        
            except Exception as e:
                logger.warning(f"Failed to process {xml_file}: {e}")
        
        # Count beans with source paths
        with_source = sum(1 for _, source_path in global_bean_map.values() if source_path)
        logger.info(f"  Built bean map: {len(global_bean_map)} beans, {with_source} with source paths")
        
        return global_bean_map
    
    def _load_steps(self):
        
        """Load Steps and create relationships to Jobs"""
        # Query information graph for Spring XML files instead of scanning file system
        spring_xml_files = self._load_spring_xml_files_from_graph()
        
        if not spring_xml_files:
            logger.warning("No Spring XML files found in information graph")
            return
        
        # Build bean map using information graph
        global_bean_map = self._build_global_bean_map_from_graph(spring_xml_files)
        
        # Parse Spring Batch XML files with the bean map
        from neo4j_direct_step_loader import parse_spring_batch_xml
        
        job_defs = []
        for xml_file in spring_xml_files:
            try:
                parsed_jobs = parse_spring_batch_xml(xml_file, global_bean_map)
                job_defs.extend(parsed_jobs)
            except Exception as e:
                logger.warning(f"Failed to parse {xml_file}: {e}")
        logger.info(f"Parsed {len(job_defs)} job definitions from information graph")
        
        for job_def in job_defs:
            cypher = generate_cypher(job_def)
            logger.info(f"Loading Steps for job '{job_def.name}'...")
            statements = [s.strip() for s in cypher.split(";") if s.strip()]    
            with self.driver.session(database=self.database) as session:
                for stmt in statements:
                    #logger.info(f"Executing Cypher:: {stmt[:500]}...")
                    session.run(stmt)

            logger.info(f"✓ Loaded {len(statements)} statements for job '{job_def.name}'")
        
        # Copy consolidated DB operations from information graph
        self._copy_step_db_operations_from_info_graph()
    
    def _copy_step_db_operations_from_info_graph(self):
        """
        Copy consolidated stepDbOperations from information graph to knowledge graph.
        
        This creates DataAsset nodes and relationships similar to _associate_step_interaction,
        but derives the data from the information graph's JavaMethod nodes instead of Excel.
        
        Structure created:
        Step -[READS_FROM/WRITES_TO/DELETES_FROM/AGGREGATES_ON]-> DataAsset -[FOR_RESOURCE]-> Resource
        """
        logger.info("Creating DataAsset nodes from information graph DB operations...")
        
        # Query information graph for Steps with JavaMethods that have DB operations
        query_step_methods = """
        MATCH (s:Step)-[:IMPLEMENTED_BY]->(jc:JavaClass)-[:HAS_METHOD]->(m:JavaMethod)
        WHERE m.dbOperations IS NOT NULL AND m.dbOperationCount > 0
        RETURN s.name as stepName,
               collect({
                   methodName: m.methodName,
                   methodFqn: m.fqn,
                   dbOperations: m.dbOperations
               }) as methodsWithOps
        
        UNION
        
        MATCH (s:Step)-[:IMPLEMENTED_BY]->(jc:JavaClass)-[:HAS_METHOD]->(entry:JavaMethod)
        MATCH path = (entry)-[:CALLS*]->(called:JavaMethod)
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
        
        # Create DataAsset nodes and relationships for each step
        created_count = 0
        for step_name, methods in steps_data.items():
            # Group operations by unique combination
            unique_ops = {}
            for method_info in methods:
                method_fqn = method_info['methodFqn']
                method_name = method_info['methodName']
                
                for db_op in method_info['dbOperations']:
                    op_key = f"{step_name}_{db_op}_{method_fqn}"
                    if op_key not in unique_ops:
                        unique_ops[op_key] = {
                            'operation': db_op,
                            'methodReference': method_fqn,
                            'methodName': method_name
                        }
            
            # Create DataAsset and relationships for each unique operation
            for op_key, op_data in unique_ops.items():
                db_operation = op_data['operation']
                method_reference = op_data['methodReference']
                method_name = op_data['methodName']
                
                operation_type = get_operation_type(db_operation)
                resource_type = get_resource_type(db_operation)
                
                # Parse db_operation to extract resource name
                # Format: OPERATION:RESOURCE_NAME:PRIORITY (e.g., "SELECT:CUSTOMER:HIGH")
                parts = db_operation.split(':')
                if len(parts) >= 2:
                    resource_name = parts[1].strip()  # Extract the resource/table name
                    resource_id = f"RESOURCE_{resource_type}_{resource_name}"
                else:
                    # Fallback if format is different
                    resource_name = f"Auto-generated {resource_type}"
                    resource_id = f"RESOURCE_{resource_type}_AUTO"
                
                # Create DataAsset and link to Step and Resource
                query_create = """
                // Ensure Resource exists
                MERGE (r:Resource {name: $resourceName, type: $resourceType})
                ON CREATE SET r.id = $resourceId,
                              r.name = $resourceName,
                              r.type = $resourceType,
                              r.enabled = true,
                              r.description = 'Auto-generated from information graph'
                
                // Create DataAsset
                MERGE (di:DataAsset {id: $dataAssetId})
                SET di.description = $description,
                    di.method = $method,
                    di.methodReference = $methodReference,
                    di.enabled = true
                
                // Link DataAsset to Resource
                MERGE (di)-[:FOR_RESOURCE]->(r)
                
                // Link Step to DataAsset based on operation type
                WITH di, r
                MATCH (s:Step {name: $stepName})
                """
                
                # Add relationship based on operation type
                if operation_type == 'READ':
                    query_create += "MERGE (s)-[:READS_FROM]->(di)"
                elif operation_type == 'INSERT':
                    query_create += "MERGE (s)-[:WRITES_TO]->(di)"
                elif operation_type == 'DELETE':
                    query_create += "MERGE (s)-[:DELETES_FROM]->(di)"
                elif operation_type == 'AGGREGATE':
                    query_create += "MERGE (s)-[:AGGREGATES_ON]->(di)"
                
                query_create += "\nRETURN di, r, s"
                
                with self.driver.session(database=self.database) as session:
                    session.run(query_create,
                               resourceId=resource_id,
                               resourceName=resource_name,
                               resourceType=resource_type,
                               dataAssetId=op_key,
                               description=f"{operation_type} operation: {db_operation}",
                               method=method_name,
                               methodReference=method_reference,
                               stepName=step_name)
                    created_count += 1
        
        logger.info(f"  ✓ Created {created_count} DataAsset nodes with relationships in knowledge graph")
    
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
        
        logger.info(f"✓ Loaded {len(df)} ResourceDependency")
    
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
    
    def _load_resources(self, excel_file):
        """Load Resources"""
        df = pd.read_excel(excel_file, 'Resources')
        logger.info(f"Loading {len(df)} Resources...")
        
        with self.driver.session(database=self.database) as session:
            for _, row in df.iterrows():
                data = row.to_dict()
                # Handle NaN values
                data = {k: v for k, v in data.items() if pd.notna(v)}
                session.execute_write(self._create_resource, data)
        
        logger.info(f"✓ Loaded {len(df)} Resources")
        
    @staticmethod
    def _create_resource(tx, data: Dict):
        """Transaction function to create Resource"""
        query = """
        MERGE (r:Resource {id: $id})
        SET r.name = $name,
            r.type = $type,
            r.enabled = $enabled
        """
        if 'checkInterval' in data:
            query += ", r.checkInterval = $checkInterval"
        if 'filePath' in data:
            query += ", r.resourceLocation = $filePath"
        if 'schemaName' in data:
            query += ", r.schemaName = $schemaName"
        if 'description' in data:
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
                tx.run(query, **data)
        else:
            query += " RETURN r"
            tx.run(query, **data)
        
    def _load_step_interaction(self, excel_file):
        """Load Step Interaction"""
        df = pd.read_excel(excel_file, 'DataInteraction_v2')
        logger.info(f"Loading {len(df)} DataInteraction_v2...")
        with self.driver.session(database=self.database) as session:
            for _, row in df.iterrows():
                data = row.to_dict()
                # Handle NaN values
                data = {k: v for k, v in data.items() if pd.notna(v)}
                session.execute_write(self._associate_step_interaction, data)
        
        logger.info(f"✓ Loaded {len(df)} DataInteraction_v2")
    
    @staticmethod
    def _associate_step_interaction(tx, data: Dict):
        """Transaction function to associate step interaction"""

        entityType = data.get('entityType', None)
        methodReference = data.get('methodReference', "NOT_SPECIFIED")
        query = f"""
            Merge (di: DataAsset{{id: $id}})
            SET di.description = $description,
                di.method = $method,
                di.methodReference = "{methodReference}",
                di.enabled = $enabled
            WITH di
            MATCH (r:Resource {{id: $dataInteractionId}})
            MERGE (di)-[:FOR_RESOURCE]->(r)
            WITH di, r
        """
        dataInteractionOperationType = data.get('dataInteractionOperationType', None)
        if dataInteractionOperationType == "READ":
            query += f"""
            MATCH (entity:{entityType} {{name: $entityId}})
            WITH di, r, entity
            MERGE (entity)-[:READS_FROM]->(di)
            RETURN di, entity, r
            """
        elif dataInteractionOperationType == "INSERT":
            query +=  f"""
            MATCH (entity:{entityType} {{name: $entityId}})
            WITH di, r, entity
            MERGE (entity)-[:WRITES_TO]->(di)
            RETURN di, entity, r
            """
        elif dataInteractionOperationType == "DELETE":
            query +=  f"""
            MATCH (entity:{entityType} {{name: $entityId}})
            WITH di, r, entity
            MERGE (entity)-[:DELETES_FROM]->(di)
            RETURN di, entity, r
            """
        elif dataInteractionOperationType == "AGGREGATE":
            query +=  f"""
            MATCH (entity:{entityType} {{name: $entityId}})
            WITH di, r, entity
            MERGE (entity)-[:AGGREGATES_ON]->(di)
            RETURN di, entity, r
            """
        else:
            query +=   """
                RETURN di, r
                """
        #print("Executing Step Interaction Query:", query, " with data:", data)
        tx.run(query, **data)        
    
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
        
        logger.info(f"✓ Loaded {len(df)} JobSuccessor")
    
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
                #logger.info(f"✓ Query for JobContext {context_type} is {query}")
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
                    #logger.info(f"✓ Query for JobContext {context_type} is {query}")
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

        logger.info(f"✓ Loaded {len(df)} JobContext")

    @staticmethod
    def _create_job_context(tx, data: Dict):
        """Transaction function to create Context for Job and Job Group"""
        context_for_entity_id = data['contextForEntityId']
        rel_type = 'FOR_GROUP'
        query = ""        
        entity_label = 'Job'
        rel_type = 'FOR_JOB'
        job_group_id = data.get('jobGroupId', None)
        query = f"""
            MERGE (ctx:ScheduleInstanceContext {{id: $id}})
            SET ctx.name = 'Context_{context_for_entity_id}',
                ctx.description = 'Context for {context_for_entity_id}',
                ctx.enabled = true,
                ctx.contextForEntityId = '{context_for_entity_id}',
                ctx.estimatedDurationMs = $estimatedDurationMs
                WITH ctx
                    MATCH (entity:{entity_label} {{id: $contextForEntityId}})
                    MERGE (ctx)-[:{rel_type}]->(entity)
                                            
        """
        if job_group_id is not None:
            query += f"""
                WITH ctx
                    MATCH (groupEntity:JobGroup {{id: $jobGroupId}})                        
                    MERGE (ctx)-[:FOR_GROUP]->(groupEntity) 
            """

        query += " RETURN ctx"
        #logger.info(f"✓ Query for JobContext {context_type} is {query}")
        tx.run(query, **data)

    def _load_slas(self, excel_file):
        """Load SLAs and create relationships"""
        df = pd.read_excel(excel_file, 'SLAs')
        logger.info(f"Loading {len(df)} SLAs...")
        
        with self.driver.session(database=self.database) as session:
            for _, row in df.iterrows():
                data = row.to_dict()
                data = {k: v for k, v in data.items() if pd.notna(v)}
                session.execute_write(self._create_sla, data)
        
        logger.info(f"✓ Loaded {len(df)} SLAs")
    
    @staticmethod
    def _create_sla(tx, data: Dict):
        """Transaction function to create SLA"""
        query = """
        MERGE (sla:SLA {id: $id})
        SET sla.name = $name,
            sla.policy = $policy,
            sla.severity = $severity,
            sla.enabled = $enabled,
            sla.type = $type
        """
        
        if 'time' in data:
            query += ", sla.time = $time"
        if 'durationMs' in data:
            query += ", sla.durationMs = $durationMs"
        if 'tz' in data:
            query += ", sla.tz = $tz"
        
        if 'relativeEntityId' in data:
            relative_entity_type = data['relativeEntityType']
            query += f"""
                WITH sla
                MATCH (relativeEntity:{relative_entity_type} {{id: $relativeEntityId}})
                MERGE (sla)-[:RELATIVE_TO_RESOURCE]->(relativeEntity)
            """
        # Link to entity
        entity_type = data['forEntityType']
        query += f"""
        WITH sla
        MATCH (entity:{entity_type} {{id: $forEntityId}})
        MERGE (entity)-[:HAS_SLA]->(sla)
        RETURN sla
        """
        
        tx.run(query, **data)

    def _load_associate_calendar(self, excel_file):
        """Load Associate Calendar"""
        df = pd.read_excel(excel_file, 'AssociateCalendar')
        logger.info(f"Loading {len(df)} AssociateCalendar...")
        with self.driver.session(database=self.database) as session:
            for _, row in df.iterrows():
                data = row.to_dict()
                data = {k: v for k, v in data.items() if pd.notna(v)}
                session.execute_write(self._associate_calendar, data)
        
        logger.info(f"✓ Loaded {len(df)} AssociateCalendar")
    
    @staticmethod
    def _associate_calendar(tx, data: Dict):
        """Transaction function to create Calendar"""
        allowed = data['Allowed']
        contextType = data.get('contextType', None)
        query = ""
        # Create Allowed/Disallowed Calendar Association with JobGroup
        if allowed == 'Y':
            query += f"""
            MATCH (c:Calendar {{id: $id}})
            MATCH (entity:{contextType} {{id: $requiresContextId}})
            MERGE (entity)-[:CAN_EXECUTE_ON]->(c)
            """
        elif allowed == 'N':
            query += f"""
            MATCH (c:Calendar {{id: $id}})
            MATCH (entity:{contextType} {{id: $requiresContextId}})
            MERGE (entity)-[:CANNOT_EXECUTE_ON]->(c)
            """
        # Link to entity
        query += f"""
        RETURN c
        """        
        tx.run(query, **data)

    def _load_calendar(self, excel_file):
        """Load Calendar"""
        df = pd.read_excel(excel_file, 'Calendar')
        logger.info(f"Loading {len(df)} Calendar...")
        
        with self.driver.session(database=self.database) as session:
            for _, row in df.iterrows():
                data = row.to_dict()
                data = {k: v for k, v in data.items() if pd.notna(v)}
                session.execute_write(self._create_calendar, data)

        logger.info(f"✓ Loaded {len(df)} Calendar")

    @staticmethod
    def _create_calendar(tx, data: Dict):
        """Transaction function to create Calendar"""
        query = """
        MERGE (c:Calendar {id: $id})
        SET c.name = $name,
            c.type = $type,
            c.description = $description,
            c.enabled = $enabled
        """
        
        if 'blockedDays' in data:
            query += ", c.blockedDays = $blockedDays"
        if 'startTime' in data:
            query += ", c.startTime = $startTime"
        if 'endTime' in data:
            query += ", c.endTime = $endTime"
        if 'tz' in data:
            query += ", c.tz = $tz"
        
        # Link to entity
        query += f"""
        RETURN c
        """
        
        tx.run(query, **data)
    
    def _load_holidays(self, excel_file):
        """Load Holidays and link to constraints"""
        df = pd.read_excel(excel_file, 'Holidays')
        logger.info(f"Loading {len(df)} Holidays...")
        
        with self.driver.session(database=self.database) as session:
            for _, row in df.iterrows():
                data = row.to_dict()
                session.execute_write(self._create_holiday, data)
        
        logger.info(f"✓ Loaded {len(df)} Holidays")
    
    @staticmethod
    def _create_holiday(tx, data: Dict):
        """Transaction function to create Holiday"""
        query = """
        MERGE (h:Holiday {id: $id})
        SET h.name = $name,
            h.date = date($date),
            h.enabled = $enabled
        WITH h
        MATCH (c:Calendar {id: $calendarId})
        MERGE (c)-[:BLOCKS_ON]->(h)
        RETURN h
        """
        tx.run(query, **data)
    
    # ========================================================================
    # UTILITY METHODS
    # ========================================================================
    
    def clear_database(self):
        """Clear all nodes and relationships (use with caution!)"""
        logger.warning("Clearing entire database...")
        with self.driver.session(database=self.database) as session:
            session.run("MATCH (n) DETACH DELETE n")
        logger.info("✓ Database cleared")
    
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
    print("=" * 70)
    print("Spring Batch Knowledge Graph - Neo4j Direct Loader")
    print("=" * 70)
    print()
    
    # Configuration
    #DEFAULT_CONFIG_FILE = r"D:\Iris\practice\GenAI\code\Batch_KG\information_graph_config.yaml"
    DEFAULT_CLASS_EXCEL = "sample_data/class_level_data_1.xlsx"

    load_dotenv()
    config_file = os.getenv("KG_CONFIG_FILE") #or DEFAULT_CONFIG_FILE

    # Read class Excel path from config (fallback to default)
    class_excel = DEFAULT_CLASS_EXCEL
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            cfg = yaml.safe_load(f) or {}
        class_excel = cfg.get('class_data', {}).get('excel_file', DEFAULT_CLASS_EXCEL)
    except FileNotFoundError:
        logger.warning(f"Config file not found at {config_file}; using default class Excel path")
    
    try:
        # Create loader and connect to Neo4j using config file
        with Neo4jLoader(config_path=config_file) as loader:

            # Step 0: Clean the database state
            print("\n🧹 Step 0: Cleaning database state...")
            loader.clear_database()
            print("   ✓ Database cleaned successfully")

            # Step 1: Create constraints and indexes
            print("\n📐 Step 1: Creating constraints and indexes...")
            loader.create_constraints_and_indexes()
            
            # Step 2: Load class-level data
            print("\n📦 Step 2: Loading class-level data...")
            loader.load_class_level_data(class_excel)

            # Step 3: Compute CPM for Job Groups
            #print("\n🕒 Step 3: Computing CPM for Job Groups...")
            #analyzer = CPMAnalyzer(loader.driver)
            #loader.compute_cpm_for_jobgroup("JG_EOD", analyzer)
            #loader.compute_cpm_for_jobgroup("JG_MID", analyzer)
            #loader.compute_cpm_for_jobgroup("JG_TEST", analyzer)
            
            # Step 4: Show statistics
            print("\n📈 Step 4: Database statistics...")
            stats = loader.get_statistics()
            for node_type, count in stats.items():
                print(f"  {node_type}: {count}")
            
            print("\n" + "=" * 70)
            print("✅ LOADING COMPLETE!")
            print("=" * 70)
            print()
            print("🎉 Your data is now in Neo4j!")
            print()
    
    except Exception as e:
        logger.error(f"Error during loading: {str(e)}", exc_info=True)
        raise


if __name__ == "__main__":
    main()
