"""
Manual Resource Associator - Associate Resources with JavaMethods after manual resolution

This tool allows you to manually specify actual table names or procedure names for methods
that were marked with DYNAMIC_TABLE, UNKNOWN, or DYNAMIC_PROCEDURE during enrichment.

TWO MODES:
1. Update JavaMethod directly (default) - for specific DAO methods
2. Update JavaClass (Tasklet/Reader/Writer/Processor) - for generic methods called from multiple places

Usage:
    1. Create a YAML config file with manual mappings
    2. Run: python manual_resource_associator.py --config manual_mappings.yaml
    
    Or use interactive mode:
    3. Run: python manual_resource_associator.py --interactive

Config File Format (manual_mappings.yaml):
    db_operations:
      - method_fqn: "com.companyname.dao.BatchJobDAOImpl.getJobNamesHavingPauseStatus"
        operation_type: "SELECT"
        table_name: "batch_job"
        schema_name: "batch_schema"
        confidence: "HIGH"
      
      # For generic methods, specify tasklet/reader/writer/processor to update JavaClass
      - method_fqn: "com.companyname.dao.CustomerDAOImpl.executeQuery"
        writer_fqn: "com.companyname.batch.writer.CustomerItemWriter"  # Update Writer class
        operation_type: "UPDATE"
        table_name: "customer"
        confidence: "HIGH"
    
    procedure_calls:
      - method_fqn: "com.companyname.dao.CustomerDAOImpl.uploadLoadStatus"
        procedure_name: "UPLOAD_LOAD_STATUS"
        schema_name: "APMDATA"
        package_name: "PKG_BATCH"
        database_type: "ORACLE"
        is_function: false
      
      # For generic executeStoredProcedure method, specify tasklet and bean_id
      - method_fqn: "com.companyname.dao.BatchJobDAOImpl.executeStoredProcedure"
        tasklet_fqn: "com.companyname.batch.tasklet.StoredProcedureExecutorTasklet"
        bean_id: "storedProcedureExecutorTasklet"  # Required for class-level config
        procedure_name: "P_DATA_RESTORE_PROCESSOR"
        schema_name: "APMLOAD"
        database_type: "ORACLE"
        is_function: true
    
    shell_executions:
      - method_fqn: "com.companyname.util.ShellExecutor.runScript"
        tasklet_fqn: "com.companyname.batch.tasklet.DataMigrationTasklet"
        bean_id: "dataMigrationTasklet"  # Required for class-level config
        script_name: "data_migration.sh"
        script_path: "/opt/batch/scripts/data_migration.sh"
        script_type: "BASH"
        confidence: "HIGH"

HOW IT WORKS:
- Without tasklet/reader/writer/processor FQN: Updates the JavaMethod directly (original behavior)
- With tasklet/reader/writer/processor FQN + bean_id: Updates the Step node directly (using bean_id)
- Step consolidation collects from Step properties FIRST, then call chain (excluding tracked generic methods)
- bean_id creates composite key (method_fqn + bean_id) allowing same class to be used in multiple Steps
- This allows generic methods to be reused across 500+ Steps without conflict

"""

import os
import sys
import yaml
import uuid
import argparse

from typing import Dict, List, Optional
from neo4j import GraphDatabase
from dotenv import load_dotenv

import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - [%(pathname)s:%(lineno)d %(funcName)s] - %(message)s"
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Load configuration
config_file_path = os.getenv('KG_CONFIG_FILE', 'config/information_graph_config.yaml')
manual_mappings_file_path = os.getenv('MANUAL_MAPPINGS_FILE', 'config/manual_mappings_sample.yaml')
with open(config_file_path, 'r') as f:
    config = yaml.safe_load(f)

NEO4J_URI = config['neo4j']['uri']
NEO4J_USER = config['neo4j']['user']
NEO4J_PASSWORD = config['neo4j']['password']
NEO4J_DATABASE = config['neo4j']['database_ig']

# Load grey area keywords from config
GREY_AREA_KEYWORDS = config.get('grey_area_keywords', {})
CORE_KEYWORDS = GREY_AREA_KEYWORDS.get('core', ['UNKNOWN', 'DYNAMIC', 'PARAMETERIZED'])
DB_KEYWORDS = GREY_AREA_KEYWORDS.get('db_operations', [])
PROC_KEYWORDS = GREY_AREA_KEYWORDS.get('procedure_calls', [])
SHELL_KEYWORDS = GREY_AREA_KEYWORDS.get('shell_executions', [])
ENRICHER_PREFIXES = GREY_AREA_KEYWORDS.get('enricher_prefixes', [])


class ManualResourceAssociator:
    """
    Associates manually resolved Resource names with JavaMethod nodes.
    Creates Resource nodes if they don't exist and establishes relationships.
    """
    
    def __init__(self, uri: str, user: str, password: str, database: str = "informationgraph"):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self.database = database
        self.stats = {
            'db_operations_processed': 0,
            'procedure_calls_processed': 0,
            'shell_executions_processed': 0,
            'resources_created': 0,
            'relationships_created': 0,
            'errors': 0
        }
        # Track method FQNs that were configured with class-level updates
        # These are "generic" methods whose operations should be skipped during traversal
        # Key format: "method_fqn|bean_id" for composite uniqueness
        self.class_level_methods = set()
    
    def close(self):
        self.driver.close()

    def _resolve_method_fqn(self, method_fqn: str) -> Optional[str]:
        """
        Resolve a method_fqn from the YAML mapping to the actual FQN stored in Neo4j.

        Tries exact match first.  Falls back to classFqn + methodName lookup when the
        supplied FQN has no parameter list — this keeps existing mapping files working
        after the FQN format change (name-only → name(ParamTypes)).

        Returns the resolved FQN string, or None if not found.
        """
        with self.driver.session(database=self.database) as session:
            # 1. Exact match
            result = session.run(
                "MATCH (m:JavaMethod {fqn: $fqn}) RETURN m.fqn AS fqn LIMIT 1",
                fqn=method_fqn)
            record = result.single()
            if record:
                return record['fqn']

            # 2. Fallback — only when FQN has no parameter list (old format)
            if '(' in method_fqn:
                return None  # Already has signature, exact mismatch is a real error

            last_dot = method_fqn.rfind('.')
            if last_dot == -1:
                return None
            class_fqn_part = method_fqn[:last_dot]
            method_name_part = method_fqn[last_dot + 1:]

            result = session.run(
                "MATCH (m:JavaMethod {classFqn: $classFqn, methodName: $methodName}) "
                "RETURN m.fqn AS fqn",
                classFqn=class_fqn_part, methodName=method_name_part)
            records = [r['fqn'] for r in result]

            if len(records) == 1:
                logger.info(f"     FQN fallback resolved: '{method_fqn}' -> '{records[0]}'")
                return records[0]
            elif len(records) > 1:
                logger.warning(
                    f"     Ambiguous FQN: '{method_fqn}' matches {len(records)} overloads: {records}")
                logger.warning(
                    f"     Hint: update method_fqn to include parameter types, e.g. '{records[0]}'. "
                    f"Using first match for now.")
                return records[0]
            return None

    def associate_db_operation(self, method_fqn: str, operation_type: str, table_name: str, 
                                schema_name: str = None, confidence: str = "HIGH",
                                tasklet_fqn: str = None, reader_fqn: str = None,
                                writer_fqn: str = None, processor_fqn: str = None,
                                bean_id: str = None) -> bool:
        """
        Create TABLE Resource and DB_OPERATION relationship for a method.
        If tasklet/reader/writer/processor FQN + bean_id provided, updates Step directly.
        
        Args:
            method_fqn: Method fully qualified name
            operation_type: SELECT, INSERT, UPDATE, DELETE
            table_name: Actual table name
            schema_name: Optional schema/entity name
            confidence: HIGH, MEDIUM, LOW
            tasklet_fqn: Optional Tasklet class FQN to update at Step level
            reader_fqn: Optional ItemReader class FQN to update at Step level
            writer_fqn: Optional ItemWriter class FQN to update at Step level
            processor_fqn: Optional ItemProcessor class FQN to update at Step level
            bean_id: Required when using class FQN - identifies specific Step bean instance
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Resolve method FQN (with fallback for old-format mapping files)
            method_fqn = self._resolve_method_fqn(method_fqn)
            if not method_fqn:
                logger.error(f"   Method not found for fqn: {method_fqn}")
                self.stats['errors'] += 1
                return False

            with self.driver.session(database=self.database) as session:
                # Normalize values
                table_name = table_name.upper()
                operation_type = operation_type.upper()
                schema_name_norm = (schema_name or 'UNKNOWN').upper()
                
                # Generate unique ID for new resources
                unique_id = f"RES_TABLE_{uuid.uuid4().hex[:8].upper()}"
                
                # Create or update Resource node
                resource_query = """
                MERGE (r:Resource {name: $name, type: 'TABLE'})
                ON CREATE SET r.id = $id,
                              r.enabled = true,
                              r.schemaName = $schemaName,
                              r.foundInRepo = false,
                              r.notFoundInRepo = true,
                              r.manuallyResolved = true
                ON MATCH SET r.schemaName = COALESCE(r.schemaName, $schemaName),
                             r.manuallyResolved = true
                RETURN r.id as resourceId
                """
                result = session.run(resource_query,
                    name=table_name, id=unique_id, schemaName=schema_name_norm)
                if result.single():
                    logger.info(f"     Resource created/updated: {table_name}")
                    self.stats['resources_created'] += 1
                
                # Create relationship between JavaMethod and Resource
                relationship_query = """
                MATCH (m:JavaMethod {fqn: $method_fqn})
                MATCH (r:Resource {name: $name, type: 'TABLE'})
                MERGE (m)-[:DB_OPERATION {operationType: $operationType, confidence: $confidence, manuallyResolved: true}]->(r)
                """
                session.run(relationship_query,
                    method_fqn=method_fqn, name=table_name,
                    operationType=operation_type, confidence=confidence)
                logger.info(f"     Relationship created: {method_fqn} -[DB_OPERATION:{operation_type}]-> {table_name}")
                self.stats['relationships_created'] += 1
                
                # Build db operation value
                db_op_value = f"{operation_type}:{table_name}:{confidence}"
                
                # If tasklet/reader/writer/processor FQN specified, update Step directly
                class_fqn = tasklet_fqn or reader_fqn or writer_fqn or processor_fqn
                
                if class_fqn:
                    if not bean_id:
                        logger.error(f"     bean_id required when using class FQN")
                        self.stats['errors'] += 1
                        return False
                    
                    # Update Step node with dbOperations

                    # Find Step by bean_id — TASKLET steps use implBean, CHUNK steps use
                    # readerBean / writerBean / processorBean; check all four.
                    check_step_query = """
                    MATCH (s:Step)
                    WHERE s.implBean = $beanId OR s.readerBean = $beanId
                       OR s.writerBean = $beanId OR s.processorBean = $beanId
                    RETURN s.name as name
                    """
                    result = session.run(check_step_query, beanId=bean_id)
                    step_record = result.single()
                    if not step_record:
                        logger.error(f"     Step not found with bean_id (implBean/readerBean/writerBean/processorBean): {bean_id}")
                        self.stats['errors'] += 1
                        return False

                    update_step_query = """
                    MATCH (s:Step)
                    WHERE s.implBean = $beanId OR s.readerBean = $beanId
                       OR s.writerBean = $beanId OR s.processorBean = $beanId
                    WITH s,
                         CASE
                           WHEN s.stepDbOperations IS NULL THEN [$opValue]
                           WHEN any(op IN s.stepDbOperations WHERE
                                    op STARTS WITH $opType AND
                                    (op CONTAINS 'DYNAMIC' OR op CONTAINS 'UNKNOWN'))
                           THEN [op IN s.stepDbOperations |
                                   CASE WHEN (op STARTS WITH $opType AND
                                              (op CONTAINS 'DYNAMIC' OR op CONTAINS 'UNKNOWN'))
                                        THEN $opValue ELSE op END]
                           ELSE s.stepDbOperations + [$opValue]
                         END AS newOps
                    SET s.stepDbOperations = newOps,
                        s.stepDbOperationCount = size(newOps),
                        s.manuallyResolvedDbOps = true
                    """
                    session.run(update_step_query, beanId=bean_id, opValue=db_op_value,
                                opType=operation_type + ":")
                    logger.info(f"     Step updated: {step_record['name']} (beanId: {bean_id})")
                    logger.info(f"     Added: {db_op_value}")
                    # Track this method + bean combo as class-level configured (generic method)
                    composite_key = f"{method_fqn}|{bean_id}"
                    self.class_level_methods.add(composite_key)

                    # Also update method node so trace no longer reports it as grey area
                    session.run(
                        "MATCH (m:JavaMethod {fqn: $fqn}) SET m.furtherAnalysisRequired = false",
                        fqn=method_fqn)
                    logger.info(f"     Method updated: furtherAnalysisRequired=false")
                else:
                    # Original behavior: Update JavaMethod
                    update_method_query = """
                    MATCH (m:JavaMethod {fqn: $fqn})  
                    SET m.dbOperations = [op IN m.dbOperations | 
                        CASE 
                            WHEN op STARTS WITH $opType AND (op CONTAINS 'DYNAMIC' OR op CONTAINS 'UNKNOWN')
                            THEN $opValue
                            ELSE op
                        END
                    ],
                    m.furtherAnalysisRequired = false
                    """
                    session.run(update_method_query,
                        fqn=method_fqn,
                        opType=f"{operation_type}:",
                        opValue=db_op_value)
                    logger.info(f"     Method updated: furtherAnalysisRequired=false")
                self.stats['db_operations_processed'] += 1
                return True
                
        except Exception as e:
            logger.error(f"   Error associating DB operation: {e}")
            self.stats['errors'] += 1
            return False
    
    def associate_procedure_call(self, method_fqn: str, procedure_name: str, 
                                  schema_name: str = None, package_name: str = None,
                                  database_type: str = "UNKNOWN", is_function: bool = False,
                                  tasklet_fqn: str = None, reader_fqn: str = None,
                                  writer_fqn: str = None, processor_fqn: str = None,
                                  bean_id: str = None) -> bool:
        """
        Create PROCEDURE/FUNCTION Resource and INVOKES relationship for a method.
        If tasklet/reader/writer/processor FQN + bean_id provided, updates Step directly.
        
        Args:
            method_fqn: Method fully qualified name (the generic method that calls procedure)
            procedure_name: Actual procedure/function name
            schema_name: Database schema (e.g., APMDATA)
            package_name: Oracle package name (e.g., PKG_BATCH)
            database_type: ORACLE, DB2, POSTGRESQL, etc.
            is_function: True if function, False if procedure
            tasklet_fqn: Optional Tasklet class FQN to update at Step level
            reader_fqn: Optional ItemReader class FQN to update at Step level
            writer_fqn: Optional ItemWriter class FQN to update at Step level
            processor_fqn: Optional ItemProcessor class FQN to update at Step level
            bean_id: Required when using class FQN - identifies specific Step bean instance
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Resolve method FQN (with fallback for old-format mapping files)
            method_fqn = self._resolve_method_fqn(method_fqn)
            if not method_fqn:
                logger.error(f"   Method not found for fqn: {method_fqn}")
                self.stats['errors'] += 1
                return False

            with self.driver.session(database=self.database) as session:
                resource_type = 'FUNCTION' if is_function else 'PROCEDURE'
                unique_id = f"RES_PROC_{uuid.uuid4().hex[:8].upper()}"
                
                # Create or update Resource node with schema and package information
                # If creating new Resource (not from db_repo), mark as notFoundInRepo
                if package_name:
                    resource_query = """
                    MERGE (r:Resource {name: $name, type: $rtype})
                    ON CREATE SET r.id = $id,
                                  r.enabled = true,
                                  r.databaseType = $dbType,
                                  r.schemaName = $schemaName,
                                  r.packageName = $packageName,
                                  r.foundInRepo = false,
                                  r.notFoundInRepo = true,
                                  r.manuallyResolved = true
                    ON MATCH SET r.databaseType = COALESCE(r.databaseType, $dbType),
                                 r.schemaName = COALESCE(r.schemaName, $schemaName),
                                 r.packageName = COALESCE(r.packageName, $packageName),
                                 r.manuallyResolved = true
                    RETURN r.id as resourceId
                    """
                    result = session.run(resource_query,
                        name=procedure_name, rtype=resource_type, id=unique_id,
                        dbType=database_type,
                        schemaName=(schema_name or 'UNKNOWN').upper(),
                        packageName=package_name)
                else:
                    resource_query = """
                    MERGE (r:Resource {name: $name, type: $rtype})
                    ON CREATE SET r.id = $id,
                                  r.enabled = true,
                                  r.databaseType = $dbType,
                                  r.schemaName = $schemaName,
                                  r.foundInRepo = false,
                                  r.notFoundInRepo = true,
                                  r.manuallyResolved = true
                    ON MATCH SET r.databaseType = COALESCE(r.databaseType, $dbType),
                                 r.schemaName = COALESCE(r.schemaName, $schemaName),
                                 r.manuallyResolved = true
                    RETURN r.id as resourceId
                    """
                    result = session.run(resource_query,
                        name=procedure_name, rtype=resource_type, id=unique_id,
                        dbType=database_type,
                        schemaName=(schema_name or 'UNKNOWN').upper())
                if result.single():
                    logger.info(f"     Resource created/updated: {procedure_name} ({resource_type})")
                    self.stats['resources_created'] += 1
                
                # Create INVOKES relationship
                relationship_query = """
                MATCH (m:JavaMethod {fqn: $method_fqn})
                MATCH (r:Resource {name: $name, type: $rtype})
                MERGE (m)-[:INVOKES {databaseType: $dbType, confidence: 'HIGH', manuallyResolved: true}]->(r)
                """
                session.run(relationship_query,
                    method_fqn=method_fqn, name=procedure_name, rtype=resource_type,
                    dbType=database_type)
                logger.info(f"     Relationship created: {method_fqn} -[INVOKES]-> {procedure_name}")
                self.stats['relationships_created'] += 1
                
                # Build procedure call value
                schema_part = (schema_name or 'UNKNOWN').upper()
                package_part = package_name if package_name else 'NONE'
                proc_value = f"{schema_part}:{package_part}:{procedure_name}:{database_type}:{resource_type}:HIGH"
                
                # If tasklet/reader/writer/processor FQN specified, update Step directly
                class_fqn = tasklet_fqn or reader_fqn or writer_fqn or processor_fqn
                
                if class_fqn:
                    if not bean_id:
                        logger.error(f"     bean_id required when using class FQN")
                        self.stats['errors'] += 1
                        return False
                    
                    # Update Step node with procedureCalls

                    # Find Step by bean_id — TASKLET steps use implBean, CHUNK steps use
                    # readerBean / writerBean / processorBean; check all four.
                    check_step_query = """
                    MATCH (s:Step)
                    WHERE s.implBean = $beanId OR s.readerBean = $beanId
                       OR s.writerBean = $beanId OR s.processorBean = $beanId
                    RETURN s.name as name
                    """
                    result = session.run(check_step_query, beanId=bean_id)
                    step_record = result.single()
                    if not step_record:
                        logger.error(f"     Step not found with bean_id (implBean/readerBean/writerBean/processorBean): {bean_id}")
                        self.stats['errors'] += 1
                        return False

                    update_step_query = """
                    MATCH (s:Step)
                    WHERE s.implBean = $beanId OR s.readerBean = $beanId
                       OR s.writerBean = $beanId OR s.processorBean = $beanId
                    WITH s,
                         CASE
                           WHEN s.stepProcedureCalls IS NULL THEN [$procValue]
                           WHEN any(proc IN s.stepProcedureCalls WHERE
                                    proc CONTAINS 'DYNAMIC_PROCEDURE' OR
                                    (proc CONTAINS 'UNKNOWN' AND proc CONTAINS $rtypeToken))
                           THEN [proc IN s.stepProcedureCalls |
                                   CASE WHEN (proc CONTAINS 'DYNAMIC_PROCEDURE' OR
                                              (proc CONTAINS 'UNKNOWN' AND proc CONTAINS $rtypeToken))
                                        THEN $procValue ELSE proc END]
                           ELSE s.stepProcedureCalls + [$procValue]
                         END AS newCalls
                    SET s.stepProcedureCalls = newCalls,
                        s.stepProcedureCallCount = size(newCalls),
                        s.manuallyResolvedProcCalls = true
                    """
                    session.run(update_step_query, beanId=bean_id, procValue=proc_value,
                                rtypeToken=f":{resource_type}:")
                    logger.info(f"     Step updated: {step_record['name']} (beanId: {bean_id})")
                    logger.info(f"     Added: {proc_value}")
                    # Track this method + bean combo as class-level configured (generic method)
                    composite_key = f"{method_fqn}|{bean_id}"
                    self.class_level_methods.add(composite_key)

                    # Also update method node so trace no longer reports it as grey area
                    session.run(
                        "MATCH (m:JavaMethod {fqn: $fqn}) SET m.furtherAnalysisRequired = false",
                        fqn=method_fqn)
                    logger.info(f"     Method updated: furtherAnalysisRequired=false")
                else:
                    # Original behavior: Update JavaMethod
                    update_method_query = """
                    MATCH (m:JavaMethod {fqn: $fqn})  
                    SET m.procedureCalls = [proc IN m.procedureCalls | 
                        CASE 
                            WHEN (proc CONTAINS 'DYNAMIC_PROCEDURE' OR 
                                  (proc CONTAINS 'UNKNOWN' AND proc CONTAINS $dbTypeToken AND proc CONTAINS $rtypeToken))
                            THEN $procValue
                            ELSE proc
                        END
                    ],
                    m.furtherAnalysisRequired = false
                    """
                    session.run(update_method_query,
                        fqn=method_fqn,
                        dbTypeToken=f":{database_type}:",
                        rtypeToken=f":{resource_type}:",
                        procValue=proc_value)
                    logger.info(f"     Method updated: furtherAnalysisRequired=false")
                
                self.stats['procedure_calls_processed'] += 1
                return True
                
        except Exception as e:
            logger.error(f"   Error associating procedure call: {e}")
            self.stats['errors'] += 1
            return False
    
    def associate_shell_execution(self, method_fqn: str, script_name: str, 
                                   script_path: str = None, script_type: str = "BASH",
                                   remote_host: str = None, remote_user: str = None,
                                   remote_port: int = None, ssh_key_location: str = None,
                                   confidence: str = "HIGH", description: str = None,
                                   tasklet_fqn: str = None, reader_fqn: str = None,
                                   writer_fqn: str = None, processor_fqn: str = None,
                                   bean_id: str = None) -> bool:
        """
        Create SHELL_SCRIPT Resource and EXECUTES relationship for a method.
        If tasklet/reader/writer/processor FQN + bean_id provided, updates Step directly.
        
        Args:
            method_fqn: Method fully qualified name
            script_name: Script name/filename
            script_path: Full path to script
            script_type: BASH, PYTHON, POWERSHELL, BATCH, etc.
            remote_host: Remote hostname (if SSH execution)
            remote_user: Remote username
            remote_port: SSH port
            ssh_key_location: SSH key file location
            confidence: HIGH, MEDIUM, LOW
            description: Optional description
            tasklet_fqn: Optional Tasklet class FQN to update at Step level
            reader_fqn: Optional ItemReader class FQN to update at Step level
            writer_fqn: Optional ItemWriter class FQN to update at Step level
            processor_fqn: Optional ItemProcessor class FQN to update at Step level
            bean_id: Required when using class FQN - identifies specific Step bean instance
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Resolve method FQN (with fallback for old-format mapping files)
            method_fqn = self._resolve_method_fqn(method_fqn)
            if not method_fqn:
                logger.error(f"   Method not found for fqn: {method_fqn}")
                self.stats['errors'] += 1
                return False

            with self.driver.session(database=self.database) as session:
                # Generate unique ID for new resources
                unique_id = f"RES_SCRIPT_{uuid.uuid4().hex[:8].upper()}"
                
                # Determine execution type
                is_remote = remote_host is not None
                execution_type = "REMOTE" if is_remote else "LOCAL"
                
                # Build parameterized resource props
                res_params = {
                    'name': script_name,
                    'id': unique_id,
                    'scriptType': script_type,
                    'scriptPath': script_path if script_path else script_name,
                    'executionType': execution_type,
                    'description': description or '',
                }
                if is_remote:
                    res_params['remoteHost'] = remote_host
                    if remote_user:
                        res_params['remoteUser'] = remote_user
                    if remote_port:
                        res_params['remotePort'] = remote_port
                    if ssh_key_location:
                        res_params['sshKeyLocation'] = ssh_key_location
                
                # Build SET clauses that reference parameters by name
                static_sets = (
                    "r.id = $id, r.enabled = true, r.scriptType = $scriptType,"
                    " r.scriptPath = $scriptPath, r.executionType = $executionType,"
                    " r.manuallyResolved = true, r.description = $description"
                )
                if is_remote:
                    static_sets += ", r.remoteHost = $remoteHost"
                    if remote_user:  static_sets += ", r.remoteUser = $remoteUser"
                    if remote_port:  static_sets += ", r.remotePort = $remotePort"
                    if ssh_key_location: static_sets += ", r.sshKeyLocation = $sshKeyLocation"
                
                resource_query = f"""
                MERGE (r:Resource {{name: $name, type: 'SHELL_SCRIPT'}})
                ON CREATE SET {static_sets}
                ON MATCH SET r.scriptPath = $scriptPath, r.manuallyResolved = true
                RETURN r.id as resourceId
                """
                result = session.run(resource_query, **res_params)
                if result.single():
                    logger.info(f"     Resource created/updated: {script_name} ({script_type})")
                    if is_remote:
                        logger.info(f"      Remote: {remote_user}@{remote_host}:{script_path}")
                    else:
                        logger.info(f"      Local: {script_path}")
                    self.stats['resources_created'] += 1
                
                # Create EXECUTES relationship
                relationship_query = """
                MATCH (m:JavaMethod {fqn: $method_fqn})
                MATCH (r:Resource {name: $name, type: 'SHELL_SCRIPT'})
                MERGE (m)-[:EXECUTES {scriptType: $scriptType, confidence: $confidence, executionType: $executionType, manuallyResolved: true}]->(r)
                """
                session.run(relationship_query,
                    method_fqn=method_fqn, name=script_name,
                    scriptType=script_type, confidence=confidence,
                    executionType=execution_type)
                logger.info(f"     Relationship created: {method_fqn} -[EXECUTES]-> {script_name}")
                self.stats['relationships_created'] += 1
                
                # Build shell execution value
                shell_exec_value = f"RESOLVED:{script_name}:{confidence}"
                
                # If tasklet/reader/writer/processor FQN specified, update Step directly
                class_fqn = tasklet_fqn or reader_fqn or writer_fqn or processor_fqn
                
                if class_fqn:
                    if not bean_id:
                        logger.error(f"     bean_id required when using class FQN")
                        self.stats['errors'] += 1
                        return False
                    
                    # Update Step node with shellExecutions

                    # Find Step by bean_id — TASKLET steps use implBean, CHUNK steps use
                    # readerBean / writerBean / processorBean; check all four.
                    check_step_query = """
                    MATCH (s:Step)
                    WHERE s.implBean = $beanId OR s.readerBean = $beanId
                       OR s.writerBean = $beanId OR s.processorBean = $beanId
                    RETURN s.name as name
                    """
                    result = session.run(check_step_query, beanId=bean_id)
                    step_record = result.single()
                    if not step_record:
                        logger.error(f"     Step not found with bean_id (implBean/readerBean/writerBean/processorBean): {bean_id}")
                        self.stats['errors'] += 1
                        return False

                    update_step_query = """
                    MATCH (s:Step)
                    WHERE s.implBean = $beanId OR s.readerBean = $beanId
                       OR s.writerBean = $beanId OR s.processorBean = $beanId
                    WITH s,
                         CASE
                           WHEN s.stepShellExecutions IS NULL THEN [$shellValue]
                           WHEN any(exec IN s.stepShellExecutions WHERE
                                    exec CONTAINS 'UNKNOWN' OR exec CONTAINS 'DYNAMIC')
                           THEN [exec IN s.stepShellExecutions |
                                   CASE WHEN (exec CONTAINS 'UNKNOWN' OR exec CONTAINS 'DYNAMIC')
                                        THEN $shellValue ELSE exec END]
                           ELSE s.stepShellExecutions + [$shellValue]
                         END AS newExecs
                    SET s.stepShellExecutions = newExecs,
                        s.stepShellExecutionCount = size(newExecs),
                        s.manuallyResolvedShellExecs = true
                    """
                    session.run(update_step_query, beanId=bean_id, shellValue=shell_exec_value)
                    logger.info(f"     Step updated: {step_record['name']} (beanId: {bean_id})")
                    logger.info(f"     Added: {shell_exec_value}")
                    # Track this method + bean combo as class-level configured (generic method)
                    composite_key = f"{method_fqn}|{bean_id}"
                    self.class_level_methods.add(composite_key)

                    # Also update the method node so trace_unknown_operations no longer
                    # reports it as a grey area (class-level methods stay "unresolved" on
                    # the node otherwise, causing false alarms after manual resolution).
                    update_method_query = """
                    MATCH (m:JavaMethod {fqn: $fqn})
                    SET m.shellExecutions = CASE
                        WHEN $shellValue IN m.shellExecutions THEN m.shellExecutions
                        WHEN size(m.shellExecutions) = 1 AND NOT m.shellExecutions[0] STARTS WITH 'RESOLVED:'
                        THEN [$shellValue]
                        ELSE [exec IN m.shellExecutions WHERE exec STARTS WITH 'RESOLVED:'] + [$shellValue]
                    END,
                    m.furtherAnalysisRequired = false
                    """
                    session.run(update_method_query, fqn=method_fqn, shellValue=shell_exec_value)
                    logger.info(f"     Method updated: furtherAnalysisRequired=false")
                else:
                    # Original behavior: Update JavaMethod
                    # Strategy: Replace grey area entries with RESOLVED entry (idempotent)
                    # A grey area entry is one that doesn't start with "RESOLVED:" and contains incomplete/error info
                    update_method_query = """
                    MATCH (m:JavaMethod {fqn: $fqn})  
                    SET m.shellExecutions = CASE
                        WHEN $shellValue IN m.shellExecutions THEN m.shellExecutions
                        WHEN size(m.shellExecutions) = 1 AND NOT m.shellExecutions[0] STARTS WITH 'RESOLVED:' 
                        THEN [$shellValue]
                        ELSE [exec IN m.shellExecutions WHERE exec STARTS WITH 'RESOLVED:'] + [$shellValue]
                    END,
                    m.furtherAnalysisRequired = false
                    """
                    session.run(update_method_query, fqn=method_fqn, shellValue=shell_exec_value)
                    logger.info(f"     Method updated: shellExecutions updated with RESOLVED entry")
                    logger.info(f"     Method updated: furtherAnalysisRequired=false")
        except Exception as e:
            logger.error(f"   Error associating shell execution: {e}")
            self.stats['errors'] += 1
            return False
    
    def _consolidate_all_steps(self):
        """
        Consolidate all operations (DB, procedures, shell) at Step level.
        This is called ONCE after all manual fixes are complete.
        Similar to db_operation_enricher._consolidate_step_db_operations but handles all operation types.
        """
        logger.info("\n" + "="*80)
        logger.info("CONSOLIDATING STEP OPERATIONS")
        logger.info("="*80)
        
        # Get all Steps
        query_steps = """
        MATCH (s:Step)
        RETURN s.name as stepName, 
               s.stepKind as stepKind,
               s.implBean as implBean,
               s.readerBean as readerBean,
               s.processorBean as processorBean,
               s.writerBean as writerBean,
               elementId(s) as stepId,
               s.stepDbOperations as stepDbOps,
               s.stepProcedureCalls as stepProcCalls,
               s.stepShellExecutions as stepShellExecs
        """
        
        with self.driver.session(database=self.database) as session:
            result = session.run(query_steps)
            steps_data = [dict(record) for record in result]
        
        logger.info(f"  Found {len(steps_data)} Steps to consolidate")
        
        steps_updated = 0
        
        for step_data in steps_data:
            step_name = step_data['stepName']
            step_kind = step_data['stepKind']
            step_id = step_data['stepId']
            # Collect all non-null beans for this step (TASKLET has implBean;
            # CHUNK has readerBean/processorBean/writerBean)
            step_bean_ids = {b for b in [
                step_data.get('implBean'),
                step_data.get('readerBean'),
                step_data.get('processorBean'),
                step_data.get('writerBean'),
            ] if b}
            
            if not step_kind:
                continue
            
            # Determine entry method names based on step kind
            if step_kind == "TASKLET":
                entry_method_names = ["execute"]
            elif step_kind == "CHUNK":
                entry_method_names = ["read", "process", "write"]
            else:
                continue
            
            # BFS traversal to collect all operations from call graph
            all_db_operations = set()
            all_procedure_calls = set()
            all_shell_executions = set()
            
            # NEW: First, collect from Step properties (manually resolved operations)
            # ONLY keep RESOLVED entries - discard all grey area/unresolved entries
            # Grey area indicators: UNKNOWN, DYNAMIC, PARAMETERIZED, or entries from enrichers (Runtime.exec, CommonsExec, etc.)
            if step_data.get('stepDbOps'):
                for op in step_data['stepDbOps']:
                    # Keep only if it starts with RESOLVED: or doesn't contain grey area keywords
                    if op.startswith('RESOLVED:') or not any(kw in op for kw in CORE_KEYWORDS):
                        all_db_operations.add(op)
            if step_data.get('stepProcCalls'):
                for proc in step_data['stepProcCalls']:
                    if proc.startswith('RESOLVED:') or not any(kw in proc for kw in CORE_KEYWORDS):
                        all_procedure_calls.add(proc)
            if step_data.get('stepShellExecs'):
                for shell in step_data['stepShellExecs']:
                    # Only keep RESOLVED entries or clean entries (not from enricher detection)
                    is_enricher_entry = any(prefix in shell for prefix in ENRICHER_PREFIXES)
                    if shell.startswith('RESOLVED:') or (not is_enricher_entry and not any(kw in shell for kw in CORE_KEYWORDS)):
                        all_shell_executions.add(shell)
            
            # Find entry methods for this Step AND get JavaClass properties
            # Support inheritance: traverse EXTENDS chain to find inherited methods
            query_entry_methods = """
            MATCH (s:Step)
            WHERE elementId(s) = $stepId
            MATCH (s)-[:IMPLEMENTED_BY]->(jc:JavaClass)
            
            // Find methods in the class or its parent hierarchy (up to 10 levels)
            CALL (jc) {
                // Check direct methods first (closest in hierarchy)
                MATCH (jc)-[:HAS_METHOD]->(m:JavaMethod)
                WHERE m.methodName IN $methodNames
                RETURN elementId(m) as methodId, 
                       m.methodName as methodName,
                       m.fqn as methodFqn,
                       m.dbOperations as dbOps,
                       m.procedureCalls as procCalls,
                       m.shellExecutions as shellExecs,
                       0 as inheritanceDepth
                
                UNION
                
                // Check parent classes (up to 10 levels of inheritance)
                MATCH path = (jc)-[:EXTENDS*1..10]->(parent:JavaClass)
                MATCH (parent)-[:HAS_METHOD]->(m:JavaMethod)
                WHERE m.methodName IN $methodNames
                RETURN elementId(m) as methodId, 
                       m.methodName as methodName,
                       m.fqn as methodFqn,
                       m.dbOperations as dbOps,
                       m.procedureCalls as procCalls,
                       m.shellExecutions as shellExecs,
                       length(path) as inheritanceDepth
            }
            
            // Return the method closest in the inheritance hierarchy (prefer child overrides)
            WITH methodId, methodName, methodFqn, dbOps, procCalls, shellExecs, inheritanceDepth
            ORDER BY inheritanceDepth ASC
            RETURN methodId, methodName, methodFqn, dbOps, procCalls, shellExecs
            LIMIT 3  // For TASKLET: 1 execute, For CHUNK: read, write, process
            """
            
            with self.driver.session(database=self.database) as session:
                result = session.run(query_entry_methods, 
                                    stepId=step_id, 
                                    methodNames=entry_method_names)
                entry_methods = [dict(record) for record in result]
            
            if not entry_methods:
                continue
            
            for entry_method in entry_methods:
                method_id = entry_method['methodId']
                method_fqn = entry_method.get('methodFqn')
                
                # Check if this method was configured with class-level update (generic method) for THIS STEP
                # Use composite key: method_fqn|bean_id — check against ALL beans of this step
                # (CHUNK steps have reader/processor/writer beans, not implBean)
                # If so, skip its operations (already collected from Step properties)
                # If not, include ALL operations (even UNKNOWN/DYNAMIC) for human review
                is_class_level_method = method_fqn is not None and any(
                    f"{method_fqn}|{bid}" in self.class_level_methods
                    for bid in step_bean_ids
                )
                
                if not is_class_level_method:
                    # Add operations from entry method itself (include UNKNOWN/DYNAMIC)
                    if entry_method.get('dbOps'):
                        all_db_operations.update(entry_method['dbOps'])
                    if entry_method.get('procCalls'):
                        all_procedure_calls.update(entry_method['procCalls'])
                    if entry_method.get('shellExecs'):
                        all_shell_executions.update(entry_method['shellExecs'])
                
                # BFS traversal
                visited = set()
                queue = [method_id]
                visited.add(method_id)
                
                while queue:
                    current_id = queue.pop(0)
                    
                    # Get all called methods
                    query_calls = """
                    MATCH (m:JavaMethod)-[:CALLS]->(called:JavaMethod)
                    WHERE elementId(m) = $methodId
                    RETURN elementId(called) as calledId,
                           called.fqn as calledFqn,
                           called.dbOperations as dbOps,
                           called.procedureCalls as procCalls,
                           called.shellExecutions as shellExecs
                    """
                    
                    with self.driver.session(database=self.database) as session2:
                        result = session2.run(query_calls, methodId=current_id)
                        called_methods = [dict(record) for record in result]
                    
                    for called in called_methods:
                        called_id = called['calledId']
                        called_fqn = called.get('calledFqn')
                        
                        if called_id not in visited:
                            visited.add(called_id)
                            queue.append(called_id)
                            
                            # Check if this called method was configured with class-level update for THIS STEP
                            # Use composite key: method_fqn|bean_id — check against ALL beans of this step
                            # If so, skip its operations (already handled at Step level)
                            # If not, include ALL operations (even UNKNOWN/DYNAMIC)
                            is_class_level_called = called_fqn is not None and any(
                                f"{called_fqn}|{bid}" in self.class_level_methods
                                for bid in step_bean_ids
                            )
                            
                            if not is_class_level_called:
                                # Collect operations from called method (include UNKNOWN/DYNAMIC)
                                if called.get('dbOps'):
                                    all_db_operations.update(called['dbOps'])
                                if called.get('procCalls'):
                                    all_procedure_calls.update(called['procCalls'])
                                if called.get('shellExecs'):
                                    all_shell_executions.update(called['shellExecs'])
            
            # Update Step with recalculated operations
            step_db_ops = sorted(list(all_db_operations))
            step_proc_calls = sorted(list(all_procedure_calls))
            step_shell_execs = sorted(list(all_shell_executions))
            
            
            query_update = """
            MATCH (s:Step)
            WHERE elementId(s) = $stepId
            SET s.stepDbOperations = $dbOps,
                s.stepDbOperationCount = $dbOpCount,
                s.stepProcedureCalls = $procCalls,
                s.stepProcedureCallCount = $procCallCount,
                s.stepShellExecutions = $shellExecs,
                s.stepShellExecutionCount = $shellExecCount,
                s.lastUpdated = datetime()
            RETURN s.name as name
            """
            
            with self.driver.session(database=self.database) as session:
                session.run(query_update, 
                           stepId=step_id,
                           dbOps=step_db_ops,
                           dbOpCount=len(step_db_ops),
                           procCalls=step_proc_calls,
                           procCallCount=len(step_proc_calls),
                           shellExecs=step_shell_execs,
                           shellExecCount=len(step_shell_execs))
            
            logger.info(f"    Step '{step_name}': {len(step_db_ops)} DB ops, "
                      f"{len(step_proc_calls)} proc calls, {len(step_shell_execs)} shell execs")
            steps_updated += 1
        
        logger.info(f"\n  Updated {steps_updated} Steps with consolidated operations")
        logger.info("="*80)
    
    def process_config_file(self, config_path: str = manual_mappings_file_path):
        """
        Process manual mappings from YAML config file.
        
        Args:
            config_path: Path to YAML config file
        """
        logger.info("\n" + "="*80)
        logger.info("MANUAL RESOURCE ASSOCIATION")
        logger.info("="*80)
        logger.info(f"Config File: {config_path}\n")
        
        try:
            with open(config_path, 'r') as f:
                mappings = yaml.safe_load(f)
        except FileNotFoundError:
            logger.error(f" Config file not found: {config_path}")
            return
        except yaml.YAMLError as e:
            logger.error(f" Invalid YAML format: {e}")
            return
        
        # Process DB operations
        db_operations = mappings.get('db_operations', [])
        if db_operations:
            logger.info(f"Processing {len(db_operations)} DB operations:\n")
            for idx, op in enumerate(db_operations, 1):
                method_fqn = op.get('method_fqn')
                operation_type = op.get('operation_type')
                table_name = op.get('table_name')
                schema_name = op.get('schema_name')
                confidence = op.get('confidence', 'HIGH')
                tasklet_fqn = op.get('tasklet_fqn')
                reader_fqn = op.get('reader_fqn')
                writer_fqn = op.get('writer_fqn')
                processor_fqn = op.get('processor_fqn')
                bean_id = op.get('bean_id')
                
                if not all([method_fqn, operation_type, table_name]):
                    logger.error(f"  [{idx}]  Missing required fields: method_fqn, operation_type, table_name")
                    self.stats['errors'] += 1
                    continue
                
                logger.info(f"  [{idx}] {method_fqn}")
                if tasklet_fqn or reader_fqn or writer_fqn or processor_fqn:
                    class_type = 'Tasklet' if tasklet_fqn else ('Reader' if reader_fqn else ('Writer' if writer_fqn else 'Processor'))
                    class_fqn = tasklet_fqn or reader_fqn or writer_fqn or processor_fqn
                    logger.info(f"      Target: {class_type} JavaClass - {class_fqn}")
                logger.info(f"      Operation: {operation_type} on table '{table_name}'")
                self.associate_db_operation(method_fqn, operation_type, table_name, schema_name, 
                                           confidence, tasklet_fqn, reader_fqn, writer_fqn, processor_fqn, bean_id)
                
        
        # Process procedure calls
        procedure_calls = mappings.get('procedure_calls', [])
        if procedure_calls:
            logger.info(f"Processing {len(procedure_calls)} procedure calls:\n")
            for idx, proc in enumerate(procedure_calls, 1):
                method_fqn = proc.get('method_fqn')
                procedure_name = proc.get('procedure_name')
                schema_name = proc.get('schema_name')
                package_name = proc.get('package_name')
                database_type = proc.get('database_type', 'UNKNOWN')
                is_function = proc.get('is_function', False)
                tasklet_fqn = proc.get('tasklet_fqn')
                reader_fqn = proc.get('reader_fqn')
                writer_fqn = proc.get('writer_fqn')
                processor_fqn = proc.get('processor_fqn')
                bean_id = proc.get('bean_id')
                
                if not all([method_fqn, procedure_name]):
                    logger.error(f"  [{idx}]  Missing required fields: method_fqn, procedure_name")
                    self.stats['errors'] += 1
                    continue
                
                logger.info(f"  [{idx}] {method_fqn}")
                if tasklet_fqn or reader_fqn or writer_fqn or processor_fqn:
                    class_type = 'Tasklet' if tasklet_fqn else ('Reader' if reader_fqn else ('Writer' if writer_fqn else 'Processor'))
                    class_fqn = tasklet_fqn or reader_fqn or writer_fqn or processor_fqn
                    logger.info(f"      Target: {class_type} JavaClass - {class_fqn}")
                # Build display name with hierarchy
                display_name = procedure_name
                if package_name:
                    display_name = f"{package_name}.{display_name}"
                if schema_name:
                    display_name = f"{schema_name}.{display_name}"
                logger.info(f"      Procedure: {display_name} ({database_type})")
                self.associate_procedure_call(method_fqn, procedure_name, schema_name, package_name, 
                                            database_type, is_function, tasklet_fqn, reader_fqn, 
                                            writer_fqn, processor_fqn, bean_id)
                logger.info("")
        
        # Process shell executions
        shell_executions = mappings.get('shell_executions', [])
        if shell_executions:
            logger.info(f"Processing {len(shell_executions)} shell executions:\n")
            for idx, shell in enumerate(shell_executions, 1):
                method_fqn = shell.get('method_fqn')
                script_name = shell.get('script_name')
                script_path = shell.get('script_path')
                script_type = shell.get('script_type', 'BASH')
                remote_host = shell.get('remote_host')
                remote_user = shell.get('remote_user')
                remote_port = shell.get('remote_port')
                ssh_key_location = shell.get('ssh_key_location')
                confidence = shell.get('confidence', 'HIGH')
                description = shell.get('description')
                tasklet_fqn = shell.get('tasklet_fqn')
                reader_fqn = shell.get('reader_fqn')
                writer_fqn = shell.get('writer_fqn')
                processor_fqn = shell.get('processor_fqn')
                bean_id = shell.get('bean_id')
                
                if not all([method_fqn, script_name]):
                    logger.error(f"  [{idx}]  Missing required fields: method_fqn, script_name")
                    self.stats['errors'] += 1
                    continue
                
                logger.info(f"  [{idx}] {method_fqn}")
                if tasklet_fqn or reader_fqn or writer_fqn or processor_fqn:
                    class_type = 'Tasklet' if tasklet_fqn else ('Reader' if reader_fqn else ('Writer' if writer_fqn else 'Processor'))
                    class_fqn = tasklet_fqn or reader_fqn or writer_fqn or processor_fqn
                    logger.info(f"      Target: {class_type} JavaClass - {class_fqn}")
                logger.info(f"      Script: {script_name} ({script_type})")
                if remote_host:
                    logger.info(f"      Execution: REMOTE ({remote_user}@{remote_host})")
                else:
                    logger.info(f"      Execution: LOCAL")
                self.associate_shell_execution(
                    method_fqn, script_name, script_path, script_type,
                    remote_host, remote_user, remote_port, ssh_key_location,
                    confidence, description, tasklet_fqn, reader_fqn, writer_fqn, processor_fqn, bean_id
                )
                logger.info("")
        
        # Consolidate all Step operations ONCE after all fixes
        if db_operations or procedure_calls or shell_executions:
            self._consolidate_all_steps()
        
        # Print statistics
        self.print_statistics()
    
    def print_statistics(self):
        """Print processing statistics"""
        logger.info("="*80)
        logger.info("STATISTICS")
        logger.info("="*80)
        logger.info(f"  DB Operations Processed:     {self.stats['db_operations_processed']}")
        logger.info(f"  Procedure Calls Processed:   {self.stats['procedure_calls_processed']}")
        logger.info(f"  Shell Executions Processed:  {self.stats['shell_executions_processed']}")
        logger.info(f"  Resources Created/Updated:   {self.stats['resources_created']}")
        logger.info(f"  Relationships Created:       {self.stats['relationships_created']}")
        logger.info(f"  Errors:                      {self.stats['errors']}")
        logger.info("="*80)
        
        if self.stats['errors'] == 0:
            logger.info(" MANUAL RESOURCE ASSOCIATION COMPLETE")
        else:
            logger.info(f"  COMPLETED WITH {self.stats['errors']} ERRORS")
        logger.info("="*80 + "\n")


def create_sample_config():
    """Create a sample configuration file"""
    sample_config = {
        'db_operations': [
            {
                'method_fqn': 'com.companyname.dao.BatchJobDAOImpl.getJobNamesHavingPauseStatus',
                'operation_type': 'SELECT',
                'table_name': 'batch_job',
                'schema_name': 'batch_schema',
                'confidence': 'HIGH'
            },
            {
                # Example: For generic methods, specify reader/writer/processor FQN + bean_id
                'method_fqn': 'com.companyname.dao.GenericDAO.executeQuery',
                'writer_fqn': 'com.companyname.batch.writer.CustomerItemWriter',
                'bean_id': 'customerItemWriter',  # Required for class-level config
                'operation_type': 'UPDATE',
                'table_name': 'customer',
                'schema_name': 'batch_schema',
                'confidence': 'HIGH'
            }
        ],
        'procedure_calls': [
            {
                'method_fqn': 'com.companyname.dao.CustomerDAOImpl.uploadLoadStatus',
                'procedure_name': 'UPLOAD_LOAD_STATUS',
                'database_type': 'ORACLE',
                'is_function': False
            },
            {
                # Example: For generic methods, specify tasklet/reader/writer/processor FQN + bean_id
                'method_fqn': 'com.companyname.dao.BatchJobDAOImpl.executeStoredProcedure',
                'tasklet_fqn': 'com.companyname.batch.tasklet.StoredProcedureExecutorTasklet',
                'bean_id': 'customerStoredProcedureTasklet',  # Required for class-level config
                'procedure_name': 'P_DATA_RESTORE_PROCESSOR',
                'schema_name': 'APMLOAD',
                'database_type': 'ORACLE',
                'is_function': True
            }
        ],
        'shell_executions': [
            {
                # Example with tasklet FQN + bean_id
                'method_fqn': 'com.companyname.util.ShellExecutor.runScript',
                'tasklet_fqn': 'com.companyname.batch.tasklet.DataMigrationTasklet',
                'bean_id': 'dataMigrationTasklet',  # Required for class-level config
                'script_name': 'data_migration.sh',
                'script_path': '/opt/batch/scripts/data_migration.sh',
                'script_type': 'BASH',
                'confidence': 'HIGH'
            }
        ]
    }
    
    output_path = 'manual_mappings_sample.yaml'
    with open(output_path, 'w') as f:
        yaml.dump(sample_config, f, default_flow_style=False, sort_keys=False)
    
    logger.info(f"\n Sample config file created: {output_path}")
    logger.info("Edit this file with your actual mappings and run:")
    logger.info(f"   python manual_resource_associator.py --config {output_path}\n")


def main():
    
    # Create associator and process
    associator = ManualResourceAssociator(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, NEO4J_DATABASE)
    
    try:
        associator.process_config_file(manual_mappings_file_path)
    finally:
        associator.close()


if __name__ == "__main__":
    main()
