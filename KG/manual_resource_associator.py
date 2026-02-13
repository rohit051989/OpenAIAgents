"""
Manual Resource Associator - Associate Resources with JavaMethods after manual resolution

This tool allows you to manually specify actual table names or procedure names for methods
that were marked with DYNAMIC_TABLE, UNKNOWN, or DYNAMIC_PROCEDURE during enrichment.

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
      
      - method_fqn: "com.companyname.dao.CustomerDAOImpl.deleteById"
        operation_type: "DELETE"
        table_name: "customer"
        confidence: "HIGH"
    
    procedure_calls:
      - method_fqn: "com.companyname.dao.CustomerDAOImpl.uploadLoadStatus"
        procedure_name: "UPLOAD_LOAD_STATUS"
        database_type: "ORACLE"
        is_function: false
"""

import os
import sys
import yaml
import uuid
import argparse
import logging
from typing import Dict, List, Optional
from neo4j import GraphDatabase
from dotenv import load_dotenv

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
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


def escape_cypher_string(s: str) -> str:
    """Escape single quotes in Cypher string literals"""
    if s is None:
        return ""
    return str(s).replace("'", "\\\\'")


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
    
    def close(self):
        self.driver.close()
    
    def associate_db_operation(self, method_fqn: str, operation_type: str, table_name: str, 
                                schema_name: str = None, confidence: str = "HIGH") -> bool:
        """
        Create TABLE Resource and DB_OPERATION relationship for a method.
        
        Args:
            method_fqn: Method fully qualified name
            operation_type: SELECT, INSERT, UPDATE, DELETE
            table_name: Actual table name
            schema_name: Optional schema/entity name
            confidence: HIGH, MEDIUM, LOW
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Verify method exists
            with self.driver.session(database=self.database) as session:
                check_query = "MATCH (m:JavaMethod {fqn: $fqn}) RETURN m.name as name"
                result = session.run(check_query, fqn=method_fqn)
                if not result.single():
                    logger.error(f"   Method not found: {method_fqn}")
                    self.stats['errors'] += 1
                    return False
                
                # Normalize values
                table_name = table_name.upper()
                operation_type = operation_type.upper()
                
                escaped_method_fqn = escape_cypher_string(method_fqn)
                escaped_table_name = escape_cypher_string(table_name)
                escaped_operation_type = escape_cypher_string(operation_type)
                escaped_confidence = escape_cypher_string(confidence)
                escaped_schema_name = escape_cypher_string(schema_name if schema_name else "UNKNOWN")
                
                # Generate unique ID for new resources
                unique_id = f"RES_TABLE_{uuid.uuid4().hex[:8].upper()}"
                escaped_resource_id = escape_cypher_string(unique_id)
                
                # Create or update Resource node
                resource_query = f"""
                MERGE (r:Resource {{name: '{escaped_table_name}', type: 'TABLE'}})
                ON CREATE SET r.id = '{escaped_resource_id}',
                              r.enabled = true,
                              r.schemaName = '{escaped_schema_name}',
                              r.manuallyResolved = true
                ON MATCH SET r.schemaName = COALESCE(r.schemaName, '{escaped_schema_name}'),
                             r.manuallyResolved = true
                RETURN r.id as resourceId
                """
                result = session.run(resource_query)
                if result.single():
                    logger.info(f"     Resource created/updated: {table_name}")
                    self.stats['resources_created'] += 1
                
                # Create relationship between JavaMethod and Resource
                relationship_query = f"""
                MATCH (m:JavaMethod {{fqn: '{escaped_method_fqn}'}})
                MATCH (r:Resource {{name: '{escaped_table_name}', type: 'TABLE'}})
                MERGE (m)-[:DB_OPERATION {{
                    operationType: '{escaped_operation_type}',
                    confidence: '{escaped_confidence}',
                    manuallyResolved: true
                }}]->(r)
                """
                session.run(relationship_query)
                logger.info(f"     Relationship created: {method_fqn} -[DB_OPERATION:{operation_type}]-> {table_name}")
                self.stats['relationships_created'] += 1
                
                # Update method's dbOperations property to reflect resolved table
                update_method_query = f"""
                MATCH (m:JavaMethod {{fqn: '{escaped_method_fqn}'}})
                SET m.dbOperations = [op IN m.dbOperations | 
                    CASE 
                        WHEN op CONTAINS 'DYNAMIC' OR op CONTAINS 'UNKNOWN'
                        THEN '{escaped_operation_type}:{escaped_table_name}:{escaped_confidence}'
                        ELSE op
                    END
                ],
                m.furtherAnalysisRequired = false
                """
                session.run(update_method_query)
                logger.info(f"     Method updated: furtherAnalysisRequired=false")
                
                self.stats['db_operations_processed'] += 1
                return True
                
        except Exception as e:
            logger.error(f"   Error associating DB operation: {e}")
            self.stats['errors'] += 1
            return False
    
    def associate_procedure_call(self, method_fqn: str, procedure_name: str, 
                                  database_type: str = "UNKNOWN", is_function: bool = False) -> bool:
        """
        Create PROCEDURE/FUNCTION Resource and INVOKES relationship for a method.
        
        Args:
            method_fqn: Method fully qualified name
            procedure_name: Actual procedure/function name
            database_type: ORACLE, DB2, POSTGRESQL, etc.
            is_function: True if function, False if procedure
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Verify method exists
            with self.driver.session(database=self.database) as session:
                check_query = "MATCH (m:JavaMethod {fqn: $fqn}) RETURN m.name as name"
                result = session.run(check_query, fqn=method_fqn)
                if not result.single():
                    logger.error(f"   Method not found: {method_fqn}")
                    self.stats['errors'] += 1
                    return False
                
                escaped_method_fqn = escape_cypher_string(method_fqn)
                escaped_proc_name = escape_cypher_string(procedure_name)
                escaped_db_type = escape_cypher_string(database_type)
                
                resource_type = 'FUNCTION' if is_function else 'PROCEDURE'
                unique_id = f"RES_PROC_{uuid.uuid4().hex[:8].upper()}"
                escaped_resource_id = escape_cypher_string(unique_id)
                
                # Create or update Resource node
                resource_query = f"""
                MERGE (r:Resource {{name: '{escaped_proc_name}', type: '{resource_type}'}})
                ON CREATE SET r.id = '{escaped_resource_id}',
                              r.enabled = true,
                              r.databaseType = '{escaped_db_type}',
                              r.manuallyResolved = true
                ON MATCH SET r.databaseType = COALESCE(r.databaseType, '{escaped_db_type}'),
                             r.manuallyResolved = true
                RETURN r.id as resourceId
                """
                result = session.run(resource_query)
                if result.single():
                    logger.info(f"     Resource created/updated: {procedure_name} ({resource_type})")
                    self.stats['resources_created'] += 1
                
                # Create INVOKES relationship
                relationship_query = f"""
                MATCH (m:JavaMethod {{fqn: '{escaped_method_fqn}'}})
                MATCH (r:Resource {{name: '{escaped_proc_name}', type: '{resource_type}'}})
                MERGE (m)-[:INVOKES {{
                    databaseType: '{escaped_db_type}',
                    confidence: 'HIGH',
                    manuallyResolved: true
                }}]->(r)
                """
                session.run(relationship_query)
                logger.info(f"     Relationship created: {method_fqn} -[INVOKES]-> {procedure_name}")
                self.stats['relationships_created'] += 1
                
                # Update method's procedureCalls property to reflect resolved procedure
                update_method_query = f"""
                MATCH (m:JavaMethod {{fqn: '{escaped_method_fqn}'}})
                SET m.procedureCalls = [proc IN m.procedureCalls | 
                    CASE 
                        WHEN proc CONTAINS 'DYNAMIC' OR proc CONTAINS 'UNKNOWN'
                        THEN '{escaped_proc_name}:{escaped_db_type}:{resource_type}:HIGH'
                        ELSE proc
                    END
                ],
                m.furtherAnalysisRequired = false
                """
                session.run(update_method_query)
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
                                   confidence: str = "HIGH", description: str = None) -> bool:
        """
        Create SHELL_SCRIPT Resource and EXECUTES relationship for a method.
        
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
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Verify method exists
            with self.driver.session(database=self.database) as session:
                check_query = "MATCH (m:JavaMethod {fqn: $fqn}) RETURN m.name as name"
                result = session.run(check_query, fqn=method_fqn)
                if not result.single():
                    logger.error(f"   Method not found: {method_fqn}")
                    self.stats['errors'] += 1
                    return False
                
                escaped_method_fqn = escape_cypher_string(method_fqn)
                escaped_script_name = escape_cypher_string(script_name)
                escaped_script_path = escape_cypher_string(script_path if script_path else script_name)
                escaped_script_type = escape_cypher_string(script_type)
                escaped_confidence = escape_cypher_string(confidence)
                escaped_description = escape_cypher_string(description if description else "")
                
                # Generate unique ID for new resources
                unique_id = f"RES_SCRIPT_{uuid.uuid4().hex[:8].upper()}"
                escaped_resource_id = escape_cypher_string(unique_id)
                
                # Determine execution type
                is_remote = remote_host is not None
                execution_type = "REMOTE" if is_remote else "LOCAL"
                
                # Create or update Resource node
                resource_props = {
                    'id': escaped_resource_id,
                    'enabled': 'true',
                    'scriptType': escaped_script_type,
                    'scriptPath': escaped_script_path,
                    'executionType': execution_type,
                    'manuallyResolved': 'true',
                    'description': escaped_description
                }
                
                if is_remote:
                    resource_props['remoteHost'] = escape_cypher_string(remote_host)
                    if remote_user:
                        resource_props['remoteUser'] = escape_cypher_string(remote_user)
                    if remote_port:
                        resource_props['remotePort'] = remote_port
                    if ssh_key_location:
                        resource_props['sshKeyLocation'] = escape_cypher_string(ssh_key_location)
                
                # Build SET clause for resource properties
                set_clauses = ', '.join([f"r.{k} = '{v}'" if isinstance(v, str) else f"r.{k} = {v}" 
                                         for k, v in resource_props.items()])
                
                resource_query = f"""
                MERGE (r:Resource {{name: '{escaped_script_name}', type: 'SHELL_SCRIPT'}})
                ON CREATE SET {set_clauses}
                ON MATCH SET r.scriptPath = '{escaped_script_path}',
                             r.manuallyResolved = true
                RETURN r.id as resourceId
                """
                result = session.run(resource_query)
                if result.single():
                    logger.info(f"     Resource created/updated: {script_name} ({script_type})")
                    if is_remote:
                        logger.info(f"      Remote: {remote_user}@{remote_host}:{script_path}")
                    else:
                        logger.info(f"      Local: {script_path}")
                    self.stats['resources_created'] += 1
                
                # Create EXECUTES relationship
                rel_props = {
                    'scriptType': escaped_script_type,
                    'confidence': escaped_confidence,
                    'executionType': execution_type,
                    'manuallyResolved': 'true'
                }
                
                rel_set_clauses = ', '.join([f"{k}: '{v}'" for k, v in rel_props.items()])
                
                relationship_query = f"""
                MATCH (m:JavaMethod {{fqn: '{escaped_method_fqn}'}})
                MATCH (r:Resource {{name: '{escaped_script_name}', type: 'SHELL_SCRIPT'}})
                MERGE (m)-[:EXECUTES {{{rel_set_clauses}}}]->(r)
                """
                session.run(relationship_query)
                logger.info(f"     Relationship created: {method_fqn} -[EXECUTES]-> {script_name}")
                self.stats['relationships_created'] += 1
                
                # Update method's shellExecutions property to reflect resolved script
                update_method_query = f"""
                MATCH (m:JavaMethod {{fqn: '{escaped_method_fqn}'}})
                SET m.shellExecutions = [exec IN m.shellExecutions | 
                    CASE 
                        WHEN exec CONTAINS 'DYNAMIC' OR exec CONTAINS 'UNKNOWN' OR exec CONTAINS 'PARAMETERIZED'
                        THEN 'RESOLVED:{escaped_script_name}:{escaped_confidence}'
                        ELSE exec
                    END
                ],
                m.furtherAnalysisRequired = false
                """
                session.run(update_method_query)
                logger.info(f"     Method updated: furtherAnalysisRequired=false")
                
                self.stats['shell_executions_processed'] += 1
                return True
                
        except Exception as e:
            logger.error(f"   Error associating shell execution: {e}")
            self.stats['errors'] += 1
            return False
    
    def process_config_file(self, config_path: str = manual_mappings_file_path):
        """
        Process manual mappings from YAML config file.
        
        Args:
            config_path: Path to YAML config file
        """
        print("\n" + "="*80)
        print("MANUAL RESOURCE ASSOCIATION")
        print("="*80)
        print(f"Config File: {config_path}\n")
        
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
            print(f"Processing {len(db_operations)} DB operations:\n")
            for idx, op in enumerate(db_operations, 1):
                method_fqn = op.get('method_fqn')
                operation_type = op.get('operation_type')
                table_name = op.get('table_name')
                schema_name = op.get('schema_name')
                confidence = op.get('confidence', 'HIGH')
                
                if not all([method_fqn, operation_type, table_name]):
                    logger.error(f"  [{idx}]  Missing required fields: method_fqn, operation_type, table_name")
                    self.stats['errors'] += 1
                    continue
                
                print(f"  [{idx}] {method_fqn}")
                print(f"      Operation: {operation_type} on table '{table_name}'")
                self.associate_db_operation(method_fqn, operation_type, table_name, schema_name, confidence)
                print()
        
        # Process procedure calls
        procedure_calls = mappings.get('procedure_calls', [])
        if procedure_calls:
            print(f"Processing {len(procedure_calls)} procedure calls:\n")
            for idx, proc in enumerate(procedure_calls, 1):
                method_fqn = proc.get('method_fqn')
                procedure_name = proc.get('procedure_name')
                database_type = proc.get('database_type', 'UNKNOWN')
                is_function = proc.get('is_function', False)
                
                if not all([method_fqn, procedure_name]):
                    logger.error(f"  [{idx}]  Missing required fields: method_fqn, procedure_name")
                    self.stats['errors'] += 1
                    continue
                
                print(f"  [{idx}] {method_fqn}")
                print(f"      Procedure: {procedure_name} ({database_type})")
                self.associate_procedure_call(method_fqn, procedure_name, database_type, is_function)
                print()
        
        # Process shell executions
        shell_executions = mappings.get('shell_executions', [])
        if shell_executions:
            print(f"Processing {len(shell_executions)} shell executions:\n")
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
                
                if not all([method_fqn, script_name]):
                    logger.error(f"  [{idx}]  Missing required fields: method_fqn, script_name")
                    self.stats['errors'] += 1
                    continue
                
                print(f"  [{idx}] {method_fqn}")
                print(f"      Script: {script_name} ({script_type})")
                if remote_host:
                    print(f"      Execution: REMOTE ({remote_user}@{remote_host})")
                else:
                    print(f"      Execution: LOCAL")
                self.associate_shell_execution(
                    method_fqn, script_name, script_path, script_type,
                    remote_host, remote_user, remote_port, ssh_key_location,
                    confidence, description
                )
                print()
        
        # Print statistics
        self.print_statistics()
    
    def print_statistics(self):
        """Print processing statistics"""
        print("="*80)
        print("STATISTICS")
        print("="*80)
        print(f"  DB Operations Processed:     {self.stats['db_operations_processed']}")
        print(f"  Procedure Calls Processed:   {self.stats['procedure_calls_processed']}")
        print(f"  Shell Executions Processed:  {self.stats['shell_executions_processed']}")
        print(f"  Resources Created/Updated:   {self.stats['resources_created']}")
        print(f"  Relationships Created:       {self.stats['relationships_created']}")
        print(f"  Errors:                      {self.stats['errors']}")
        print("="*80)
        
        if self.stats['errors'] == 0:
            print(" MANUAL RESOURCE ASSOCIATION COMPLETE")
        else:
            print(f"  COMPLETED WITH {self.stats['errors']} ERRORS")
        print("="*80 + "\n")


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
                'method_fqn': 'com.companyname.dao.BatchJobDAOImpl.getJobDetails',
                'operation_type': 'SELECT',
                'table_name': 'batch_job_execution',
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
            }
        ]
    }
    
    output_path = 'manual_mappings_sample.yaml'
    with open(output_path, 'w') as f:
        yaml.dump(sample_config, f, default_flow_style=False, sort_keys=False)
    
    print(f"\n Sample config file created: {output_path}")
    print("Edit this file with your actual mappings and run:")
    print(f"   python manual_resource_associator.py --config {output_path}\n")


def main():
    
    # Create associator and process
    associator = ManualResourceAssociator(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, NEO4J_DATABASE)
    
    try:
        associator.process_config_file(manual_mappings_file_path)
    finally:
        associator.close()


if __name__ == "__main__":
    main()
