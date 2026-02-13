"""
Stored Procedure Call Enricher
================================

This script enriches the information graph with stored procedure call analysis.
Analyzes DAO class methods for Oracle/database stored procedure invocations.

Features:
- Detects SimpleJdbcCall, CallableStatement, StoredProcedureQuery patterns
- Updates class level: is_procedure_invoked flag
- Updates method level: procedureCalls array and procedureCallCount
- Creates PROCEDURE Resource nodes with INVOKES relationships

Usage:
    python procedure_call_enricher.py

Requirements:
    - Run information_graph_builder_v4.py first to build the graph structure
    - Neo4j database running with information graph
    - DAO classes marked with isDAOClass=true
"""

import os
import sys
import logging
import uuid
import re
from typing import Dict, List, Set
from dotenv import load_dotenv
from neo4j import GraphDatabase
import yaml
from pathlib import Path

from classes.ProcedureAnalyzer import ProcedureAnalyzer
from classes.DataClasses import ClassInfo, MethodDef


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def escape_cypher_string(s: str) -> str:
    """Escape string for Cypher query"""
    if not s:
        return ""
    return s.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n").replace("\r", "\\r")


class ProcedureCallEnricher:
    """
    Enriches JavaMethod nodes with stored procedure call information.
    """
    
    def __init__(self, config_path: str = 'config/information_graph_config.yaml'):
        """
        Initialize the procedure call enricher.
        
        Args:
            config_path: Path to configuration file
        """
        self.config = self._load_config(config_path)
        self.driver = None
        self.database = self.config.get('neo4j', {}).get('database_ig', 'informationgraph')
        self.procedure_analyzer = ProcedureAnalyzer()
        
        # Statistics
        self.stats = {
            'classes_processed': 0,
            'classes_with_procedures': 0,
            'methods_processed': 0,
            'methods_with_procedures': 0,
            'total_procedures': 0,
        }
        
    def _load_config(self, config_path: str) -> dict:
        """Load configuration from YAML file."""
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    
    def connect(self):
        """Connect to Neo4j database."""
        neo4j_config = self.config.get('neo4j', {})
        uri = neo4j_config.get('uri', 'bolt://localhost:7687')
        user = neo4j_config.get('user', 'neo4j')
        password = neo4j_config.get('password', 'password')
        
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        logger.info(f"Connected to Neo4j at {uri}, database: {self.database}")
    
    def close(self):
        """Close Neo4j connection."""
        if self.driver:
            self.driver.close()
    
    def _get_dao_classes(self) -> List[Dict]:
        """
        Query Neo4j for all DAO classes (isDAOClass=true).
        
        Returns:
            List of dictionaries with class information
        """
        query = """
        MATCH (jc:JavaClass)
        WHERE jc.isDAOClass = true
        RETURN jc.fqn as fqn, 
               jc.path as path,
               jc.className as className
        ORDER BY jc.fqn
        """
        
        with self.driver.session(database=self.database) as session:
            result = session.run(query)
            dao_classes = [dict(record) for record in result]
            
        logger.info(f"  Found {len(dao_classes)} DAO classes to analyze")
        return dao_classes
    
    def _get_class_methods(self, class_fqn: str) -> List[Dict]:
        """
        Get all methods for a DAO class.
        
        Args:
            class_fqn: Fully qualified class name
            
        Returns:
            List of method information dictionaries
        """
        query = """
        MATCH (jc:JavaClass {fqn: $fqn})-[:HAS_METHOD]->(m:JavaMethod)
        RETURN m.fqn as fqn,
               m.methodName as methodName,
               m.signature as signature
        ORDER BY m.methodName
        """
        
        with self.driver.session(database=self.database) as session:
            result = session.run(query, fqn=class_fqn)
            return [dict(record) for record in result]
    
    def _create_class_info_mock(self, class_data: Dict) -> ClassInfo:
        """
        Create a minimal ClassInfo object for the analyzer.
        
        Args:
            class_data: Class data from Neo4j
            
        Returns:
            ClassInfo object
        """
        return ClassInfo(
            package='.'.join(class_data['fqn'].split('.')[:-1]),
            class_name=class_data['className'],
            fqn=class_data['fqn'],
            source_path=class_data['path']
        )
    
    def _create_method_def_mock(self, method_data: Dict, class_fqn: str) -> MethodDef:
        """
        Create a minimal MethodDef object for the analyzer.
        
        Args:
            method_data: Method data from Neo4j
            class_fqn: Class FQN for the method
            
        Returns:
            MethodDef object
        """
        return MethodDef(
            class_fqn=class_fqn,
            method_name=method_data['methodName'],
            return_type='void',  # Not needed for procedure detection
            parameters=[],
            modifiers=[],
            calls=[]
        )
    
    def _update_method_procedures(self, method_fqn: str, procedure_call) -> bool:
        """
        Update JavaMethod node with procedure call information.
        
        Args:
            method_fqn: Method fully qualified name
            procedure_call: ProcedureCall object
            
        Returns:
            True if update successful
        """
        # Format procedure call as string for Neo4j
        proc_str = f"{procedure_call.procedure_name}:{procedure_call.database_type}:{'FUNCTION' if procedure_call.is_function else 'PROCEDURE'}:{procedure_call.confidence}"
        
        # Check if procedure name/schema/catalog is dynamic and requires manual review
        requires_further_analysis = (
            'DYNAMIC' in procedure_call.procedure_name.upper() or
            procedure_call.procedure_name == 'UNKNOWN'
        )
        
        query = """
        MATCH (m:JavaMethod {fqn: $fqn})
        SET m.procedureCalls = [$procedure],
            m.procedureCallCount = 1,
            m.furtherAnalysisRequired = $furtherAnalysisRequired
        RETURN m.methodName as methodName
        """
        
        try:
            with self.driver.session(database=self.database) as session:
                result = session.run(
                    query,
                    fqn=method_fqn,
                    procedure=proc_str,
                    furtherAnalysisRequired=requires_further_analysis
                )
                
                if result.single():
                    # Create procedure resource and relationship
                    self._create_procedure_resource(method_fqn, procedure_call)
                    return True
                else:
                    logger.warning(f"  Method not found: {method_fqn}")
                    return False
        except Exception as e:
            logger.error(f"  Error updating method {method_fqn}: {e}")
            return False
    
    def _create_procedure_resource(self, method_fqn: str, procedure_call):
        """
        Create PROCEDURE Resource node and INVOKES relationship.
        Skip creation for DYNAMIC/UNKNOWN procedure names - these require manual resolution.
        
        Args:
            method_fqn: Method fully qualified name
            procedure_call: ProcedureCall object
        """
        # Skip Resource creation for DYNAMIC/UNKNOWN procedure names
        # These need manual resolution before Resource association
        skip_keywords = ['DYNAMIC', 'UNKNOWN', 'DYNAMIC_PROCEDURE', 'DYNAMIC_CATALOG', 'DYNAMIC_SCHEMA']
        if any(keyword in procedure_call.procedure_name.upper() for keyword in skip_keywords):
            logger.info(f"  Skipping Resource creation for {procedure_call.procedure_name} (requires manual resolution)")
            return
        
        escaped_method_fqn = escape_cypher_string(method_fqn)
        escaped_proc_name = escape_cypher_string(procedure_call.procedure_name)
        escaped_db_type = escape_cypher_string(procedure_call.database_type)
        
        resource_type = 'FUNCTION' if procedure_call.is_function else 'PROCEDURE'
        unique_id = f"RES_PROC_{uuid.uuid4().hex[:8].upper()}"
        escaped_resource_id = escape_cypher_string(unique_id)
        
        try:
            with self.driver.session(database=self.database) as session:
                # Create or update Resource node
                resource_query = f"""
                MERGE (r:Resource {{name: '{escaped_proc_name}', type: '{resource_type}'}})
                ON CREATE SET r.id = '{escaped_resource_id}',
                              r.enabled = true,
                              r.databaseType = '{escaped_db_type}'
                ON MATCH SET r.databaseType = COALESCE(r.databaseType, '{escaped_db_type}')
                """
                session.run(resource_query)
                
                # Create INVOKES relationship
                relationship_query = f"""
                MATCH (m:JavaMethod {{fqn: '{escaped_method_fqn}'}})
                MATCH (r:Resource {{name: '{escaped_proc_name}', type: '{resource_type}'}})
                MERGE (m)-[:INVOKES {{
                    databaseType: '{escaped_db_type}',
                    confidence: 'HIGH'
                }}]->(r)
                """
                session.run(relationship_query)
                
        except Exception as e:
            logger.warning(f"  Failed to create Resource relationship for {procedure_call.procedure_name}: {e}")
    
    def _update_class_flag(self, class_fqn: str):
        """
        Set is_procedure_invoked flag on JavaClass.
        
        Args:
            class_fqn: Class fully qualified name
        """
        query = """
        MATCH (jc:JavaClass {fqn: $fqn})
        SET jc.is_procedure_invoked = true
        RETURN jc.className as className
        """
        
        with self.driver.session(database=self.database) as session:
            session.run(query, fqn=class_fqn)
    
    def enrich(self):
        """
        Main enrichment process.
        """
        print("\n" + "=" * 80)
        print("STORED PROCEDURE CALL ENRICHMENT")
        print("=" * 80)
        
        # Get all DAO classes
        dao_classes = self._get_dao_classes()
        
        if not dao_classes:
            print("\n  ⚠️  No DAO classes found (isDAOClass=true).")
            print("     Run information_graph_builder_v4.py first.")
            return
        
        print(f"\n  Analyzing {len(dao_classes)} DAO classes...\n")
        
        # Analyze each DAO class
        for idx, class_data in enumerate(dao_classes, 1):
            class_fqn = class_data['fqn']
            class_name = class_data['className']
            
            print(f"[{idx}/{len(dao_classes)}] {class_name}")
            
            # Get methods for this class
            methods = self._get_class_methods(class_fqn)
            
            if not methods:
                print(f"  No methods found for {class_fqn}")
                continue
            
            self.stats['classes_processed'] += 1
            class_has_procedures = False
            
            # Create ClassInfo for analyzer
            class_info = self._create_class_info_mock(class_data)
            
            # Analyze each method
            for method_data in methods:
                self.stats['methods_processed'] += 1
                
                # Create MethodDef for analyzer
                method_def = self._create_method_def_mock(method_data, class_fqn)
                
                # Analyze for procedure calls
                procedure_call = self.procedure_analyzer.analyze_method(method_def, class_info)
                
                if procedure_call:
                    proc_type = "Function" if procedure_call.is_function else "Procedure"
                    requires_review = 'DYNAMIC' in procedure_call.procedure_name.upper() or procedure_call.procedure_name == 'UNKNOWN'
                    review_flag = " ⚠️ [Further Analysis Required]" if requires_review else ""
                    print(f"  ✓ {method_data['methodName']}() -> {procedure_call.database_type} {proc_type}: {procedure_call.procedure_name}{review_flag}")
                    
                    # Update method in graph
                    if self._update_method_procedures(method_data['fqn'], procedure_call):
                        self.stats['methods_with_procedures'] += 1
                        self.stats['total_procedures'] += 1
                        class_has_procedures = True
            
            # Update class-level flag if any procedures found
            if class_has_procedures:
                self._update_class_flag(class_fqn)
                self.stats['classes_with_procedures'] += 1
                print(f"  → Class marked as is_procedure_invoked=true\n")
            else:
                print(f"  No procedure calls detected\n")
        
        # Print statistics
        self._print_statistics()
    
    def _print_statistics(self):
        """Print enrichment statistics."""
        print("=" * 80)
        print("ENRICHMENT STATISTICS")
        print("=" * 80)
        print(f"  DAO Classes Processed:        {self.stats['classes_processed']}")
        print(f"  Classes with Procedures:      {self.stats['classes_with_procedures']}")
        print(f"  Methods Analyzed:             {self.stats['methods_processed']}")
        print(f"  Methods with Procedures:      {self.stats['methods_with_procedures']}")
        print(f"  Total Procedures Found:       {self.stats['total_procedures']}")
        print("=" * 80)
        print("✅ STORED PROCEDURE CALL ENRICHMENT COMPLETE")
        print("=" * 80 + "\n")


def main():
    """Main entry point."""
    load_dotenv()
    config_path = os.getenv("CONFIG_FILE_PATH", "config/information_graph_config.yaml")
    
    enricher = ProcedureCallEnricher(config_path=config_path)
    
    try:
        enricher.connect()
        enricher.enrich()
    except Exception as e:
        logger.error(f"Enrichment failed: {e}", exc_info=True)
        sys.exit(1)
    finally:
        enricher.close()


if __name__ == '__main__':
    main()

