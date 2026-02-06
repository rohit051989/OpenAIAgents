"""
Stored Procedure Call Enricher
================================

This script enriches the information graph with stored procedure call analysis.
It queries existing JavaMethod nodes and updates them with procedure call information.

Usage:
    python procedure_call_enricher.py

Requirements:
    - Run information_graph_builder_v3.py first to build the graph structure
    - Neo4j database running with information graph
"""

import os
import sys
import logging
from typing import Dict, List, Set
from dotenv import load_dotenv
from neo4j import GraphDatabase
import yaml

from classes.DataClasses import ProcedureAnalyzer


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ProcedureCallEnricher:
    """
    Enriches JavaMethod nodes with stored procedure call information.
    """
    
    def __init__(self, config_path: str = 'information_graph_config.yaml'):
        """
        Initialize the procedure call enricher.
        
        Args:
            config_path: Path to configuration file
        """
        self.config = self._load_config(config_path)
        self.driver = None
        self.database = self.config.get('neo4j', {}).get('database', 'informationgraph')
        self.procedure_analyzer = ProcedureAnalyzer()
        
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
        username = neo4j_config.get('username', 'neo4j')
        password = neo4j_config.get('password', 'password')
        
        self.driver = GraphDatabase.driver(uri, auth=(username, password))
        logger.info(f"Connected to Neo4j at {uri}, database: {self.database}")
    
    def close(self):
        """Close Neo4j connection."""
        if self.driver:
            self.driver.close()
    
    def _get_java_methods(self) -> List[Dict]:
        """
        Query Neo4j for all JavaMethod nodes with their source code.
        
        Returns:
            List of dictionaries with method information
        """
        query = """
        MATCH (jc:JavaClass)-[:HAS_METHOD]->(m:JavaMethod)
        WHERE m.sourcePath IS NOT NULL
        RETURN 
            jc.fqn AS classFqn,
            jc.className AS className,
            jc.sourcePath AS classSourcePath,
            m.methodName AS methodName,
            m.signature AS signature,
            m.startLine AS startLine,
            m.endLine AS endLine,
            m.sourcePath AS methodSourcePath
        ORDER BY jc.fqn, m.methodName
        """
        
        with self.driver.session(database=self.database) as session:
            result = session.run(query)
            methods = []
            for record in result:
                methods.append({
                    'class_fqn': record['classFqn'],
                    'class_name': record['className'],
                    'class_source_path': record['classSourcePath'],
                    'method_name': record['methodName'],
                    'signature': record['signature'],
                    'start_line': record['startLine'],
                    'end_line': record['endLine'],
                    'method_source_path': record['methodSourcePath']
                })
            
            logger.info(f"Retrieved {len(methods)} methods from graph")
            return methods
    
    def _read_method_source(self, source_path: str, start_line: int, end_line: int) -> str:
        """
        Read method source code from file.
        
        Args:
            source_path: Path to source file
            start_line: Starting line number (1-based)
            end_line: Ending line number (1-based)
            
        Returns:
            Method source code as string
        """
        try:
            if not os.path.exists(source_path):
                logger.warning(f"Source file not found: {source_path}")
                return ""
            
            with open(source_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                if start_line > 0 and end_line <= len(lines):
                    return ''.join(lines[start_line-1:end_line])
                else:
                    logger.warning(f"Invalid line range [{start_line}:{end_line}] for {source_path}")
                    return ""
        except Exception as e:
            logger.error(f"Error reading source file {source_path}: {e}")
            return ""
    
    def _create_method_def_mock(self, method_info: Dict, source_code: str):
        """
        Create a minimal MethodDef object for the analyzer.
        
        Args:
            method_info: Method information from Neo4j
            source_code: Method source code
            
        Returns:
            Mock MethodDef object with required attributes
        """
        class MethodDefMock:
            def __init__(self, name, signature, source):
                self.method_name = name
                self.signature = signature
                self.source_code = source
                self.procedure_calls = []  # Will be populated by analyzer
        
        return MethodDefMock(
            method_info['method_name'],
            method_info['signature'],
            source_code
        )
    
    def _create_class_info_mock(self, method_info: Dict):
        """
        Create a minimal ClassInfo object for the analyzer.
        
        Args:
            method_info: Method information from Neo4j
            
        Returns:
            Mock ClassInfo object with required attributes
        """
        class ClassInfoMock:
            def __init__(self, name, fqn):
                self.class_name = name
                self.fqn = fqn
        
        return ClassInfoMock(
            method_info['class_name'],
            method_info['class_fqn']
        )
    
    def _update_method_procedures(self, method_info: Dict, procedure_calls: List) -> bool:
        """
        Update JavaMethod node with procedure call information.
        
        Args:
            method_info: Method information
            procedure_calls: List of ProcedureCall objects
            
        Returns:
            True if update successful
        """
        if not procedure_calls:
            return False
        
        # Convert procedure calls to serializable format
        procedures_data = []
        for proc in procedure_calls:
            procedures_data.append({
                'databaseType': proc.database_type,
                'procedureName': proc.procedure_name,
                'isFunction': proc.is_function,
                'callType': proc.call_type,
                'parameters': proc.parameters if hasattr(proc, 'parameters') else []
            })
        
        query = """
        MATCH (jc:JavaClass {fqn: $classFqn})-[:HAS_METHOD]->(m:JavaMethod {methodName: $methodName})
        SET m.procedureCalls = $procedureCalls,
            m.procedureCallCount = $procedureCallCount
        RETURN m.methodName AS methodName
        """
        
        try:
            with self.driver.session(database=self.database) as session:
                result = session.run(
                    query,
                    classFqn=method_info['class_fqn'],
                    methodName=method_info['method_name'],
                    procedureCalls=procedures_data,
                    procedureCallCount=len(procedures_data)
                )
                
                if result.single():
                    return True
                else:
                    logger.warning(f"Method not found for update: {method_info['class_fqn']}.{method_info['method_name']}")
                    return False
        except Exception as e:
            logger.error(f"Error updating method {method_info['class_fqn']}.{method_info['method_name']}: {e}")
            return False
    
    def enrich(self):
        """
        Main enrichment process.
        """
        print("\n" + "=" * 80)
        print("STORED PROCEDURE CALL ENRICHMENT")
        print("=" * 80)
        
        # Get all methods from graph
        methods = self._get_java_methods()
        
        if not methods:
            print("\n  ⚠️  No methods found in graph. Run information_graph_builder_v3.py first.")
            return
        
        print(f"\n  Analyzing {len(methods)} methods for stored procedure calls...\n")
        
        analyzed_count = 0
        found_count = 0
        
        for method_info in methods:
            # Read method source code
            source_path = method_info['method_source_path'] or method_info['class_source_path']
            if not source_path:
                continue
            
            source_code = self._read_method_source(
                source_path,
                method_info['start_line'],
                method_info['end_line']
            )
            
            if not source_code:
                continue
            
            # Create mock objects for analyzer
            method_def = self._create_method_def_mock(method_info, source_code)
            class_info = self._create_class_info_mock(method_info)
            
            # Analyze for procedure calls
            proc_call = self.procedure_analyzer.analyze_method(method_def, class_info)
            
            if proc_call:
                method_def.procedure_calls.append(proc_call)
                
                # Update graph
                if self._update_method_procedures(method_info, method_def.procedure_calls):
                    found_count += 1
                    proc_type = "Function" if proc_call.is_function else "Procedure"
                    print(f"    {method_info['class_name']}.{method_info['method_name']}() -> "
                          f"{proc_call.database_type} {proc_type}: {proc_call.procedure_name}")
            
            analyzed_count += 1
        
        print(f"\n  ✓ Analyzed {analyzed_count} methods")
        print(f"  ✓ Found procedure calls in {found_count} methods")
        
        print("\n" + "=" * 80)
        print("✅ STORED PROCEDURE CALL ENRICHMENT COMPLETE")
        print("=" * 80)


def main():

    """Main entry point."""
    load_dotenv()
    config_path = os.getenv("KG_CONFIG_FILE")
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
