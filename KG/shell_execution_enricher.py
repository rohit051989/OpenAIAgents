"""
Shell Script Execution Enricher
================================

This script enriches the information graph with shell script execution analysis.
It queries existing JavaMethod nodes and updates them with shell execution information.

Usage:
    python shell_execution_enricher.py

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

from classes.ShellScriptAnalyzer import ShellScriptAnalyzer


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ShellExecutionEnricher:
    """
    Enriches JavaMethod nodes with shell script execution information.
    """
    
    def __init__(self, config_path: str = 'information_graph_config.yaml'):
        """
        Initialize the shell execution enricher.
        
        Args:
            config_path: Path to configuration file
        """
        self.config = self._load_config(config_path)
        self.driver = None
        self.database = self.config.get('neo4j', {}).get('database', 'informationgraph')
        self.shell_analyzer = ShellScriptAnalyzer()
        
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
        WHERE jc.path IS NOT NULL
        RETURN 
            jc.fqn AS classFqn,
            jc.className AS className,
            jc.path AS path,
            m.methodName AS methodName,
            m.signature AS signature,
            m.startLine AS startLine,
            m.endLine AS endLine
        ORDER BY jc.fqn, m.methodName
        """
        
        with self.driver.session(database=self.database) as session:
            result = session.run(query)
            methods = []
            for record in result:
                methods.append({
                    'class_fqn': record['classFqn'],
                    'class_name': record['className'],
                    'path': record['path'],
                    'method_name': record['methodName'],
                    'signature': record['signature'],
                    'start_line': record['startLine'],
                    'end_line': record['endLine']
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
                self.shell_executions = []  # Will be populated by analyzer
        
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
    
    def _update_method_shell_executions(self, method_info: Dict, shell_executions: List) -> bool:
        """
        Update JavaMethod node with shell execution information.
        
        Args:
            method_info: Method information
            shell_executions: List of ShellExecution objects
            
        Returns:
            True if update successful
        """
        if not shell_executions:
            return False
        
        # Convert shell executions to serializable format
        executions_data = []
        for shell_exec in shell_executions:
            executions_data.append({
                'scriptType': shell_exec.script_type,
                'scriptName': shell_exec.script_name,
                'executionMethod': shell_exec.execution_method,
                'command': shell_exec.command if hasattr(shell_exec, 'command') else None,
                'isStaticPath': shell_exec.is_static_path if hasattr(shell_exec, 'is_static_path') else False
            })
        
        query = """
        MATCH (jc:JavaClass {fqn: $classFqn})-[:HAS_METHOD]->(m:JavaMethod {methodName: $methodName})
        SET m.shellExecutions = $shellExecutions,
            m.shellExecutionCount = $shellExecutionCount
        RETURN m.methodName AS methodName
        """
        
        try:
            with self.driver.session(database=self.database) as session:
                result = session.run(
                    query,
                    classFqn=method_info['class_fqn'],
                    methodName=method_info['method_name'],
                    shellExecutions=executions_data,
                    shellExecutionCount=len(executions_data)
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
        print("SHELL SCRIPT EXECUTION ENRICHMENT")
        print("=" * 80)
        
        # Get all methods from graph
        methods = self._get_java_methods()
        
        if not methods:
            print("\n  ⚠️  No methods found in graph. Run information_graph_builder_v3.py first.")
            return
        
        print(f"\n  Analyzing {len(methods)} methods for shell script executions...\n")
        
        analyzed_count = 0
        found_count = 0
        
        for method_info in methods:
            # Read method source code
            source_path = method_info['path']
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
            
            # Analyze for shell executions
            shell_exec = self.shell_analyzer.analyze_method(method_def, class_info)
            
            if shell_exec:
                method_def.shell_executions.append(shell_exec)
                
                # Update graph
                if self._update_method_shell_executions(method_info, method_def.shell_executions):
                    found_count += 1
                    script_display = shell_exec.script_name if shell_exec.script_name else "[dynamic]"
                    print(f"    {method_info['class_name']}.{method_info['method_name']}() -> "
                          f"{shell_exec.script_type} script: {script_display} ({shell_exec.execution_method})")
            
            analyzed_count += 1
        
        print(f"\n  ✓ Analyzed {analyzed_count} methods")
        print(f"  ✓ Found shell executions in {found_count} methods")
        
        print("\n" + "=" * 80)
        print("✅ SHELL SCRIPT EXECUTION ENRICHMENT COMPLETE")
        print("=" * 80)


def main():
    """Main entry point."""

    load_dotenv()
    config_path = os.getenv("KG_CONFIG_FILE")

    enricher = ShellExecutionEnricher(config_path=config_path)
    
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
