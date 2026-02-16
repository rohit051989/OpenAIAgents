"""
Shell Script Execution Enricher V2

This script enriches an existing Information Graph with shell script execution analysis.
Runs after information_graph_builder_v4.py completes.

Architecture:
- Queries Neo4j for Shell Executor classes (isShellExecutorClass=true)
- For each Shell Executor class, extracts all methods
- For each method:
  - Analyzes for shell script execution patterns
  - Detects grey areas (dynamic paths, parameterized scripts, unknown locations)
  - Marks methods with furtherAnalysisRequired flag for manual review
- Creates ShellScript Resource nodes for identified scripts
- Updates Neo4j with shellExecutions and shellExecutionCount
- Consolidates shell executions at Step level

Grey Area Detection:
- DYNAMIC_PATH: Script path is built dynamically (variables, concatenation)
- UNKNOWN_SCRIPT: Cannot determine which script is executed
- REMOTE_EXECUTION: SSH/remote execution with dynamic host/credentials
- PARAMETERIZED: Script path contains placeholders or parameters

Manual Resolution:
- Methods marked with furtherAnalysisRequired need manual review
- Update config/manual_mappings_sample.yaml with actual script details
- Run manual_resource_associator.py to apply manual mappings
"""

import os
from dotenv import load_dotenv
import yaml
from neo4j import GraphDatabase
from typing import Dict, List, Optional, Set
from pathlib import Path
import re

# Import analyzers
from classes.ShellScriptAnalyzer import ShellScriptAnalyzer
from classes.DataClasses import ClassInfo, MethodDef

import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - [%(pathname)s:%(lineno)d %(funcName)s] - %(message)s"
)
logger = logging.getLogger(__name__)


def escape_cypher_string(s: str) -> str:
    """Escape string for Cypher query"""
    if not s:
        return ""
    return s.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n").replace("\r", "\\r")


class ShellExecutionEnricher:
    """
    Enriches JavaMethod nodes with shell script execution information.
    Marks grey areas for manual resolution.
    """
    
    def __init__(self, config_path: str = 'config/information_graph_config.yaml'):
        """Initialize the shell execution enricher."""
        self.config = self._load_config(config_path)
        self.driver = None
        self.database = self.config['neo4j']['database_ig']
        self.shell_analyzer = ShellScriptAnalyzer()
        
    def _load_config(self, config_path: str) -> dict:
        """Load configuration from YAML file."""
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    
    def connect(self):
        """Connect to Neo4j database."""
        neo4j_config = self.config['neo4j']
        uri = neo4j_config['uri']
        user = neo4j_config['user']
        password = neo4j_config['password']
        
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        logger.info(f"Connected to Neo4j at {uri}, database: {self.database}")
    
    def close(self):
        """Close Neo4j connection."""
        if self.driver:
            self.driver.close()
    
    def _get_shell_executor_classes(self) -> List[Dict]:
        """
        Query Neo4j for Shell Executor classes.
        
        Returns:
            List of shell executor class information
        """
        query = """
        MATCH (jc:JavaClass {isShellExecutorClass: true})
        RETURN 
            jc.fqn AS classFqn,
            jc.className AS className,
            jc.path AS path,
            jc.package AS package
        ORDER BY jc.fqn
        """
        
        with self.driver.session(database=self.database) as session:
            result = session.run(query)
            classes = []
            for record in result:
                classes.append({
                    'class_fqn': record['classFqn'],
                    'class_name': record['className'],
                    'path': record['path'],
                    'package': record['package']
                })
            
            logger.info(f"  Found {len(classes)} Shell Executor classes")
            return classes
    
    def _get_class_methods(self, class_fqn: str) -> List[Dict]:
        """Get all methods for a class."""
        query = """
        MATCH (jc:JavaClass {fqn: $classFqn})-[:HAS_METHOD]->(m:JavaMethod)
        RETURN 
            m.fqn AS methodFqn,
            m.methodName AS methodName,
            m.signature AS signature,
            m.returnType AS returnType
        ORDER BY m.methodName
        """
        
        with self.driver.session(database=self.database) as session:
            result = session.run(query, classFqn=class_fqn)
            methods = []
            for record in result:
                methods.append({
                    'fqn': record['methodFqn'],
                    'name': record['methodName'],
                    'signature': record['signature'],
                    'return_type': record['returnType']
                })
            return methods
    
    def _read_source_file(self, file_path: str) -> str:
        """Read entire source file."""
        try:
            if not os.path.exists(file_path):
                logger.warning(f"  Source file not found: {file_path}")
                return ""
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            logger.error(f"  Error reading source file {file_path}: {e}")
            return ""
    
    def _analyze_shell_execution(self, method_source: str, method_name: str) -> List[Dict]:
        """
        Analyze method source for shell script executions.
        Detects patterns and marks grey areas.
        Only counts DIRECT execution patterns (Runtime.exec, ProcessBuilder, executor.execute).
        
        Returns:
            List of shell execution dictionaries with grey area flags
        """
        executions = []
        
        # Pattern 1: Runtime.exec() calls
        runtime_pattern = r'Runtime\.getRuntime\(\)\.exec\s*\(\s*([^)]+)\)'
        for match in re.finditer(runtime_pattern, method_source, re.DOTALL):
            command_arg = match.group(1).strip()
            execution = self._parse_command_argument(command_arg, 'Runtime.exec')
            executions.append(execution)
        
        # Pattern 2: ProcessBuilder
        processbuilder_pattern = r'new\s+ProcessBuilder\s*\(\s*([^)]+)\)'
        for match in re.finditer(processbuilder_pattern, method_source, re.DOTALL):
            command_arg = match.group(1).strip()
            execution = self._parse_command_argument(command_arg, 'ProcessBuilder')
            executions.append(execution)
        
        # Pattern 3: Apache Commons Exec - executor.execute()
        commons_exec_pattern = r'executor\.execute\s*\(\s*([^)]+)\)'
        for match in re.finditer(commons_exec_pattern, method_source, re.DOTALL):
            command_arg = match.group(1).strip()
            execution = self._parse_command_argument(command_arg, 'CommonsExec')
            executions.append(execution)
        
        # NOTE: Removed Pattern 4 (indirect method calls) to avoid false positives
        # Methods that call other execution methods don't need to be flagged
        
        return executions
    
    def _parse_command_argument(self, command_arg: str, execution_method: str) -> Dict:
        """
        Parse command argument to extract script details and detect grey areas.
        
        Returns:
            Dictionary with execution details and grey area flags
        """
        command_arg = command_arg.strip()
        
        # Check if it's a simple string literal
        if command_arg.startswith('"') and command_arg.endswith('"'):
            script_path = command_arg.strip('"')
            return {
                'execution_method': execution_method,
                'script_type': self._detect_script_type(script_path),
                'script_name': script_path,
                'confidence': 'HIGH',
                'is_dynamic': False,
                'further_analysis': False,
                'grey_area_reason': None
            }
        
        # Check for variable references
        if re.search(r'\w+\s*\+|\+\s*\w+|String\.format|String\.join', command_arg):
            return {
                'execution_method': execution_method,
                'script_type': 'SHELL',
                'script_name': 'DYNAMIC_PATH',
                'confidence': 'LOW',
                'is_dynamic': True,
                'further_analysis': True,
                'grey_area_reason': 'DYNAMIC_PATH:String concatenation or formatting detected'
            }
        
        # Check for method parameters
        if re.search(r'\b(scriptDir|scriptFile|scriptPath|hostname|user|command|cmd)\b', command_arg, re.IGNORECASE):
            return {
                'execution_method': execution_method,
                'script_type': 'SHELL',
                'script_name': 'PARAMETERIZED',
                'confidence': 'LOW',
                'is_dynamic': True,
                'further_analysis': True,
                'grey_area_reason': 'PARAMETERIZED:Script path passed as parameter'
            }
        
        # Check for SSH/remote execution patterns
        if re.search(r'ssh|scp|sftp|rsync', command_arg, re.IGNORECASE):
            return {
                'execution_method': execution_method,
                'script_type': 'REMOTE_SHELL',
                'script_name': 'REMOTE_EXECUTION',
                'confidence': 'LOW',
                'is_dynamic': True,
                'further_analysis': True,
                'grey_area_reason': 'REMOTE_EXECUTION:SSH or remote execution detected'
            }
        
        # Default: unknown script
        return {
            'execution_method': execution_method,
            'script_type': 'UNKNOWN',
            'script_name': 'UNKNOWN_SCRIPT',
            'confidence': 'LOW',
            'is_dynamic': True,
            'further_analysis': True,
            'grey_area_reason': 'UNKNOWN_SCRIPT:Cannot determine script from source'
        }
    
    def _detect_script_type(self, script_path: str) -> str:
        """Detect script type from file extension or content."""
        script_lower = script_path.lower()
        
        if '.sh' in script_lower or 'bash' in script_lower:
            return 'BASH'
        elif '.py' in script_lower or 'python' in script_lower:
            return 'PYTHON'
        elif '.ps1' in script_lower or 'powershell' in script_lower:
            return 'POWERSHELL'
        elif '.bat' in script_lower or '.cmd' in script_lower:
            return 'BATCH'
        elif '.pl' in script_lower or 'perl' in script_lower:
            return 'PERL'
        else:
            return 'SHELL'
    
    def _update_method_with_executions(self, method_fqn: str, executions: List[Dict]) -> bool:
        """
        Update JavaMethod node with shell execution information.
        """
        if not executions:
            return False
        
        # Build execution list strings
        execution_strs = []
        further_analysis_reasons = []
        
        for exec_info in executions:
            exec_str = f"{exec_info['execution_method']}:{exec_info['script_name']}:{exec_info['confidence']}"
            execution_strs.append(exec_str)
            
            if exec_info['further_analysis'] and exec_info['grey_area_reason']:
                further_analysis_reasons.append(exec_info['grey_area_reason'])
        
        further_analysis_required = any(e['further_analysis'] for e in executions)
        
        escaped_method_fqn = escape_cypher_string(method_fqn)
        
        query = f"""
        MATCH (m:JavaMethod {{fqn: '{escaped_method_fqn}'}})
        SET m.shellExecutions = {execution_strs},
            m.shellExecutionCount = {len(executions)},
            m.furtherAnalysisRequired = {str(further_analysis_required).lower()},
            m.furtherAnalysisReasons = {further_analysis_reasons if further_analysis_reasons else []}
        RETURN m.methodName AS methodName
        """
        
        try:
            with self.driver.session(database=self.database) as session:
                result = session.run(query)
                return result.single() is not None
        except Exception as e:
            logger.error(f"  Error updating method {method_fqn}: {e}")
            return False
    
    def _create_shell_script_resource(self, script_name: str, script_type: str, confidence: str):
        """
        Create or update ShellScript Resource node.
        """
        if not script_name or script_name in ['DYNAMIC_PATH', 'PARAMETERIZED', 'UNKNOWN_SCRIPT', 'REMOTE_EXECUTION']:
            return  # Don't create resources for grey areas
        
        escaped_name = escape_cypher_string(script_name)
        escaped_type = escape_cypher_string(script_type)
        escaped_confidence = escape_cypher_string(confidence)
        
        query = f"""
        MERGE (r:Resource {{name: '{escaped_name}', type: 'SHELL_SCRIPT'}})
        ON CREATE SET r.scriptType = '{escaped_type}',
                      r.confidence = '{escaped_confidence}',
                      r.enabled = true
        RETURN r.name AS name
        """
        
        try:
            with self.driver.session(database=self.database) as session:
                session.run(query)
        except Exception as e:
            logger.error(f"  Error creating resource for {script_name}: {e}")
    
    def _clear_shell_execution_data(self):
        """Clear all shell execution properties from JavaMethod nodes."""
        query = """
        MATCH (m:JavaMethod)
        WHERE m.shellExecutions IS NOT NULL 
           OR m.shellExecutionCount IS NOT NULL
           OR m.furtherAnalysisRequired IS NOT NULL
           OR m.furtherAnalysisReasons IS NOT NULL
        REMOVE m.shellExecutions, m.shellExecutionCount, 
               m.furtherAnalysisRequired, m.furtherAnalysisReasons
        RETURN count(m) AS cleared
        """
        
        try:
            with self.driver.session(database=self.database) as session:
                result = session.run(query)
                record = result.single()
                if record:
                    count = record['cleared']
                    logger.info(f"    Cleared shell execution data from {count} methods")
        except Exception as e:
            logger.error(f"  Error clearing shell execution data: {e}")
    
    def enrich(self):
        """Main enrichment process."""
        logger.info("\n" + "=" * 80)
        logger.info("SHELL SCRIPT EXECUTION ENRICHMENT")
        logger.info("=" * 80)
        
        # Clear old shell execution data
        #logger.info("\n  Clearing old shell execution data...")
        #self._clear_shell_execution_data()
        
        # Get shell executor classes
        shell_classes = self._get_shell_executor_classes()
        
        if not shell_classes:
            logger.info("\n    No Shell Executor classes found.")
            logger.info("      Run information_graph_builder_v4.py first to identify shell executor classes.")
            return
        
        total_methods = 0
        methods_with_executions = 0
        methods_with_grey_areas = 0
        total_executions = 0
        
        for class_info in shell_classes:
            logger.info(f"\n  Analyzing class: {class_info['class_name']}")
            
            # Get all methods for this class
            methods = self._get_class_methods(class_info['class_fqn'])
            
            # Read source file once
            source_code = self._read_source_file(class_info['path']) if class_info['path'] else ""
            
            if not source_code:
                logger.warning(f"    No source code available for {class_info['class_name']}")
                continue
            
            for method in methods:
                # Extract method source using ShellScriptAnalyzer's improved extraction
                method_source = self.shell_analyzer._extract_method_source(source_code, method['name'])
                
                if not method_source:
                    continue
                
                # Only count methods that were analyzed (not all methods in class)
                total_methods += 1
                
                # Analyze for shell executions (only direct execution patterns)
                executions = self._analyze_shell_execution(method_source, method['name'])
                
                # Only process if actual executions found
                if executions:
                    methods_with_executions += 1
                    total_executions += len(executions)
                    
                    # Update method in graph
                    if self._update_method_with_executions(method['fqn'], executions):
                        has_grey_area = any(e['further_analysis'] for e in executions)
                        if has_grey_area:
                            methods_with_grey_areas += 1
                        
                        # Print execution details
                        for exec_info in executions:
                            status = " " if exec_info['further_analysis'] else ""
                            logger.info(f"    {status} {method['name']}() -> {exec_info['script_name']} "
                                      f"({exec_info['execution_method']}, {exec_info['confidence']})")
                            if exec_info['further_analysis']:
                                logger.info(f"       Grey Area: {exec_info['grey_area_reason']}")
                        
                        # Create resource nodes for static scripts
                        for exec_info in executions:
                            if not exec_info['is_dynamic']:
                                self._create_shell_script_resource(
                                    exec_info['script_name'],
                                    exec_info['script_type'],
                                    exec_info['confidence']
                                )
        
        logger.info("\n" + "=" * 80)
        logger.info("ENRICHMENT SUMMARY")
        logger.info("=" * 80)
        logger.info(f"  Shell Executor Classes: {len(shell_classes)}")
        logger.info(f"  Total Methods Analyzed: {total_methods}")
        logger.info(f"  Methods with Shell Executions: {methods_with_executions}")
        logger.info(f"  Total Shell Executions Found: {total_executions}")
        logger.info(f"  Methods Requiring Manual Review: {methods_with_grey_areas}")
        logger.info("=" * 80)
        
        if methods_with_grey_areas > 0:
            logger.info("\n  MANUAL REVIEW REQUIRED:")
            logger.info(f"   {methods_with_grey_areas} method(s) have grey areas (dynamic/unknown scripts)")
            logger.info("   Update config/manual_mappings_sample.yaml with actual script details")
            logger.info("   Then run: python manual_resource_associator.py")
        
        logger.info("\n" + "=" * 80)
        logger.info(" SHELL SCRIPT EXECUTION ENRICHMENT COMPLETE")
        logger.info("=" * 80)


def main():
    """Main entry point."""
    load_dotenv()
    
    config_path = os.getenv('KG_CONFIG_FILE', 'config/information_graph_config.yaml')
    
    enricher = ShellExecutionEnricher(config_path=config_path)
    
    try:
        enricher.connect()
        enricher.enrich()
    except Exception as e:
        logger.error(f"Enrichment failed: {e}", exc_info=True)
        raise
    finally:
        enricher.close()


if __name__ == '__main__':
    main()
