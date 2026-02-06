"""
Information Graph Builder V3 - Two Shot Approach
=================================================
Shot 1: Create complete folder/file tree structure
Shot 2: Mark package folders based on actual Java files
"""

import os
import re
import yaml
import os
from dotenv import load_dotenv
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field
from neo4j import GraphDatabase
import json
from datetime import datetime
import xml.etree.ElementTree as ET
import logging

# Import ClassInfo from call_hierarchy_extension
from classes.JavaCallHierarchyParser import JavaCallHierarchyParser
from classes.SpringBeanRegistry import SpringBeanRegistry
from classes.DataClasses import BeanDef, ClassInfo, JobDef
from classes.DAOAnalyzer import DAOAnalyzer
from neo4j_direct_step_loader import parse_directory
from call_hierarchy_extension_v2 import enrich_with_call_hierarchy_v2
from neo4j_direct_step_loader import generate_cypher

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def generate_cypher_for_hierarchy(job: JobDef) -> str:
    """
    Generate Cypher statements to load Java call hierarchy into Neo4j.
    
    Creates a graph structure:
    - Job -> Step -> JavaClass -> JavaMethod -> JavaClass -> JavaMethod (recursively)
    - Each JavaClass node represents a Java class
    - Each JavaMethod node represents a method
    - Relationships: HAS_METHOD (Class->Method), CALLS (Method->Method), USES_CLASS (Class->Class)
    
    Args:
        job: Enriched JobDef with enrichment data containing step_classes and all_classes_cache
        
    Returns:
        Cypher statements as a single string
    """
    if not hasattr(job, 'enrichment') or not job.enrichment:
        logger.warning(f"Job '{job.name}' has no enrichment data. Skipping hierarchy generation.")
        return ""
    
    lines: List[str] = []
    processed_classes = set()
    processed_methods = set()
    processed_class_relationships = set()
    processed_method_calls = set()
    
    step_classes = job.enrichment.get('step_classes', {})
    all_classes_cache = job.enrichment.get('all_classes_cache', {})
    
    if not step_classes:
        logger.warning(f"Job '{job.name}' has no step_classes in enrichment. Skipping.")
        return ""
    
    logger.info(f"Generating call hierarchy for job '{job.name}' with {len(step_classes)} step classes")
    
    def escape_cypher_string(s: str) -> str:
        """Escape string for Cypher query"""
        if not s:
            return ""
        return s.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n").replace("\r", "\\r")
    
    def process_class_recursive(class_fqn: str, depth: int = 0, max_depth: int = 10):
        """Recursively process a class and its called classes"""
        if depth > max_depth or class_fqn in processed_classes or class_fqn not in all_classes_cache:
            return
        
        processed_classes.add(class_fqn)
        class_info = all_classes_cache[class_fqn]
        
        # Determine if this is a DAO class
        dao_analyzer = DAOAnalyzer()
        is_dao_class = dao_analyzer._is_dao_class(class_info)
        is_dao_class_value = "true" if is_dao_class else "false"
        
        # Create JavaClass node
        escaped_fqn = escape_cypher_string(class_fqn)
        escaped_class_name = escape_cypher_string(class_info.class_name)
        escaped_package = escape_cypher_string(class_info.package)
        
        lines.append(
            f"MERGE (c:JavaClass {{fqn: '{escaped_fqn}'}}) "
            f"SET c.className = '{escaped_class_name}', "
            f"c.package = '{escaped_package}', "
            f"c.isDAOClass = {is_dao_class_value};"
        )
        
        # Process each method in the class
        for method_name, method_def in class_info.methods.items():
            method_fqn = f"{class_fqn}.{method_name}"
            
            if method_fqn not in processed_methods:
                processed_methods.add(method_fqn)
                
                # Create JavaMethod node
                escaped_method_fqn = escape_cypher_string(method_fqn)
                escaped_method_name = escape_cypher_string(method_name)
                escaped_return_type = escape_cypher_string(method_def.return_type)
                escaped_signature = escape_cypher_string(method_def.signature)
                modifiers_str = escape_cypher_string(",".join(method_def.modifiers))
                
                # Build cypher statement with base properties
                cypher_stmt = (
                    f"MERGE (m:JavaMethod {{fqn: '{escaped_method_fqn}'}}) "
                    f"SET m.methodName = '{escaped_method_name}', "
                    f"m.returnType = '{escaped_return_type}', "
                    f"m.signature = '{escaped_signature}', "
                    f"m.modifiers = '{modifiers_str}', "
                    f"m.classFqn = '{escaped_fqn}'"
                )
                # Set additional properties for DB operations, procedures, shell executions
                cypher_stmt += ", m.dbOperationCount = 0"                
                cypher_stmt += ", m.procedureCallCount = 0"
                cypher_stmt += ", m.shellExecutionCount = 0"                
                cypher_stmt += ";"
                lines.append(cypher_stmt)

                # Create HAS_METHOD relationship
                lines.append(
                    f"MATCH (c:JavaClass {{fqn: '{escaped_fqn}'}}) "
                    f"MATCH (m:JavaMethod {{fqn: '{escaped_method_fqn}'}}) "
                    f"MERGE (c)-[:HAS_METHOD]->(m);"
                )
                
                # Process method calls
                for call in method_def.calls:
                    # Determine target class - if not set, assume same class for self-calls
                    called_class_fqn = call.target_class if call.target_class else class_fqn
                    called_method_fqn = f"{called_class_fqn}.{call.method_name}"
                    
                    call_key = (method_fqn, called_method_fqn)
                    if call_key not in processed_method_calls:
                        processed_method_calls.add(call_key)
                        
                        # Create called method node (if it exists in cache)
                        if called_class_fqn in all_classes_cache:
                            called_class_info = all_classes_cache[called_class_fqn]
                            if call.method_name in called_class_info.methods:
                                called_method_def = called_class_info.methods[call.method_name]
                                
                                escaped_called_method_fqn = escape_cypher_string(called_method_fqn)
                                escaped_called_method_name = escape_cypher_string(call.method_name)
                                escaped_called_return_type = escape_cypher_string(called_method_def.return_type)
                                escaped_called_signature = escape_cypher_string(called_method_def.signature)
                                called_modifiers_str = escape_cypher_string(",".join(called_method_def.modifiers))
                                escaped_called_class_fqn = escape_cypher_string(called_class_fqn)
                                
                                # Build cypher statement for called method with base properties
                                called_cypher_stmt = (
                                    f"MERGE (cm:JavaMethod {{fqn: '{escaped_called_method_fqn}'}}) "
                                    f"SET cm.methodName = '{escaped_called_method_name}', "
                                    f"cm.returnType = '{escaped_called_return_type}', "
                                    f"cm.signature = '{escaped_called_signature}', "
                                    f"cm.modifiers = '{called_modifiers_str}', "
                                    f"cm.classFqn = '{escaped_called_class_fqn}'"
                                )
                                
                                # Set additional properties for DB operations, procedures, shell executions
                                called_cypher_stmt += ", cm.dbOperationCount = 0"
                                called_cypher_stmt += ", cm.procedureCallCount = 0"
                                called_cypher_stmt += ", cm.shellExecutionCount = 0"                                    
                                called_cypher_stmt += ";"
                                lines.append(called_cypher_stmt)                                    
                                
                                # Create CALLS relationship
                                lines.append(
                                    f"MATCH (m:JavaMethod {{fqn: '{escaped_method_fqn}'}}) "
                                    f"MATCH (cm:JavaMethod {{fqn: '{escaped_called_method_fqn}'}}) "
                                    f"MERGE (m)-[:CALLS {{lineNumber: {call.line_number}}}]->(cm);"
                                )
                            else:
                                # Method not found in class, but still create CALLS relationship if target method exists
                                escaped_called_method_fqn = escape_cypher_string(called_method_fqn)
                                logger.debug(f"Method {call.method_name} not found in class {called_class_fqn}, checking if method node exists")
                                
                                # Try to create relationship anyway (method might have been created elsewhere)
                                lines.append(
                                    f"MATCH (m:JavaMethod {{fqn: '{escaped_method_fqn}'}}) "
                                    f"MATCH (cm:JavaMethod {{fqn: '{escaped_called_method_fqn}'}}) "
                                    f"MERGE (m)-[:CALLS {{lineNumber: {call.line_number}}}]->(cm);"
                                )
                        else:
                            # Class not in cache, but still try to create relationship if both methods exist
                            escaped_called_method_fqn = escape_cypher_string(called_method_fqn)
                            logger.debug(f"Class {called_class_fqn} not in cache, attempting to link existing method nodes")
                            
                            lines.append(
                                f"MATCH (m:JavaMethod {{fqn: '{escaped_method_fqn}'}}) "
                                f"MATCH (cm:JavaMethod {{fqn: '{escaped_called_method_fqn}'}}) "
                                f"MERGE (m)-[:CALLS {{lineNumber: {call.line_number}}}]->(cm);"
                            )
        
        # Process called_classes relationships
        for called_class_fqn in class_info.called_classes:
            class_rel_key = (class_fqn, called_class_fqn)
            if class_rel_key not in processed_class_relationships:
                processed_class_relationships.add(class_rel_key)
                
                escaped_called_class_fqn = escape_cypher_string(called_class_fqn)
                
                # Ensure called class node exists
                if called_class_fqn in all_classes_cache:
                    called_class_info = all_classes_cache[called_class_fqn]
                    escaped_called_class_name = escape_cypher_string(called_class_info.class_name)
                    escaped_called_package = escape_cypher_string(called_class_info.package)
                    
                    # Determine if this is a DAO class
                    dao_analyzer_called = DAOAnalyzer()
                    is_dao_class_called = dao_analyzer_called._is_dao_class(called_class_info)
                    is_dao_class_called_value = "true" if is_dao_class_called else "false"
                    
                    lines.append(
                        f"MERGE (cc:JavaClass {{fqn: '{escaped_called_class_fqn}'}}) "
                        f"SET cc.className = '{escaped_called_class_name}', "
                        f"cc.package = '{escaped_called_package}', "
                        f"cc.isDAOClass = {is_dao_class_called_value};"
                    )
                    
                    # Create USES_CLASS relationship
                    lines.append(
                        f"MATCH (c:JavaClass {{fqn: '{escaped_fqn}'}}) "
                        f"MATCH (cc:JavaClass {{fqn: '{escaped_called_class_fqn}'}}) "
                        f"MERGE (c)-[:USES_CLASS]->(cc);"
                    )
                    
                    # Recursively process the called class
                    process_class_recursive(called_class_fqn, depth + 1, max_depth)
    
    # Link Steps to their Java classes
    for step_name, step_def in job.steps.items():
        step_class_fqn = None
        
        # Determine the main class for this step
        if step_def.step_kind == "TASKLET" and step_def.class_name:
            # Find FQN from step_classes
            for fqn, class_info in step_classes.items():
                if class_info.fqn == step_def.class_name:
                    step_class_fqn = fqn
                    break
        
        elif step_def.step_kind == "CHUNK":
            # For chunk steps, we'll link to reader, processor, writer classes
            for bean_name, class_attr in [
                (step_def.reader_bean, step_def.reader_class),
                (step_def.processor_bean, step_def.processor_class),
                (step_def.writer_bean, step_def.writer_class)
            ]:
                if class_attr:
                    for fqn, class_info in step_classes.items():
                        if class_info.fqn == class_attr:
                            # Process this class recursively FIRST to ensure it exists
                            process_class_recursive(fqn)
                            
                            escaped_step_name = escape_cypher_string(step_name)
                            escaped_class_fqn = escape_cypher_string(fqn)
                            
                            lines.append(
                                f"MATCH (s:Step {{name: '{escaped_step_name}'}}) "
                                f"MERGE (c:JavaClass {{fqn: '{escaped_class_fqn}'}}) "
                                f"MERGE (s)-[:IMPLEMENTED_BY]->(c);"
                            )
        
        if step_class_fqn:
            # Process this class and its call hierarchy recursively FIRST to ensure it exists
            process_class_recursive(step_class_fqn)
            
            escaped_step_name = escape_cypher_string(step_name)
            escaped_class_fqn = escape_cypher_string(step_class_fqn)
            
            lines.append(
                f"MATCH (s:Step {{name: '{escaped_step_name}'}}) "
                f"MERGE (c:JavaClass {{fqn: '{escaped_class_fqn}'}}) "
                f"MERGE (s)-[:IMPLEMENTED_BY]->(c);"
            )
    
    # Set isDAOClass property using DAOAnalyzer
    logger.info(f"Setting isDAOClass property for {len(processed_classes)} classes")
    dao_analyzer = DAOAnalyzer()
    dao_class_count = 0
    for class_fqn in processed_classes:
        if class_fqn in all_classes_cache:
            class_info = all_classes_cache[class_fqn]
            
            # Use DAOAnalyzer to determine if this is a DAO class
            # This checks for DAO naming patterns and common DAO frameworks
            is_dao = dao_analyzer._is_dao_class(class_info)
            
            escaped_fqn = escape_cypher_string(class_fqn)
            is_dao_class_value = "true" if is_dao else "false"
            
            lines.append(
                f"MATCH (c:JavaClass {{fqn: '{escaped_fqn}'}}) "
                f"SET c.isDAOClass = {is_dao_class_value};"
            )
            
            if is_dao:
                dao_class_count += 1
    
    logger.info(f"Generated {len(lines)} Cypher statements for job '{job.name}' call hierarchy")
    logger.info(f"  - Processed {len(processed_classes)} classes")
    logger.info(f"  - Processed {len(processed_methods)} methods")
    logger.info(f"  - Processed {len(processed_method_calls)} method calls")
    logger.info(f"  - Processed {len(processed_class_relationships)} class relationships")
    logger.info(f"  - Identified {dao_class_count} DAO classes")
    
    return "\n".join(lines)

class InformationGraphBuilder:
    """Builds hierarchical information graph using two-shot approach."""
    
    def __init__(self, config_path: str):
        """Initialize with configuration file."""
        # Load configuration
        with open(config_path, 'r', encoding='utf-8') as f:
            self.config = yaml.safe_load(f)
        
        # Neo4j connection
        neo4j_config = self.config['neo4j']
        self.driver = GraphDatabase.driver(
            neo4j_config['uri'],
            auth=(neo4j_config['user'], neo4j_config['password'])
        )
        self.database = neo4j_config['database_ig']
        
        # Java parser
        self.java_parser = JavaCallHierarchyParser() if self.config['scan_options'].get('parse_java_classes', True) else None
        
        # Build lookup maps
        self.repos_map = {r['path']: r for r in self.config.get('repositories', [])}
        self.file_type_rules = self.config.get('file_type_rules', {})
        self.skip_dirs = set(self.config.get('skip_directories', []))
        self.skip_files = self.config.get('skip_files', [])
        
        # Track created nodes
        self.created_nodes = set()
        
    def close(self):
        """Close Neo4j connection."""
        self.driver.close()
    
    def clear_database(self):
        """Clear all nodes and relationships."""
        with self.driver.session(database=self.database) as session:
            session.run("MATCH (n) DETACH DELETE n")
            print(f"✓ Cleared database: {self.database}")
    
    def create_constraints(self):
        """Create uniqueness constraints and indexes."""
        # First, drop all existing constraints
        with self.driver.session(database=self.database) as session:
            # Get all constraints
            result = session.run("SHOW CONSTRAINTS")
            for record in result:
                try:
                    constraint_name = record.get("name")
                    if constraint_name:
                        session.run(f"DROP CONSTRAINT {constraint_name} IF EXISTS")
                except Exception:
                    pass
        
        # Create our constraints
        constraints = [
            "CREATE CONSTRAINT node_path_unique IF NOT EXISTS FOR (n:Node) REQUIRE n.path IS UNIQUE",
        ]
        
        indexes = [
            "CREATE INDEX node_name_idx IF NOT EXISTS FOR (n:Node) ON (n.name)",
            "CREATE INDEX node_type_idx IF NOT EXISTS FOR (n:Node) ON (n.node_type)",
        ]
        
        with self.driver.session(database=self.database) as session:
            for constraint in constraints:
                try:
                    session.run(constraint)
                except Exception as e:
                    pass
            
            for index in indexes:
                try:
                    session.run(index)
                except Exception as e:
                    pass
        
        print("✓ Created constraints and indexes")
    
    def _is_spring_xml(self, file_path: Path) -> bool:
        """Check if XML file contains Spring namespaces."""
        spring_namespaces = [
            'http://www.springframework.org/schema/beans',
            'http://www.springframework.org/schema/batch',
            'http://www.springframework.org/schema/context',
            'http://www.springframework.org/schema/tx',
            'http://www.springframework.org/schema/jdbc',
            'http://www.springframework.org/schema/aop'
        ]
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Check if any Spring namespace is present in root tag
            root_ns = root.tag
            if any(ns in root_ns for ns in spring_namespaces):
                return True
            
            # Also check in attributes
            for attr_name, attr_value in root.attrib.items():
                if any(ns in attr_value for ns in spring_namespaces):
                    return True
                    
        except Exception:
            pass
        
        return False
    
    def _should_skip_file(self, file_path: Path) -> bool:
        """Check if file should be skipped based on skip_files configuration."""
        file_name = file_path.name
        
        for skip_pattern in self.skip_files:
            # Exact name match
            if skip_pattern == file_name:
                return True
            
            # Wildcard pattern match (simple glob-style)
            if '*' in skip_pattern:
                # Convert simple glob pattern to regex
                import fnmatch
                if fnmatch.fnmatch(file_name, skip_pattern):
                    return True
        
        return False
    
    def _is_test_path(self, file_path: Path) -> bool:
        """Check if file path is in test directories."""
        path_str = str(file_path).replace('\\', '/')
        
        # Common test directory patterns
        test_patterns = [
            '/src/test/',
            '/test/',
            '/src/main/test/',
            '\\src\\test\\',
            '\\test\\',
            '\\src\\main\\test\\'
        ]
        
        return any(pattern in path_str for pattern in test_patterns)
    
    def identify_file_type(self, file_path: Path) -> List[str]:
        """Identify file type based on config rules."""
        file_str = str(file_path).replace('\\', '/')
        file_name = file_path.name
        file_ext = file_path.suffix
        file_types = []
        
        # Special handling for XML files - check for Spring namespaces
        if file_ext == '.xml' and file_name.lower() != 'pom.xml' and file_name.lower() != 'web.xml':
            if self._is_spring_xml(file_path):
                file_types.append('SpringConfig')
            # Always add XmlConfig for non-pom XML files
            file_types.append('XmlConfig')
            return file_types
        
        for type_name, rules in self.file_type_rules.items():
            matched = False
            
            # Check exact names
            if 'exact_names' in rules and file_name in rules['exact_names']:
                matched = True
            
            # Check extensions
            if 'extensions' in rules and file_ext in rules['extensions']:
                # Check include patterns
                if 'include_patterns' in rules:
                    if any(re.search(pattern, file_str, re.IGNORECASE) for pattern in rules['include_patterns']):
                        matched = True
                # Check exclude patterns
                elif 'exclude_patterns' in rules:
                    if not any(re.search(pattern, file_str, re.IGNORECASE) for pattern in rules['exclude_patterns']):
                        matched = True
                else:
                    matched = True
            
            # Check locations
            if matched and 'locations' in rules:
                if not any(loc in file_str for loc in rules['locations']):
                    matched = False
            
            if matched:
                # Convert type_name to CamelCase label
                label = ''.join(word.capitalize() for word in type_name.split('_'))
                file_types.append(label)
        
        if not file_types:
            file_types.append('File')
        
        return file_types
    
    # =====================================================================
    # SHOT 1: Create basic tree structure
    # =====================================================================
    
    def shot1_create_tree(self, root_path: str):
        """
        Shot 1: Create complete folder/file tree.
        Mark only: Directory, Repository, Project
        All other folders are just 'Folder'
        """
        root = Path(root_path).absolute()
        
        if not root.exists():
            raise ValueError(f"Path does not exist: {root_path}")
        
        print(f"\n📂 SHOT 1: Creating tree structure")
        print(f"Scanning: {root}")
        print("=" * 80)
        
        stats = {
            'directories': 1,
            'repositories': 0,
            'folders': 0,
            'projects': 0,
            'files': 0,
            'java_classes': 0,
            'test_classes': 0,
            'config_files': 0
        }
        
        # Create root directory node
        root_path_str = str(root)
        query = """
        MERGE (n:Node:Directory {path: $path})
        ON CREATE SET 
            n.name = $name,
            n.node_type = 'Directory',
            n.created_at = datetime()
        RETURN n
        """
        
        with self.driver.session(database=self.database) as session:
            session.run(query,
                path=root_path_str,
                name=root.name
            )
        
        self.created_nodes.add(root_path_str)
        
        # Recursively scan everything
        self._scan_recursive_shot1(root, root_path_str, stats)
        
        print("\n" + "=" * 80)
        print("✓ Shot 1 completed!")
        print("\nStatistics:")
        print(f"  Directories: {stats['directories']}")
        print(f"  Repositories: {stats['repositories']}")
        print(f"  Folders: {stats['folders']}")
        print(f"  Projects: {stats['projects']}")
        print(f"  Files: {stats['files']}")
        print(f"    Java Classes: {stats['java_classes']}")
        print(f"    Test Classes: {stats['test_classes']}")
        print(f"    Config Files: {stats['config_files']}")
        print("=" * 60)
    
    def _scan_recursive_shot1(self, current_path: Path, parent_path_str: str, stats: Dict, depth: int = 0):
        """Recursively scan and create basic tree structure."""
        max_depth = self.config['scan_options'].get('max_depth', 20)
        
        if depth > max_depth:
            return
        
        try:
            items = list(current_path.iterdir())
        except (PermissionError, OSError) as e:
            return
        
        # Process each item
        for item in items:
            # Skip ignored directories
            if item.is_dir() and item.name in self.skip_dirs:
                continue
            
            # Skip ignored files
            if item.is_file() and self._should_skip_file(item):
                continue
            
            # Use absolute path for tracking
            item_path_str = str(item.absolute())
            
            # Skip if already created (prevents duplicates)
            if item_path_str in self.created_nodes:
                continue
            
            if item.is_file():
                # Create file node
                self._create_file_shot1(item, parent_path_str, stats)
            else:
                # Create folder node
                self._create_folder_shot1(item, parent_path_str, stats)
                # Recurse into folder
                self._scan_recursive_shot1(item, item_path_str, stats, depth + 1)
            
            # Mark as created after successful creation
            self.created_nodes.add(item_path_str)
    
    def _create_folder_shot1(self, folder_path: Path, parent_path: str, stats: Dict):
        """Create a folder node - mark as Repository or Project if applicable."""
        # Use absolute path consistently
        path_str = str(folder_path.absolute())
        
        # Determine folder type
        if path_str in self.repos_map or str(folder_path) in self.repos_map:
            folder_type = "Repository"
            label = "Node:Repository"
            stats['repositories'] += 1
        elif (folder_path / 'pom.xml').exists() or (folder_path / 'build.gradle').exists():
            folder_type = "Project"
            label = "Node:Project"
            stats['projects'] += 1
        else:
            folder_type = "Folder"
            label = "Node:Folder"
            stats['folders'] += 1
        
        query = f"""
        MERGE (n:{label} {{path: $path}})
        ON CREATE SET 
            n.name = $name,
            n.node_type = $node_type,
            n.created_at = datetime()
        WITH n
        MATCH (parent:Node {{path: $parent_path}})
        MERGE (parent)-[:CONTAINS]->(n)
        RETURN n
        """
        
        with self.driver.session(database=self.database) as session:
            session.run(query,
                path=path_str,
                name=folder_path.name,
                node_type=folder_type,
                parent_path=parent_path
            )
    
    def _create_file_shot1(self, file_path: Path, parent_path: str, stats: Dict):
        """Create a file node."""
        file_types = self.identify_file_type(file_path)
        
        # Check if it's a Java class
        is_java = 'JavaClass' in file_types or 'JavaTestClass' in file_types
        
        if is_java and self.java_parser:
            # Parse Java file to get ClassInfo - use absolute path
            absolute_path = str(file_path.absolute())
            class_info = self.java_parser.parse_java_file(absolute_path)
            
            if class_info:
                self._create_java_class_shot1(class_info, parent_path)
                stats['java_classes'] += 1
                if 'JavaTestClass' in file_types:
                    stats['test_classes'] += 1
            else:
                # Failed to parse, create regular file
                self._create_regular_file_shot1(file_path, parent_path, file_types, stats)
        else:
            # Regular file
            self._create_regular_file_shot1(file_path, parent_path, file_types, stats)
    
    def _create_regular_file_shot1(self, file_path: Path, parent_path: str, file_types: List[str], stats: Dict):
        """Create a regular file node."""
        safe_types = [ft.replace(' ', '').replace('-', '') for ft in file_types if ft]
        labels = 'Node:File:' + ':'.join(safe_types) if safe_types else 'Node:File'
        
        # Use absolute path consistently
        path_str = str(file_path.absolute())
        
        try:
            file_size = file_path.stat().st_size
        except:
            file_size = 0
        
        # Check if SpringConfig is in test or main directory
        is_spring_config = 'SpringConfig' in file_types
        is_main_config = not self._is_test_path(file_path) if is_spring_config else None
        
        # Build the query with conditional properties
        if is_spring_config:
            query = f"""
            MERGE (n:{labels} {{path: $path}})
            ON CREATE SET 
                n.name = $name,
                n.node_type = 'File',
                n.extension = $extension,
                n.size = $size,
                n.file_types = $file_types,
                n.isMainConfig = $isMainConfig,
                n.created_at = datetime()
            WITH n
            MATCH (parent:Node {{path: $parent_path}})
            MERGE (parent)-[:CONTAINS]->(n)
            RETURN n
            """
            
            with self.driver.session(database=self.database) as session:
                session.run(query,
                    path=path_str,
                    name=file_path.name,
                    extension=file_path.suffix,
                    size=file_size,
                    file_types=','.join(file_types),
                    isMainConfig=is_main_config,
                    parent_path=parent_path
                )
        else:
            query = f"""
            MERGE (n:{labels} {{path: $path}})
            ON CREATE SET 
                n.name = $name,
                n.node_type = 'File',
                n.extension = $extension,
                n.size = $size,
                n.file_types = $file_types,
                n.created_at = datetime()
            WITH n
            MATCH (parent:Node {{path: $parent_path}})
            MERGE (parent)-[:CONTAINS]->(n)
            RETURN n
            """
            
            with self.driver.session(database=self.database) as session:
                session.run(query,
                    path=path_str,
                    name=file_path.name,
                    extension=file_path.suffix,
                    size=file_size,
                    file_types=','.join(file_types),
                    parent_path=parent_path
                )
        
        stats['files'] += 1
        
        if any(ft in ['SpringConfig', 'XmlConfig'] for ft in file_types):
            stats['config_files'] += 1
    
    def _create_java_class_shot1(self, class_info: ClassInfo, parent_path: str):
        """Create a JavaClass node with package property and isDAOClass flag."""
        # Determine if this is a DAO class
        dao_analyzer = DAOAnalyzer()
        is_dao_class = dao_analyzer._is_dao_class(class_info)
        
        query = """
        MERGE (n:Node:File:JavaClass {path: $path})
        ON CREATE SET 
            n.name = $name,
            n.node_type = 'File',
            n.className = $className,
            n.fqn = $fqn,
            n.package = $package,
            n.extends = $extends,
            n.implements = $implements,
            n.imports = $imports,
            n.fields = $fields,
            n.method_count = $method_count,
            n.isDAOClass = $isDAOClass,
            n.created_at = datetime()
        WITH n
        MATCH (parent:Node {path: $parent_path})
        MERGE (parent)-[:CONTAINS]->(n)
        RETURN n, parent
        """
        
        with self.driver.session(database=self.database) as session:
            result = session.run(query,
                path=class_info.source_path,
                name=Path(class_info.source_path).name,
                className=class_info.class_name,
                fqn=class_info.fqn,
                package=class_info.package,
                extends=class_info.extends or "",
                implements=class_info.implements,
                imports=class_info.imports,
                fields=json.dumps(class_info.fields),
                method_count=len(class_info.methods),
                isDAOClass=is_dao_class,
                parent_path=parent_path
            )
            
            # Check if the query succeeded
            record = result.single()
            if not record:
                print(f"WARNING: Parent not found for {class_info.class_name} at {class_info.source_path}")
    
    # =====================================================================
    # SHOT 2: Mark package folders
    # =====================================================================
    
    def shot2_mark_packages(self):
        """
        Shot 2: Find all Java files, extract packages, mark folders as Package.
        """
        print(f"\n📦 SHOT 2: Marking package folders")
        print("=" * 60)
        
        # Find all JavaClass nodes with packages
        query = """
        MATCH (java:JavaClass)
        WHERE java.package IS NOT NULL AND java.package <> ''
        RETURN java.path as path, java.package as package
        """
        
        with self.driver.session(database=self.database) as session:
            result = session.run(query)
            java_files = [(record['path'], record['package']) for record in result]
        
        print(f"Found {len(java_files)} Java files with packages")
        
        # Process each Java file
        packages_marked = set()
        
        for java_path, package_name in java_files:
            # Mark folders based on this Java file's package
            self._mark_package_folders(Path(java_path), package_name, packages_marked)
        
        print(f"\n✓ Marked {len(packages_marked)} unique package folders")
        print("=" * 60)
    
    def _mark_package_folders(self, java_file_path: Path, package_name: str, packages_marked: Set[str]):
        """Mark folders as Package based on Java file's package declaration."""
        if not package_name:
            return
        
        # Get package parts
        package_parts = package_name.split('.')
        
        # Find 'src' in path
        path_parts = java_file_path.parts
        if 'src' not in path_parts:
            return
        
        src_idx = path_parts.index('src')
        
        # Get path from src to file's parent
        folders_after_src = path_parts[src_idx + 1 : -1]  # Exclude file name
        
        # Match package parts with folders
        # Start from the end and work backwards
        for i in range(len(package_parts)):
            # Check if folder structure matches package structure
            if i < len(folders_after_src):
                # Build path to potential package folder
                potential_package_folders = []
                
                # Try to find where package starts in folder structure
                for start_idx in range(len(folders_after_src)):
                    matches = True
                    for j, pkg_part in enumerate(package_parts):
                        folder_idx = start_idx + j
                        if folder_idx >= len(folders_after_src):
                            matches = False
                            break
                        if folders_after_src[folder_idx] != pkg_part:
                            matches = False
                            break
                    
                    if matches:
                        # Found matching package structure
                        # Mark each folder in the package path
                        for j, pkg_part in enumerate(package_parts):
                            folder_idx = start_idx + j
                            if folder_idx < len(folders_after_src):
                                # Build full path to this folder
                                folder_path_parts = path_parts[:src_idx + 1] + path_parts[src_idx + 1 : src_idx + 1 + folder_idx + 1]
                                folder_path = str(Path(*folder_path_parts))
                                
                                # Mark as package if not already marked
                                if folder_path not in packages_marked:
                                    self._convert_folder_to_package(folder_path, package_parts[:j+1])
                                    packages_marked.add(folder_path)
                        break
    
    def _load_spring_xml_files_from_graph(self) -> List[str]:
        """
        Load Spring XML configuration files from the Neo4j graph.
        
        This method replaces the file system scanning approach (find_xml_files) 
        by querying the graph for nodes with SpringConfig label.
        
        Returns:
            List of absolute file paths to Spring XML configuration files
        """
        print(f"\n📄 Loading Spring XML files from graph")
        print("=" * 60)
        
        query = """
        MATCH (f:SpringConfig)
        WHERE f.path IS NOT NULL AND f.isMainConfig = true
        RETURN f.path as path, f.name as name
        ORDER BY f.path
        """
        
        spring_xml_files = []
        
        with self.driver.session(database=self.database) as session:
            result = session.run(query)
            for record in result:
                file_path = record['path']
                spring_xml_files.append(file_path)
        
        print(f"  Found {len(spring_xml_files)} Spring XML files in graph")
        
        # Show sample files
        if spring_xml_files:
            print(f"\n  Sample files:")
            for i, xml_file in enumerate(spring_xml_files[:5]):
                file_name = Path(xml_file).name
                print(f"    {i+1}. {file_name}")
            if len(spring_xml_files) > 5:
                print(f"    ... and {len(spring_xml_files) - 5} more")
        
        print("=" * 60)
        return spring_xml_files
    
    def _find_java_source_from_graph(self, class_name: str) -> str:
        """
        Find Java source file path for a given class name from the Neo4j graph.
        
        This method replaces the file system scanning approach (find_java_source_file)
        by querying the graph for JavaClass nodes with matching FQN.
        
        Args:
            class_name: Fully qualified class name (e.g., "com.example.MyClass")
            
        Returns:
            Absolute path to the Java source file, or empty string if not found
        """
        if not class_name:
            return ""
        
        query = """
        MATCH (j:JavaClass)
        WHERE j.fqn = $class_name
        RETURN j.path as path
        LIMIT 1
        """
        
        with self.driver.session(database=self.database) as session:
            result = session.run(query, class_name=class_name)
            record = result.single()
            
            if record:
                return record.get('path', "")
        
        return ""
    
    def _build_global_bean_map_from_graph(self, spring_xml_files: List[str]) -> Dict[str, Tuple[str, str]]:
        """
        Build global bean map from Spring XML files using graph for Java source lookups.
        
        This method replaces the file system scanning approach by:
        1. Parsing Spring XML files for bean definitions (still reads XML from file system)
        2. Using graph queries to find Java source paths instead of file system search
        
        Args:
            spring_xml_files: List of Spring XML file paths (from graph)
            
        Returns:
            Dictionary mapping bean ID to tuple of (class_name, source_path)
        """
        print(f"\n🔧 Building Global Bean Map from Graph")
        print("=" * 60)
        
        global_bean_map: Dict[str, Tuple[str, str]] = {}
        beans_without_source = []
        
        for xml_file in spring_xml_files:
            try:
                tree = ET.parse(xml_file)
                root = tree.getroot()
                
                # Define namespace
                ns = {'beans': 'http://www.springframework.org/schema/beans'}
                
                # Extract all bean definitions
                for bean_el in root.findall('.//beans:bean', ns):
                    bean_id = bean_el.get("id")
                    bean_class = bean_el.get("class", "")
                    
                    if bean_id and bean_class:
                        # Use graph to find Java source path
                        source_path = self._find_java_source_from_graph(bean_class)
                        
                        if not source_path:
                            beans_without_source.append((bean_id, bean_class))
                        
                        # Add to global map
                        if bean_id in global_bean_map and global_bean_map[bean_id][0] != bean_class:
                            print(f"  Warning: Bean ID '{bean_id}' redefined. "
                                  f"Previous: {global_bean_map[bean_id][0]}, New: {bean_class}")
                        
                        global_bean_map[bean_id] = (bean_class, source_path)
                
            except Exception as e:
                print(f"  Warning: Failed to process {Path(xml_file).name}: {e}")
        
        # Statistics
        total_with_source = sum(1 for _, source_path in global_bean_map.values() if source_path)
        print(f"\n  Bean Map Statistics:")
        print(f"    Total Beans: {len(global_bean_map)}")
        print(f"    With Source Path: {total_with_source}")
        print(f"    Without Source Path: {len(beans_without_source)}")
        
        if beans_without_source and len(beans_without_source) <= 10:
            print(f"\n  Beans without source path:")
            for bean_id, bean_class in beans_without_source:
                print(f"    - Bean '{bean_id}' -> Class '{bean_class}'")
        elif len(beans_without_source) > 10:
            print(f"\n  First 10 beans without source path:")
            for bean_id, bean_class in beans_without_source[:10]:
                print(f"    - Bean '{bean_id}' -> Class '{bean_class}'")
            print(f"    ... and {len(beans_without_source) - 10} more")
        
        print("=" * 60)
        return global_bean_map
    
    def build_global_bean_registry(self, spring_xml_files: List[str], original_bean_map: Dict[str, Tuple[str, str]]) -> SpringBeanRegistry:
        """
        Step 2: Build comprehensive bean registry with dual indexes.
        Creates BeanDef objects for all beans with proper dependency tracking.
        
        Args:
            spring_xml_files: List of Spring XML files to process
            original_bean_map: Original bean map for source path reference
            
        Returns:
            SpringBeanRegistry with all beans indexed
        """
        print("\n" + "=" * 80)
        print("Step 2: Building Global Bean Registry")
        print("=" * 80)
        
        registry = SpringBeanRegistry()
        
        
        # Process each XML file
        for xml_file in spring_xml_files:
            try:
                tree = ET.parse(xml_file)
                root = tree.getroot()
                
                ns = {'beans': 'http://www.springframework.org/schema/beans'}
                
                for bean_elem in root.findall('.//beans:bean', ns):
                    bean_id = bean_elem.get('id')
                    bean_class = bean_elem.get('class')
                    
                    if not bean_id or not bean_class:
                        continue
                    
                    # Extract simple class name
                    bean_class_name = bean_class.split('.')[-1] if '.' in bean_class else bean_class
                    
                    # Get source path from original map
                    source_path = None
                    if bean_id in original_bean_map:
                        source_path = original_bean_map[bean_id][1]
                    
                    # Create BeanDef
                    bean_def = BeanDef(
                        bean_id=bean_id,
                        bean_class=bean_class,
                        bean_class_name=bean_class_name,
                        class_source_path=source_path,
                        source_xml_file=xml_file
                    )
                    
                    # Extract property dependencies
                    for prop in bean_elem.findall('beans:property', ns):
                        prop_name = prop.get('name')
                        ref_bean_id = prop.get('ref')
                        prop_value = prop.get('value')
                        
                        if prop_name and ref_bean_id:
                            # Get referenced bean class if available
                            ref_bean_class = self._resolve_dependency_class(ref_bean_id, registry, original_bean_map)
                            bean_def.property_dependencies[prop_name] = (f"type:ref",f"ref_bean_id:{ref_bean_id}", f"ref_bean_class:{ref_bean_class}")
                        elif prop_name and prop_value:
                            # Literal value, no dependency
                            bean_def.property_dependencies[prop_name] = (f"type:value",f"value:{prop_value}", "")
                    
                    # Extract constructor dependencies
                    for arg in bean_elem.findall('beans:constructor-arg', ns):
                        ref_bean_id = arg.get('ref')
                        arg_name = arg.get('name')
                        arg_value = arg.get('value')
                        
                        # Check for nested <value> element if no value attribute
                        if not arg_value:
                            value_elem = arg.find('beans:value', ns)
                            if value_elem is not None and value_elem.text:
                                arg_value = value_elem.text.strip()

                        if ref_bean_id and not arg_value:
                            key = arg_name if arg_name else f"constructor_arg_{arg.get('index', '0')}"
                            ref_bean_class = self._resolve_dependency_class(ref_bean_id, registry, original_bean_map)
                            bean_def.constructor_dependencies[key] = (f"type:ref",f"ref_bean_id:{ref_bean_id}", f"ref_bean_class:{ref_bean_class}")
                        
                        elif arg_value and not ref_bean_id:
                            key = arg_name if arg_name else f"constructor_arg_{arg.get('index', '0')}"
                            bean_def.constructor_dependencies[key] = (f"type:value",f"value:{arg_value}", "")

                    # Add to registry
                    registry.add_bean(bean_def)
                    
            except Exception as e:
                print(f"  Warning: Failed to process {xml_file}: {e}")
        
        # Print statistics
        stats = registry.get_stats()
        print(f"\n  Registry Statistics:")
        print(f"    Total Beans: {stats['total_beans']}")
        print(f"    Unique Classes: {stats['unique_classes']}")
        print(f"    With Source Path: {stats['with_source_path']}")
        print(f"    Pending Processing: {stats['pending_processing']}")
        
        return registry

    def _resolve_dependency_class(self, ref_bean_id: str, registry: SpringBeanRegistry, 
                                original_bean_map: Dict[str, Tuple[str, str]]) -> str:
        """
        Helper to resolve dependency bean class.
        Returns the class name if available, otherwise empty string.
        """
        # Try registry first
        existing_bean = registry.get_by_id(ref_bean_id)
        if existing_bean:
            return existing_bean.bean_class
        
        # Try original bean map
        if ref_bean_id in original_bean_map:
            return original_bean_map[ref_bean_id][0]
        
        return ""
    
    def _store_bean_map_in_graph(self, bean_map: Dict[str, Tuple[str, str]], spring_xml_files: List[str]):
        """
        Store the global bean map in the information graph as Bean nodes.
        
        Creates:
        - Bean nodes with properties: beanId, beanClass, path, hasSource
        - DEFINED_IN relationship to SpringConfig files
        - IMPLEMENTS relationship to JavaClass nodes (if source path exists)
        
        Args:
            bean_map: Dictionary mapping bean ID to tuple of (class_name, source_path)
            spring_xml_files: List of Spring XML files where beans are defined
        """
        print(f"\n🔗 Storing Bean Map in Information Graph")
        print("=" * 60)
        
        # Build reverse map: xml_file -> list of bean_ids
        xml_to_beans: Dict[str, List[str]] = {}
        for xml_file in spring_xml_files:
            try:
                tree = ET.parse(xml_file)
                root = tree.getroot()
                ns = {'beans': 'http://www.springframework.org/schema/beans'}
                
                beans_in_file = []
                for bean_el in root.findall('.//beans:bean', ns):
                    bean_id = bean_el.get("id")
                    if bean_id:
                        beans_in_file.append(bean_id)
                
                xml_to_beans[xml_file] = beans_in_file
            except Exception as e:
                logger.warning(f"Failed to parse {Path(xml_file).name}: {e}")
        
        beans_created = 0
        beans_with_source = 0
        beans_without_source = 0
        
        with self.driver.session(database=self.database) as session:
            for bean_id, (bean_class, source_path) in bean_map.items():
                has_source = bool(source_path)
                
                # Extract simple class name for easier querying
                simple_class_name = bean_class.split('.')[-1] if '.' in bean_class else bean_class
                
                # Create Bean node
                query_create_bean = """
                MERGE (b:Bean {beanId: $beanId})
                ON CREATE SET 
                    b.beanClass = $beanClass,
                    b.simpleClassName = $simpleClassName,
                    b.path = $path,
                    b.hasSource = $hasSource,
                    b.created_at = datetime()
                ON MATCH SET
                    b.beanClass = $beanClass,
                    b.simpleClassName = $simpleClassName,
                    b.path = $path,
                    b.hasSource = $hasSource
                RETURN b
                """
                
                session.run(query_create_bean,
                    beanId=bean_id,
                    beanClass=bean_class,
                    simpleClassName=simple_class_name,
                    path=source_path or "",
                    hasSource=has_source
                )
                
                beans_created += 1
                if has_source:
                    beans_with_source += 1
                else:
                    beans_without_source += 1
                
                # Create relationship to SpringConfig file where bean is defined
                for xml_file, beans_in_file in xml_to_beans.items():
                    if bean_id in beans_in_file:
                        query_link_xml = """
                        MATCH (b:Bean {beanId: $beanId})
                        MATCH (f:SpringConfig {path: $xmlPath})
                        MERGE (b)-[:DEFINED_IN]->(f)
                        """
                        session.run(query_link_xml,
                            beanId=bean_id,
                            xmlPath=xml_file
                        )
                        break
                
                # Create relationship to JavaClass if source path exists
                if has_source:
                    query_link_class = """
                    MATCH (b:Bean {beanId: $beanId})
                    MATCH (j:JavaClass {path: $path})
                    MERGE (b)-[:IMPLEMENTS]->(j)
                    """
                    try:
                        session.run(query_link_class,
                            beanId=bean_id,
                            path=source_path
                        )
                    except Exception as e:
                        logger.debug(f"Could not link bean '{bean_id}' to JavaClass: {e}")
        
        print(f"\n  Bean Node Statistics:")
        print(f"    Total Beans Created: {beans_created}")
        print(f"    With Source Path: {beans_with_source}")
        print(f"    Without Source Path: {beans_without_source}")
        print("=" * 60)
    
    def _load_classes(self):

        # Step 1: Scan all Spring XML files
        spring_xml_files = self._load_spring_xml_files_from_graph()       

        # Step 2: Build original bean map for source paths
        original_bean_map = self._build_global_bean_map_from_graph(spring_xml_files)
        
        # Step 2.5: Store bean map in information graph
        self._store_bean_map_in_graph(original_bean_map, spring_xml_files)
        
        # Step 3: Build comprehensive bean registry
        registry = self.build_global_bean_registry(spring_xml_files, original_bean_map)
        
        # Step 4: Parse batch job definitions
        job_defs = parse_directory(original_bean_map, spring_xml_files)

        # Step 5: Enrich with call hierarchy
        # Note: DB operation analysis moved to separate script (db_operation_enricher.py)
        enriched_jobs = enrich_with_call_hierarchy_v2(job_defs, registry, original_bean_map)
        
        print("\n" + "=" * 80)
        print("✅ CALL HIERARCHY BUILD COMPLETE")
        print("=" * 80)
    
        # Step 6: Load Steps and create relationships to Jobs
        print("\n" + "=" * 80)
        """Load Steps and create relationships to Jobs"""
        for job_def in enriched_jobs:
            # Load basic step information
            cypher = generate_cypher(job_def)
            statements = [s.strip() for s in cypher.split(";") if s.strip()]    
            with self.driver.session(database=self.database) as session:
                for stmt in statements:
                    #logger.info(f"Executing Cypher:: {stmt[:500]}...")
                    session.run(stmt)

            logger.info(f"✓ Loaded {len(statements)} statements for Steps of job '{job_def.name}'")
            
            # Load Java call hierarchy
            hierarchy_cypher = generate_cypher_for_hierarchy(job_def)
            if hierarchy_cypher:
                logger.info(f"Loading Java call hierarchy for job '{job_def.name}'...")
                hierarchy_statements = [s.strip() for s in hierarchy_cypher.split(";") if s.strip()]
                with self.driver.session(database=self.database) as session:
                    for stmt in hierarchy_statements:
                        try:
                            session.run(stmt)
                        except Exception as e:
                            logger.error(f"Error executing hierarchy statement: {str(e)[:200]}")
                            logger.debug(f"Failed statement: {stmt[:500]}")
                
                logger.info(f"✓ Loaded {len(hierarchy_statements)} hierarchy statements for job '{job_def.name}'")
        
        # Note: All analysis (DB, procedures, shell scripts) moved to separate scripts
        # Run enrichment scripts after this script completes
        print("\n" + "=" * 80)
        print("✅ INFORMATION GRAPH BUILD COMPLETE")
        print("=" * 80)
        print("\nNext Steps: Run enrichment scripts to analyze operations")
        print("  1. python db_operation_enricher.py          # Analyze DB operations")
        print("  2. python procedure_call_enricher.py        # Analyze stored procedures")
        print("  3. python shell_execution_enricher.py       # Analyze shell scripts")
        print("=" * 80)

    def _convert_folder_to_package(self, folder_path: str, package_parts: List[str]):
        """Convert a Folder node to a Package node."""
        package_name = '.'.join(package_parts)
        
        # Determine if source or test based on path
        is_test = '\\test\\' in folder_path or '/test/' in folder_path
        
        query = """
        MATCH (n:Folder {path: $path})
        SET n:Package
        SET n.node_type = 'Package'
        SET n.package_name = $package_name
        SET n.full_package_name = $full_package_name
        SET n.available_to_scan = $available_to_scan
        SET n.package_type = $package_type
        RETURN n
        """
        
        with self.driver.session(database=self.database) as session:
            session.run(query,
                path=folder_path,
                package_name=package_parts[-1],  # Just the last segment
                full_package_name=package_name,
                available_to_scan=not is_test,
                package_type='test' if is_test else 'source'
            )


def main():
    """Main execution function."""
    #DEFAULT_CONFIG_FILE = r"D:\Iris\practice\GenAI\code\Batch_KG\information_graph_config111.yaml"

    load_dotenv()
    config_file = os.getenv("KG_CONFIG_FILE") #or DEFAULT_CONFIG_FILE
    
    print("=" * 60)
    print("Information Graph Builder V3 (Two-Shot Approach)")
    print("=" * 60)
    print(f"Config: {config_file}")
    
    builder = InformationGraphBuilder(config_path=config_file)
    
    try:
        # Clear existing data
        print("\n1. Clearing existing database...")
        builder.clear_database()
        
        # Create constraints
        print("\n2. Creating constraints and indexes...")
        #builder.create_constraints()
        
        # SHOT 1: Create basic tree
        print("\n3. SHOT 1: Building tree structure...")
        root_dir = builder.config['root_directory']
        builder.shot1_create_tree(root_dir)
        
        # SHOT 2: Mark packages
        print("\n4. SHOT 2: Marking package folders...")
        builder.shot2_mark_packages()

        builder._load_classes()
        
        print("\n✓ Information Graph built successfully!")
        
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        builder.close()


if __name__ == "__main__":
    main()
