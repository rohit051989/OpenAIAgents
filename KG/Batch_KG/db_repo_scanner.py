"""
Database Repository Scanner
============================

Scans database-as-code repositories and creates Resource nodes in the information graph.
This ensures Resources exist in the graph before code analysis links to them.

Supports:
- Tables
- Views
- Procedures
- Functions
- Packages
- Triggers
- Synonyms
- Sequences
- DatabaseLinks

Structure Expected:
    db_repo/
        <project>/
            DB/
                Datamart|OnLine/
                    Schemas/
                        <SCHEMA_NAME>/
                            Tables/
                            Packages/
                            Procedures/
                            Functions/
                            Views/
                            Triggers/
                            Synonyms/
                            Sequences/
                            DatabaseLinks/

File Naming Convention:
    SCHEMA.OBJECT_NAME_ddl.sql
    or
    SCHEMA.PACKAGE.PROCEDURE_ddl.sql (for procedures in packages)

Usage:
    scanner = DBRepoScanner(config, neo4j_driver, database_name)
    scanner.scan_db_repositories()
"""

import os
import re
import logging
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from classes.KGNodeDefs import IGRepositoryNodeDef, IGFolderNodeDef, IGFileNodeDef, ResourceNodeDef
from classes.path_utils import to_relative_path
from neo4j import GraphDatabase
import uuid
import sqlparse
from sqlparse.sql import Identifier, Function, Parenthesis
from sqlparse.tokens import Keyword, DML, DDL

logger = logging.getLogger(__name__)


class DBRepoScanner:
    """Scanner for database-as-code repositories"""
    
    def __init__(self, config: dict, neo4j_driver, database: str):
        """
        Initialize DB repo scanner.
        
        Args:
            config: Configuration dictionary from YAML
            neo4j_driver: Neo4j driver instance
            database: Neo4j database name
        """
        self.config = config
        self.driver = neo4j_driver
        self.database = database
        
        # SQL statement to Resource type mapping
        self.create_type_mapping = {
            'TABLE': 'TABLE',
            'VIEW': 'VIEW',
            'PROCEDURE': 'PROCEDURE',
            'FUNCTION': 'FUNCTION',
            'PACKAGE': 'PACKAGE',
            'TRIGGER': 'TRIGGER',
            'SYNONYM': 'SYNONYM',
            'SEQUENCE': 'SEQUENCE',
            'DATABASE': 'DATABASE_LINK',
            'INDEX': 'INDEX',
            'TYPE': 'TYPE'
        }
        
        # Statistics
        self.stats = {
            'folders_created': 0,
            'files_created': 0,
            'resources_created': 0,
            'duplicates_found': 0,
            'errors': 0
        }
        
        # Track resources to detect duplicates
        # Key: (name, type) -> List of (schema, package_name, file_path)
        self.resource_registry: Dict[Tuple[str, str], List[Tuple[Optional[str], Optional[str], str]]] = {}
        
        # Directories to skip during scanning (from config)
        self.skip_dirs: Set[str] = set(self.config.get('skip_directories', []))
        self.skip_files: List[str] = self.config.get('skip_files', [])

        # Track created nodes to prevent duplicates
        self.created_nodes: Set[str] = set()
        
        # Collected resources for bulk creation (performance optimization)
        self.collected_resources: List[Dict] = []
    
    def _to_relative_path(self, abs_path: Path) -> str:
        """Convert absolute path to repo-relative graph path."""
        return to_relative_path(
            abs_path,
            self.config.get('repositories', []),
            self.config.get('root_directory', '')
        )
    
    def scan_db_repositories(self):
        """
        Main entry point: Scan all db_repo type repositories.
        Creates complete folder/file tree structure and processes all .sql files.
        """
        logger.info("\n" + "=" * 80)
        logger.info("DB REPOSITORY SCANNING")
        logger.info("=" * 80)
        
        # Get db_repo type repositories
        db_repos = [r for r in self.config.get('repositories', []) if r.get('type') == 'db_repo']
        
        if not db_repos:
            logger.info("  No db_repo repositories found. Skipping DB repository scanning.")
            return
        
        logger.info(f"  Found {len(db_repos)} database repositories to scan\n")
        
        # Use single session for entire scan
        with self.driver.session(database=self.database) as session:
            for repo in db_repos:
                repo_name = repo.get('name')
                repo_path = repo.get('path')
                
                logger.info(f"  Scanning DB Repository: {repo_name}")
                logger.info(f"  Path: {repo_path}")
                
                if not os.path.exists(repo_path):
                    logger.warning(f"    Repository path not found: {repo_path}")
                    self.stats['errors'] += 1
                    continue
                
                # Create complete tree structure for db_repo
                self._scan_db_repo_tree(repo_path, repo_name, session)
        
        # Bulk create all collected resources (performance optimization)
        logger.info(f"\n  Bulk creating {len(self.collected_resources)} resources...")
        self._bulk_create_resources()
        
        # After scanning all repos, mark duplicates
        self._mark_duplicate_resources()
        
        # Print statistics
        self._print_statistics()
    
    def _scan_db_repo_tree(self, repo_path: str, repo_name: str, session):
        """
        Scan db_repo and create complete folder/file tree structure.
        Similar to shot1_create_tree in information_graph_builder.
        
        Args:
            repo_path: Path to the db repository
            repo_name: Name of the repository
            session: Neo4j session to reuse
        """
        repo_path_obj = Path(repo_path)
        repo_abs_str = str(repo_path_obj.absolute())
        repo_rel_str = self._to_relative_path(repo_path_obj)
        
        # Get git metadata from config for this repo
        repo_cfg = next(
            (r for r in self.config.get('repositories', []) if r['name'] == repo_name),
            {}
        )
        
        # Ensure Repository node exists (will be used as parent for children)
        logger.info(f"    Building tree structure for db_repo")
        
        query = """
        MERGE (n:Node:Repository {path: $path})
        ON CREATE SET 
            n.name = $name,
            n.node_type = 'Repository',
            n.repoName = $repoName,
            n.repoUrl = $repoUrl,
            n.branchName = $branchName,
            n.repoType = $repoType,
            n.created_at = datetime()
        SET n.repoUrl = $repoUrl, n.branchName = $branchName
        RETURN n
        """
        
        try:
            session.run(query,
                path=repo_rel_str,
                name=repo_path_obj.name,
                repoName=repo_cfg.get('name', repo_name),
                repoUrl=repo_cfg.get('repo_url', ''),
                branchName=repo_cfg.get('branch_name', ''),
                repoType=repo_cfg.get('type', 'db_repo')
            )
            self.created_nodes.add(repo_rel_str)
            logger.info(f"      Repository node ensured: {repo_name}")
        except Exception as e:
            logger.warning(f"      Failed to create Repository node: {e}")
            return
        
        # Recursively scan and create tree
        self._scan_recursive(repo_path_obj, repo_rel_str, repo_name, session, depth=0)
    
    def _scan_recursive(self, current_path: Path, parent_path_str: str, repo_name: str, session, depth: int = 0):
        """
        Recursively scan directory and create folder/file nodes.
        
        Args:
            current_path: Current directory path
            parent_path_str: Parent node path in graph
            repo_name: Repository name
            session: Neo4j session
            depth: Current recursion depth
        """
        max_depth = 50  # Reasonable depth limit
        
        if depth > max_depth:
            return
        
        try:
            items = list(current_path.iterdir())
        except (PermissionError, OSError) as e:
            logger.warning(f"      Cannot access {current_path}: {e}")
            return
        
        for item in items:
            item_abs_str = str(item.absolute())
            item_rel_str = self._to_relative_path(item)
            
            # Skip if already created
            if item_rel_str in self.created_nodes:
                continue
            
            # Skip ignored directories
            if item.is_dir() and item.name in self.skip_dirs:
                continue

            # Skip ignored files
            if item.is_file() and self._should_skip_file(item):
                continue

            if item.is_file():
                # Create file node
                self._create_file_node(item, parent_path_str, repo_name, session)
                self.stats['files_created'] += 1
                
                # If it's a .sql file, parse and create Resources
                if item.suffix.lower() == '.sql':
                    self._parse_and_create_resources(item, repo_name, session)
            else:
                # Create folder node
                self._create_folder_node(item, parent_path_str, session)
                self.stats['folders_created'] += 1
                
                # Recurse into subfolder using relative path as parent
                self._scan_recursive(item, item_rel_str, repo_name, session, depth + 1)
            
            # Mark as created (using relative path)
            self.created_nodes.add(item_rel_str)
    
    def _create_folder_node(self, folder_path: Path, parent_path: str, session):
        """
        Create a folder node in the graph.
        
        Args:
            folder_path: Path to folder
            parent_path: Parent node path
            session: Neo4j session
        """
        path_str = self._to_relative_path(folder_path)

        folder_node = IGFolderNodeDef(
            path=path_str,
            name=folder_path.name,
            node_type='Folder'
        )

        query = """
        MERGE (n:Node:Folder {path: $path})
        ON CREATE SET 
            n.name = $name,
            n.node_type = $node_type,
            n.created_at = datetime()
        WITH n
        MATCH (parent:Node {path: $parent_path})
        MERGE (parent)-[:CONTAINS]->(n)
        RETURN n
        """
        
        try:
            session.run(query,
                path=folder_node.path,
                name=folder_node.name,
                node_type=folder_node.node_type,
                parent_path=parent_path
            )
        except Exception as e:
            logger.warning(f"      Failed to create folder node {folder_path.name}: {e}")
            self.stats['errors'] += 1
    
    def _create_file_node(self, file_path: Path, parent_path: str, repo_name: str, session):
        """
        Create a file node in the graph.
        
        Args:
            file_path: Path to file
            parent_path: Parent node path
            repo_name: Repository name
            session: Neo4j session
        """
        path_str = self._to_relative_path(file_path)
        
        try:
            file_size = file_path.stat().st_size
        except:
            file_size = 0
        
        file_node = IGFileNodeDef(
            path=path_str,
            name=file_path.name,
            node_type='File',
            extension=file_path.suffix,
            size=file_size
        )

        query = """
        MERGE (n:Node:File {path: $path})
        ON CREATE SET 
            n.name = $name,
            n.node_type = $node_type,
            n.extension = $extension,
            n.size = $size,
            n.created_at = datetime()
        WITH n
        MATCH (parent:Node {path: $parent_path})
        MERGE (parent)-[:CONTAINS]->(n)
        RETURN n
        """
        
        try:
            session.run(query,
                path=file_node.path,
                name=file_node.name,
                node_type=file_node.node_type,
                extension=file_node.extension,
                size=file_node.size,
                parent_path=parent_path
            )
        except Exception as e:
            logger.warning(f"      Failed to create file node {file_path.name}: {e}")
            self.stats['errors'] += 1
    
    def _should_skip_file(self, file_path: Path) -> bool:
        """Check if file should be skipped based on skip_files configuration."""
        import fnmatch
        file_name = file_path.name
        for skip_pattern in self.skip_files:
            if skip_pattern == file_name:
                return True
            if '*' in skip_pattern and fnmatch.fnmatch(file_name, skip_pattern):
                return True
        return False

    def _split_create_statements(self, sql_content: str) -> List[str]:
        """
        Split SQL content into individual CREATE statements to avoid sqlparse token limits.
        Uses regex to find CREATE statement boundaries.
        
        Args:
            sql_content: Full SQL file content
        
        Returns:
            List of individual CREATE statements
        """
        # Pattern to match CREATE statements (including OR REPLACE)
        # Matches: CREATE, CREATE OR REPLACE, CREATE PUBLIC, etc.
        create_pattern = r'(CREATE\s+(?:OR\s+REPLACE\s+)?(?:PUBLIC\s+)?(?:PACKAGE\s+BODY|DATABASE\s+LINK|TABLE|VIEW|PROCEDURE|FUNCTION|PACKAGE|TRIGGER|SYNONYM|SEQUENCE|INDEX|TYPE)\s+)'
        
        # Find all CREATE statement positions
        matches = list(re.finditer(create_pattern, sql_content, re.IGNORECASE))
        
        if not matches:
            # No CREATE statements found, return original content
            return [sql_content]
        
        statements = []
        for i, match in enumerate(matches):
            start_pos = match.start()
            # End position is either the start of next CREATE or end of file
            end_pos = matches[i + 1].start() if i + 1 < len(matches) else len(sql_content)
            
            statement = sql_content[start_pos:end_pos].strip()
            if statement:
                statements.append(statement)
        
        return statements
    
    def _parse_and_create_resources(self, sql_file: Path, repo_name: str, session):
        """
        Parse SQL file content and create Resource nodes for each CREATE statement found.
        One SQL file can contain multiple CREATE statements.
        
        Args:
            sql_file: Path to SQL file
            repo_name: Repository name
            session: Neo4j session
        """
        file_name = sql_file.name
        file_path_str = self._to_relative_path(sql_file)

        # Look up branch name for git metadata
        repo_cfg = next(
            (r for r in self.config.get('repositories', []) if r.get('name') == repo_name),
            {}
        )
        branch_name = repo_cfg.get('branch_name', '')
        
        # Read file content
        try:
            with open(sql_file, 'r', encoding='utf-8', errors='ignore') as f:
                sql_content = f.read()
        except Exception as e:
            logger.debug(f"        Failed to read {file_name}: {e}")
            return
        
        if not sql_content.strip():
            return
        
        logger.debug(f"        Parsing SQL file: {file_name}")
        # Split large SQL files into individual CREATE statements to avoid sqlparse token limits
        # Use regex to find CREATE statement boundaries
        create_statements = self._split_create_statements(sql_content)
        
        # Parse each CREATE statement individually
        statements = []
        for create_stmt in create_statements:
            try:
                parsed = sqlparse.parse(create_stmt)
                statements.extend(parsed)
            except Exception as e:
                logger.debug(f"        Failed to parse statement in {file_name}: {e}")
                continue
        
        resources_found = 0
        for statement in statements:
            # Extract CREATE statement details
            resource_info = self._extract_create_info(statement, sql_content)
            
            if resource_info:
                schema_name = resource_info['schema']
                object_name = resource_info['name']
                resource_type = resource_info['type']
                package_name = resource_info.get('package')
                
                # Register resource (for duplicate detection)
                resource_key = (object_name.upper(), resource_type)
                if resource_key not in self.resource_registry:
                    self.resource_registry[resource_key] = []
                
                self.resource_registry[resource_key].append((
                    schema_name.upper() if schema_name else None,
                    package_name.upper() if package_name else None,
                    file_path_str
                ))
                
                # Collect resource for bulk creation (instead of creating one by one)
                unique_id = f"RES_{resource_type}_{uuid.uuid4().hex[:8].upper()}"
                res_node = ResourceNodeDef(
                    id=unique_id,
                    name=object_name.upper(),
                    type=resource_type,
                    schemaName=schema_name.upper() if schema_name else 'UNKNOWN',
                    packageName=package_name.upper() if package_name else '',
                    foundInRepo=True,
                    repoName=repo_name,
                    repoFilePath=file_path_str,
                    enabled=True
                )
                resource_data = {
                    'id': res_node.id,
                    'name': res_node.name,
                    'type': res_node.type,
                    'schemaName': res_node.schemaName,
                    'packageName': res_node.packageName,
                    'repoFilePath': res_node.repoFilePath,
                    'repoName': res_node.repoName,
                    'gitBranchName': branch_name,
                }
                self.collected_resources.append(resource_data)
                resources_found += 1
        
        if resources_found > 0:
            logger.debug(f"        Parsed {file_name}: {resources_found} resource(s)")
    
    def _extract_create_info(self, statement, full_sql: str) -> Optional[Dict[str, str]]:
        """
        Extract CREATE statement information (type, schema, name, package).
        
        Args:
            statement: Parsed SQL statement
            full_sql: Full SQL content for context
        
        Returns:
            Dict with keys: type, schema, name, package (or None if not a CREATE)
        """
        statement_str = str(statement).strip().upper()
        
        # Check if this is a CREATE statement
        if not statement_str.startswith('CREATE'):
            return None
        
        # Extract CREATE <TYPE> <NAME>
        # Patterns:
        #   CREATE TABLE schema.table_name
        #   CREATE OR REPLACE PROCEDURE schema.proc_name
        #   CREATE PACKAGE schema.package_name
        #   CREATE PACKAGE BODY schema.package_name
        #   CREATE OR REPLACE PACKAGE BODY schema.pkg.proc_name
        
        # Remove CREATE and OR REPLACE
        working_str = statement_str.replace('CREATE OR REPLACE', 'CREATE')
        working_str = working_str.replace('CREATE', '').strip()
        
        # Extract type (first word or multi-word types)
        parts = working_str.split()
        if len(parts) < 2:
            return None
        
        # Handle multi-word types: PACKAGE BODY, DATABASE LINK, PUBLIC DATABASE LINK
        if parts[0] == 'PACKAGE' and len(parts) > 1 and parts[1] == 'BODY':
            resource_type = 'PACKAGE'
            name_part = ' '.join(parts[2:]).split('(')[0].split()[0]  # Get first identifier after BODY
        elif parts[0] == 'PUBLIC' and len(parts) > 2 and parts[1] == 'DATABASE' and parts[2] == 'LINK':
            # PUBLIC DATABASE LINK link_name
            resource_type = 'DATABASE_LINK'
            name_part = ' '.join(parts[3:]).split('(')[0].split()[0] if len(parts) > 3 else None
        elif parts[0] == 'DATABASE' and len(parts) > 1 and parts[1] == 'LINK':
            # DATABASE LINK link_name
            resource_type = 'DATABASE_LINK'
            name_part = ' '.join(parts[2:]).split('(')[0].split()[0] if len(parts) > 2 else None
        else:
            type_word = parts[0]
            resource_type = self.create_type_mapping.get(type_word)
            if not resource_type:
                logger.debug(f"        Unknown CREATE type: {type_word}")
                return None
            
            name_part = ' '.join(parts[1:]).split('(')[0].split()[0]  # Get first identifier, stop at (
        
        # Parse schema.name or schema.package.procedure
        name_parts = name_part.split('.')
        
        schema_name = None
        object_name = None
        package_name = None
        
        if len(name_parts) == 1:
            # Just object name
            object_name = name_parts[0]
        elif len(name_parts) == 2:
            # schema.object
            schema_name = name_parts[0]
            object_name = name_parts[1]
        elif len(name_parts) >= 3:
            # schema.package.procedure
            schema_name = name_parts[0]
            package_name = name_parts[1]
            object_name = name_parts[2]
        
        return {
            'type': resource_type,
            'schema': schema_name,
            'name': object_name,
            'package': package_name
        }
    
    def _bulk_create_resources(self):
        """
        Bulk create all collected resources using UNWIND for maximum performance.
        This replaces individual queries (17K queries -> ~10 bulk operations).
        Reduces Phase 0 time from 50+ minutes to ~2-5 minutes.
        """
        if not self.collected_resources:
            logger.info("    No resources to create")
            return
        
        batch_size = 1000  # Process 1000 resources per batch
        total_resources = len(self.collected_resources)
        num_batches = (total_resources + batch_size - 1) // batch_size
        
        logger.info(f"    Creating {total_resources} resources in {num_batches} batches...")
        
        with self.driver.session(database=self.database) as session:
            for i in range(0, total_resources, batch_size):
                batch = self.collected_resources[i:i + batch_size]
                batch_num = i // batch_size + 1
                
                try:
                    # Separate resources with and without packages for different queries
                    resources_with_package = [r for r in batch if r['packageName']]
                    resources_without_package = [r for r in batch if not r['packageName']]
                    
                    # Bulk create resources WITH package
                    if resources_with_package:
                        query_with_pkg = """
                        UNWIND $resources AS res
                        MERGE (r:Resource {name: res.name, type: res.type, schemaName: res.schemaName, packageName: res.packageName})
                        ON CREATE SET r.id = res.id,
                                      r.enabled = true,
                                      r.foundInRepo = true,
                                      r.repoName = res.repoName,
                                      r.repoFilePath = res.repoFilePath,
                                      r.gitRepoName = res.repoName,
                                      r.gitBranchName = res.gitBranchName,
                                      r.gitFileExists = true,
                                      r.created_at = datetime()
                        ON MATCH SET r.foundInRepo = true,
                                     r.repoName = COALESCE(r.repoName, res.repoName),
                                     r.repoFilePath = COALESCE(r.repoFilePath, res.repoFilePath)
                        WITH r, res
                        MATCH (f:File {path: res.repoFilePath})
                        MERGE (f)-[rel:DB_OPERATION]->(r)
                        ON CREATE SET rel.operationType = 'CREATE',
                                      rel.statementType = res.type
                        RETURN count(r) as cnt
                        """
                        result = session.run(query_with_pkg, resources=resources_with_package)
                        count = result.single()['cnt']
                        self.stats['resources_created'] += count
                    
                    # Bulk create resources WITHOUT package
                    if resources_without_package:
                        query_without_pkg = """
                        UNWIND $resources AS res
                        MERGE (r:Resource {name: res.name, type: res.type, schemaName: res.schemaName})
                        ON CREATE SET r.id = res.id,
                                      r.enabled = true,
                                      r.foundInRepo = true,
                                      r.repoName = res.repoName,
                                      r.repoFilePath = res.repoFilePath,
                                      r.packageName = null,
                                      r.gitRepoName = res.repoName,
                                      r.gitBranchName = res.gitBranchName,
                                      r.gitFileExists = true,
                                      r.created_at = datetime()
                        ON MATCH SET r.foundInRepo = true,
                                     r.repoName = COALESCE(r.repoName, res.repoName),
                                     r.repoFilePath = COALESCE(r.repoFilePath, res.repoFilePath)
                        WITH r, res
                        MATCH (f:File {path: res.repoFilePath})
                        MERGE (f)-[rel:DB_OPERATION]->(r)
                        ON CREATE SET rel.operationType = 'CREATE',
                                      rel.statementType = res.type
                        RETURN count(r) as cnt
                        """
                        result = session.run(query_without_pkg, resources=resources_without_package)
                        count = result.single()['cnt']
                        self.stats['resources_created'] += count
                    
                    logger.info(f"      Batch {batch_num}/{num_batches}: Created {len(batch)} resources")
                    
                except Exception as e:
                    logger.error(f"      Batch {batch_num} failed: {str(e)[:200]}")
                    self.stats['errors'] += len(batch)
        
        logger.info(f"    Bulk creation complete: {self.stats['resources_created']} resources created")
    
    def _mark_duplicate_resources(self):
        """
        Mark resources that have duplicates (same name/type but different schema/package).
        Uses parameterized queries to avoid token limit issues.
        """
        logger.info("\n  Checking for duplicate resources...")
        
        duplicates_marked = 0
        
        with self.driver.session(database=self.database) as session:
            for (name, resource_type), instances in self.resource_registry.items():
                if len(instances) <= 1:
                    continue
                
                # Group by schema and package to find exact duplicates
                schema_package_groups = {}
                for schema, package, file_path in instances:
                    key = (schema, package)
                    if key not in schema_package_groups:
                        schema_package_groups[key] = []
                    schema_package_groups[key].append(file_path)
                
                # Mark resources with same schema/package as duplicates
                for (schema, package), file_paths in schema_package_groups.items():
                    if len(file_paths) > 1:
                        # True duplicate - same name, type, schema, and package
                        if package:
                            query = """
                            MATCH (r:Resource {name: $name, type: $type, schemaName: $schema, packageName: $package})
                            SET r.duplicateFound = true
                            RETURN count(r) as cnt
                            """
                            params = {
                                'name': name,
                                'type': resource_type,
                                'schema': schema,
                                'package': package
                            }
                        else:
                            query = """
                            MATCH (r:Resource {name: $name, type: $type, schemaName: $schema})
                            WHERE r.packageName IS NULL
                            SET r.duplicateFound = true
                            RETURN count(r) as cnt
                            """
                            params = {
                                'name': name,
                                'type': resource_type,
                                'schema': schema
                            }
                        
                        result = session.run(query, **params)
                        record = result.single()
                        if record:
                            count = record['cnt']
                            duplicates_marked += count
                            self.stats['duplicates_found'] += count
                            logger.warning(f"    Duplicate found: {name} ({resource_type}) in schema {schema}" + 
                                         (f", package {package}" if package else ""))
        
        if duplicates_marked > 0:
            logger.info(f"  Marked {duplicates_marked} duplicate resources")
        else:
            logger.info(f"  No duplicate resources found")
    
    def _print_statistics(self):
        """Print scanning statistics."""
        logger.info("\n" + "=" * 80)
        logger.info("DB REPOSITORY SCANNING COMPLETE")
        logger.info("=" * 80)
        logger.info(f"  Folders Created:       {self.stats['folders_created']}")
        logger.info(f"  Files Created:         {self.stats['files_created']}")
        logger.info(f"  Resources Created:     {self.stats['resources_created']}")
        logger.info(f"  Duplicates Found:      {self.stats['duplicates_found']}")
        logger.info(f"  Errors:                {self.stats['errors']}")
        logger.info("=" * 80 + "\n")
