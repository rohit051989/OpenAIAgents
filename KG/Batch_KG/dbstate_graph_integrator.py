"""
DB State Graph Integrator
=========================
This module integrates data from an external dbstategraph into the existing KG.

Three-Part Architecture:
------------------------
Part 1: SCAN - Scan the KG to find Resource nodes (SQL files, procedures)
Part 2: QUERY - Run configurable Cypher queries against dbstategraph for each resource
Part 3: STORE - Orchestrate and store the response in our KG (placeholder for future)

The dbstategraph contains detailed information about what is happening in:
- SQL files (statements, operations)
- Stored procedures (logic, table access)
- Database objects (tables, views, etc.)

This enriches our KG with deeper understanding of what Resources are actually doing.

Configuration:
- All configuration is loaded from config/dbstate_graph_config.yaml
- Queries are configurable in that file (no hardcoded defaults)

Author: Rohit Khanna
Date: 2026-08-24
"""

import os
import yaml
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from neo4j import GraphDatabase
from dotenv import load_dotenv
from classes.log_utils import setup_logging

logger = setup_logging(__file__)

# Default path for dbstate graph config file
DEFAULT_DBSTATE_CONFIG_PATH = "config/dbstate_graph_config.yaml"


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class ResourceInfo:
    """Information about a Resource found in the KG."""
    name: str
    resource_type: str          # PROCEDURE, FUNCTION, SQL_SCRIPT
    schema_name: str = ""
    package_name: str = ""
    path: str = ""
    extension: str = ""
    repo_name: str = ""
    repo_file_path: str = ""


@dataclass
class DBStateQueryResult:
    """Result from querying the dbstategraph for a resource."""
    resource_name: str
    resource_type: str
    found: bool = False
    query_success: bool = False
    error_message: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    raw_records: List[Dict[str, Any]] = field(default_factory=list)


# =============================================================================
# MAIN INTEGRATOR CLASS
# =============================================================================

class DBStateGraphIntegrator:
    """
    Integrates dbstategraph data into the existing Knowledge Graph.
    
    Usage:
        integrator = DBStateGraphIntegrator(kg_config_path="config/information_graph_config.yaml")
        integrator.run()
        integrator.close()
    """
    
    def __init__(self, kg_config_path: str = None, dbstate_config_path: str = None):
        """
        Initialize the integrator.
        
        Args:
            kg_config_path: Path to main KG YAML config file (for Neo4j connection)
            dbstate_config_path: Path to dbstate graph config file (default: config/dbstate_graph_config.yaml)
        """
        load_dotenv()
        
        # Load main KG configuration (for Neo4j connection)
        if kg_config_path:
            with open(kg_config_path, 'r', encoding='utf-8') as f:
                self.kg_config = yaml.safe_load(f)
            logger.info(f"Loaded KG configuration from {kg_config_path}")
        else:
            kg_config_path = os.getenv("KG_CONFIG_FILE")
            if kg_config_path:
                with open(kg_config_path, 'r', encoding='utf-8') as f:
                    self.kg_config = yaml.safe_load(f)
                logger.info(f"Loaded KG configuration from env KG_CONFIG_FILE: {kg_config_path}")
            else:
                raise ValueError("No KG configuration provided. Set KG_CONFIG_FILE env var or pass kg_config_path.")
        
        # Load dbstate configuration from dedicated config file
        self.dbstate_config = self._load_dbstate_config(dbstate_config_path)
        
        # Neo4j connection setup
        neo4j_config = self.kg_config['neo4j']
        self.driver = GraphDatabase.driver(
            neo4j_config['uri'],
            auth=(neo4j_config['user'], neo4j_config['password'])
        )
        
        # Database names
        self.kg_database = neo4j_config.get('database_kg', 'knowledgegraph')
        self.ig_database = neo4j_config.get('database_ig', 'informationgraph')
        self.dbstate_database = self.dbstate_config.get('dbstate_database', 'dbstategraph')
        
        logger.info(f"DBStateGraphIntegrator initialized")
        logger.info(f"  KG Database: {self.kg_database}")
        logger.info(f"  IG Database: {self.ig_database}")
        logger.info(f"  DBState Database: {self.dbstate_database}")
    
    def _load_dbstate_config(self, config_path: str = None) -> Dict:
        """
        Load dbstategraph configuration from dedicated config file.
        
        Args:
            config_path: Path to dbstate config file. If None, uses:
                         1. Path from main config's dbstate_graph.config_file
                         2. Default: config/dbstate_graph_config.yaml
        
        Returns:
            Configuration dictionary
            
        Raises:
            FileNotFoundError: If config file doesn't exist
            ValueError: If required config (queries) is missing
        """
        # Determine config file path
        if not config_path:
            # Try to get from main config
            dbstate_section = self.kg_config.get('dbstate_graph', {})
            config_path = dbstate_section.get('config_file', DEFAULT_DBSTATE_CONFIG_PATH)
        
        # Load the config file
        if not os.path.exists(config_path):
            raise FileNotFoundError(
                f"DBState config file not found: {config_path}\n"
                f"Please create the config file or update the path in information_graph_config.yaml"
            )
        
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        
        logger.info(f"Loaded DBState configuration from {config_path}")
        
        # Validate required configuration
        if 'queries' not in config:
            raise ValueError(
                f"Missing 'queries' section in {config_path}. "
                "Please define 'procedure' and 'sql_file' query templates."
            )
        
        if 'procedure' not in config['queries'] and 'sql_file' not in config['queries']:
            raise ValueError(
                f"No query templates defined in {config_path}. "
                "Please define at least one of: 'procedure', 'sql_file' in the 'queries' section."
            )
        
        return config
    
    def close(self):
        """Close Neo4j connection."""
        if self.driver:
            self.driver.close()
            logger.info("Neo4j connection closed")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    # =========================================================================
    # PART 1: SCAN KG FOR RESOURCES
    # =========================================================================
    
    def scan_kg_for_resources(self) -> Tuple[List[ResourceInfo], List[ResourceInfo]]:
        """
        Part 1: Scan the Knowledge Graph to find SQL files and procedure resources.
        
        Returns:
            Tuple of (procedure_resources, sql_file_resources)
        """
        logger.info("=" * 80)
        logger.info("PART 1: Scanning KG for SQL Files and Procedure Resources")
        logger.info("=" * 80)
        
        procedures: List[ResourceInfo] = []
        sql_files: List[ResourceInfo] = []
        
        # Query for PROCEDURE/FUNCTION resources
        procedure_query = """
            MATCH (r:Resource)
            WHERE r.type IN ['PROCEDURE']
            RETURN r.name AS name,
                   r.type AS type,
                   coalesce(r.schemaName, '') AS schemaName,
                   coalesce(r.packageName, '') AS packageName,
                   coalesce(r.path, '') AS path,
                   coalesce(r.extension, '') AS extension,
                   coalesce(r.repoName, '') AS repoName,
                   coalesce(r.repoFilePath, '') AS repoFilePath
        """
        
        # Query for SQL_SCRIPT resources (by type or extension)
        sql_query = """
            MATCH (r:Resource)
            WHERE r.type = 'SQL_SCRIPT' 
               OR r.extension IN ['.sql', '.ddl']
            RETURN r.name AS name,
                   coalesce(r.type, 'SQL_FILE') AS type,
                   coalesce(r.schemaName, '') AS schemaName,
                   coalesce(r.packageName, '') AS packageName,
                   coalesce(r.path, '') AS path,
                   coalesce(r.extension, '') AS extension,
                   coalesce(r.repoName, '') AS repoName,
                   coalesce(r.repoFilePath, '') AS repoFilePath
        """
        
        # Execute queries against KG
        target_database = self.kg_database  # or self.ig_database depending on where Resource nodes are stored
        
        try:
            with self.driver.session(database=target_database) as session:
                # Scan for procedures
                logger.info(f"  Scanning for PROCEDURE/FUNCTION resources in {target_database}...")
                result = session.run(procedure_query)
                for record in result:
                    procedures.append(ResourceInfo(
                        name=record['name'],
                        resource_type=record['type'],
                        schema_name=record['schemaName'],
                        package_name=record['packageName'],
                        path=record['path'],
                        extension=record['extension'],
                        repo_name=record['repoName'],
                        repo_file_path=record['repoFilePath']
                    ))
                
                # Scan for SQL files
                logger.info(f"  Scanning for SQL file resources in {target_database}...")
                result = session.run(sql_query)
                for record in result:
                    sql_files.append(ResourceInfo(
                        name=record['name'],
                        resource_type=record['type'],
                        schema_name=record['schemaName'],
                        package_name=record['packageName'],
                        path=record['path'],
                        extension=record['extension'],
                        repo_name=record['repoName'],
                        repo_file_path=record['repoFilePath']
                    ))
                
        except Exception as e:
            logger.error(f"Error scanning KG for resources: {e}")
            raise
        
        logger.info(f"  Found {len(procedures)} PROCEDURE/FUNCTION resources")
        logger.info(f"  Found {len(sql_files)} SQL file resources")
        logger.info("")
        
        return procedures, sql_files
    
    # =========================================================================
    # PART 2: QUERY DBSTATEGRAPH
    # =========================================================================
    
    def query_dbstategraph_for_resource(self, resource: ResourceInfo) -> DBStateQueryResult:
        """
        Query the dbstategraph for a single resource.
        
        Args:
            resource: ResourceInfo object representing the resource to query
            
        Returns:
            DBStateQueryResult with query results or error information
        """
        result = DBStateQueryResult(
            resource_name=resource.name,
            resource_type=resource.resource_type
        )
        
        # Determine query type and get query template
        if resource.resource_type in ['PROCEDURE']:
            query_template = self.dbstate_config['queries'].get('procedure')
            query_type = 'procedure'
        else:  # SQL_SCRIPT, SQL_FILE, or files with .sql/.ddl extension
            query_template = self.dbstate_config['queries'].get('sql_file')
            query_type = 'sql_file'
        
        if not query_template:
            result.error_message = f"No query template configured for type: {query_type}"
            logger.warning(f"  ⚠️  {result.error_message}")
            return result
        
        # Build query parameters
        params = self._build_query_params(resource, query_type)
        
        # Execute query against dbstategraph
        try:
            with self.driver.session(database=self.dbstate_database) as session:
                query_result = session.run(query_template, params)
                records = list(query_result)
                
                if records:
                    result.found = True
                    result.query_success = True
                    result.raw_records = [dict(record) for record in records]
                    
                    # Aggregate data from all records
                    result.data = self._aggregate_query_results(records, query_type)
                    
                    logger.debug(f"  ✓ Found data for {resource.name} in dbstategraph")
                else:
                    result.found = False
                    result.query_success = True
                    error_handling = self.dbstate_config.get('error_handling', {})
                    if error_handling.get('log_not_found_as_warning', True):
                        logger.warning(f"  ⚠️  Resource '{resource.name}' not found in dbstategraph")
                    else:
                        logger.error(f"  ✗ Resource '{resource.name}' not found in dbstategraph")
                        
        except Exception as e:
            result.query_success = False
            result.error_message = str(e)
            logger.error(f"  ✗ Error querying dbstategraph for '{resource.name}': {e}")
            
            # Check if we should continue on error
            error_handling = self.dbstate_config.get('error_handling', {})
            if not error_handling.get('continue_on_query_error', True):
                raise
        
        return result
    
    def _build_query_params(self, resource: ResourceInfo, query_type: str) -> Dict[str, Any]:
        """Build query parameters based on resource and matching configuration."""
        params = {}
        matching_config = self.dbstate_config.get('matching', {})
        case_sensitive = matching_config.get('case_sensitive', False)
        
        # Get the name (handle case sensitivity)
        name = resource.name
        if not case_sensitive:
            # For case-insensitive, we might need to adjust query or use LOWER()
            # For now, pass as-is and rely on index/query design
            pass
        
        params['name'] = name
        
        # Add additional fields based on configuration
        if query_type == 'procedure':
            match_fields = matching_config.get('procedure_match_fields', ['name'])
            if 'schema' in match_fields and resource.schema_name:
                params['schema'] = resource.schema_name
            if 'package' in match_fields and resource.package_name:
                params['package'] = resource.package_name
        else:  # sql_file
            match_fields = matching_config.get('sql_file_match_fields', ['name'])
            if 'path' in match_fields and resource.path:
                params['path'] = resource.path
        
        return params
    
    def _aggregate_query_results(self, records: List, query_type: str) -> Dict[str, Any]:
        """Aggregate query results into a structured dictionary."""
        if not records:
            return {}
        
        # For single-record results, just return the first record
        if len(records) == 1:
            return dict(records[0])
        
        # For multiple records, aggregate (this depends on query structure)
        aggregated = {}
        for record in records:
            record_dict = dict(record)
            for key, value in record_dict.items():
                if key not in aggregated:
                    aggregated[key] = value
                elif isinstance(value, list):
                    if isinstance(aggregated[key], list):
                        aggregated[key].extend(value)
                    else:
                        aggregated[key] = [aggregated[key]] + value
        
        return aggregated
    
    def query_all_resources(
        self, 
        procedures: List[ResourceInfo], 
        sql_files: List[ResourceInfo]
    ) -> Dict[str, List[DBStateQueryResult]]:
        """
        Part 2: Query dbstategraph for all resources.
        
        Args:
            procedures: List of procedure resources to query
            sql_files: List of SQL file resources to query
            
        Returns:
            Dictionary with 'procedures' and 'sql_files' keys containing query results
        """
        logger.info("=" * 80)
        logger.info("PART 2: Querying DBStateGraph for Resource Details")
        logger.info("=" * 80)
        
        results = {
            'procedures': [],
            'sql_files': []
        }
        
        # Statistics
        stats = {
            'procedures_total': len(procedures),
            'procedures_found': 0,
            'procedures_not_found': 0,
            'procedures_error': 0,
            'sql_files_total': len(sql_files),
            'sql_files_found': 0,
            'sql_files_not_found': 0,
            'sql_files_error': 0
        }
        
        # Query procedures
        logger.info(f"  Querying {len(procedures)} procedure resources...")
        for i, proc in enumerate(procedures, 1):
            if i % 10 == 0 or i == len(procedures):
                logger.info(f"    Processing procedure {i}/{len(procedures)}: {proc.name}")
            
            result = self.query_dbstategraph_for_resource(proc)
            results['procedures'].append(result)
            
            if result.query_success:
                if result.found:
                    stats['procedures_found'] += 1
                else:
                    stats['procedures_not_found'] += 1
            else:
                stats['procedures_error'] += 1
        
        # Query SQL files
        logger.info(f"  Querying {len(sql_files)} SQL file resources...")
        for i, sql_file in enumerate(sql_files, 1):
            if i % 10 == 0 or i == len(sql_files):
                logger.info(f"    Processing SQL file {i}/{len(sql_files)}: {sql_file.name}")
            
            result = self.query_dbstategraph_for_resource(sql_file)
            results['sql_files'].append(result)
            
            if result.query_success:
                if result.found:
                    stats['sql_files_found'] += 1
                else:
                    stats['sql_files_not_found'] += 1
            else:
                stats['sql_files_error'] += 1
        
        # Log summary
        logger.info("")
        logger.info("  Query Results Summary:")
        logger.info(f"    Procedures: {stats['procedures_found']}/{stats['procedures_total']} found, "
                   f"{stats['procedures_not_found']} not found, {stats['procedures_error']} errors")
        logger.info(f"    SQL Files:  {stats['sql_files_found']}/{stats['sql_files_total']} found, "
                   f"{stats['sql_files_not_found']} not found, {stats['sql_files_error']} errors")
        logger.info("")
        
        return results
    
    # =========================================================================
    # PART 3: STORE IN KG (PLACEHOLDER)
    # =========================================================================
    
    def store_in_kg(self, query_results: Dict[str, List[DBStateQueryResult]]) -> Dict[str, Any]:
        """
        Part 3: Orchestrate and store the dbstategraph data in our KG.
        
        TODO: This is a placeholder. Implementation depends on the final KG data model.
        
        Current placeholder behavior:
        - Logs the results that would be stored
        - Returns summary statistics
        
        Future implementation should:
        - Create new nodes/relationships based on the data model
        - Update existing Resource nodes with enriched data
        - Create links to new entity types from dbstategraph
        
        Args:
            query_results: Dictionary containing procedure and SQL file query results
            
        Returns:
            Dictionary with storage statistics
        """
        logger.info("=" * 80)
        logger.info("PART 3: Storing DBStateGraph Data in KG (PLACEHOLDER)")
        logger.info("=" * 80)
        
        # Statistics for what would be stored
        stats = {
            'procedures_to_enrich': 0,
            'sql_files_to_enrich': 0,
            'total_tables_referenced': set(),
            'total_statements_found': 0,
            'skipped_not_found': 0,
            'skipped_error': 0
        }
        
        # Process procedure results
        logger.info("  Processing procedure results for storage...")
        for result in query_results.get('procedures', []):
            if not result.query_success or not result.found:
                if not result.found:
                    stats['skipped_not_found'] += 1
                else:
                    stats['skipped_error'] += 1
                continue
            
            stats['procedures_to_enrich'] += 1
            
            # Extract data that would be stored
            if result.data:
                tables = result.data.get('tables_accessed', [])
                if isinstance(tables, list):
                    stats['total_tables_referenced'].update(tables)
                
                statements = result.data.get('statements', [])
                if isinstance(statements, list):
                    stats['total_statements_found'] += len(statements)
            
            # TODO: Implement actual storage
            # Example Cypher that might be used:
            # MATCH (r:Resource {name: $name, type: 'PROCEDURE'})
            # SET r.tablesAccessed = $tables,
            #     r.dbstateEnriched = true,
            #     r.dbstateEnrichedAt = datetime()
            # WITH r
            # UNWIND $tables AS tableName
            # MERGE (t:Table {name: tableName})
            # MERGE (r)-[:ACCESSES]->(t)
        
        # Process SQL file results
        logger.info("  Processing SQL file results for storage...")
        for result in query_results.get('sql_files', []):
            if not result.query_success or not result.found:
                if not result.found:
                    stats['skipped_not_found'] += 1
                else:
                    stats['skipped_error'] += 1
                continue
            
            stats['sql_files_to_enrich'] += 1
            
            # Extract data that would be stored
            if result.data:
                statements = result.data.get('statements', [])
                if isinstance(statements, list):
                    stats['total_statements_found'] += len(statements)
                    # Extract table references from statements
                    for stmt in statements:
                        if isinstance(stmt, dict):
                            tables = stmt.get('tables', [])
                            if isinstance(tables, list):
                                stats['total_tables_referenced'].update(tables)
            
            # TODO: Implement actual storage
            # Similar pattern to procedures above
        
        # Convert set to count for JSON serialization
        stats['total_tables_referenced'] = len(stats['total_tables_referenced'])
        
        # Log placeholder summary
        logger.info("")
        logger.info("  PLACEHOLDER Storage Summary:")
        logger.info(f"    Procedures to enrich:    {stats['procedures_to_enrich']}")
        logger.info(f"    SQL files to enrich:     {stats['sql_files_to_enrich']}")
        logger.info(f"    Total tables referenced: {stats['total_tables_referenced']}")
        logger.info(f"    Total statements found:  {stats['total_statements_found']}")
        logger.info(f"    Skipped (not found):     {stats['skipped_not_found']}")
        logger.info(f"    Skipped (errors):        {stats['skipped_error']}")
        logger.info("")
        logger.info("  ⚠️  NOTE: Actual storage not implemented yet.")
        logger.info("       Data model design needed before implementation.")
        logger.info("")
        
        return stats
    
    # =========================================================================
    # MAIN EXECUTION
    # =========================================================================
    
    def run(self) -> Dict[str, Any]:
        """
        Execute the full integration pipeline.
        
        Returns:
            Dictionary containing:
            - scan_results: Count of resources found
            - query_results: Results from querying dbstategraph
            - storage_stats: Statistics from storage phase
            - timing: Execution time for each phase
        """
        logger.info("")
        logger.info("=" * 80)
        logger.info("DB STATE GRAPH INTEGRATION - STARTING")
        logger.info("=" * 80)
        logger.info("")
        
        overall_start = time.time()
        results = {
            'scan_results': {},
            'query_results': {},
            'storage_stats': {},
            'timing': {}
        }
        
        try:
            # Part 1: Scan KG
            part1_start = time.time()
            procedures, sql_files = self.scan_kg_for_resources()
            results['timing']['part1_scan_seconds'] = time.time() - part1_start
            results['scan_results'] = {
                'procedures_count': len(procedures),
                'sql_files_count': len(sql_files)
            }
            
            # Part 2: Query DBStateGraph
            part2_start = time.time()
            query_results = self.query_all_resources(procedures, sql_files)
            results['timing']['part2_query_seconds'] = time.time() - part2_start
            
            # Summarize query results (don't store full data in return)
            results['query_results'] = {
                'procedures_queried': len(query_results['procedures']),
                'procedures_found': sum(1 for r in query_results['procedures'] if r.found),
                'sql_files_queried': len(query_results['sql_files']),
                'sql_files_found': sum(1 for r in query_results['sql_files'] if r.found)
            }
            
            # Part 3: Store in KG (placeholder)
            part3_start = time.time()
            storage_stats = self.store_in_kg(query_results)
            results['timing']['part3_store_seconds'] = time.time() - part3_start
            results['storage_stats'] = storage_stats
            
        except Exception as e:
            logger.error(f"Error during integration: {e}")
            import traceback
            traceback.print_exc()
            raise
        
        # Final summary
        total_time = time.time() - overall_start
        results['timing']['total_seconds'] = total_time
        
        logger.info("=" * 80)
        logger.info("DB STATE GRAPH INTEGRATION - COMPLETED")
        logger.info("=" * 80)
        logger.info(f"  Total time: {total_time:.2f} seconds")
        logger.info("")
        
        return results


# =============================================================================
# STANDALONE EXECUTION
# =============================================================================

def main():
    """
    Standalone entry point — runs only the dbstate integration against an
    already-loaded KG.  This lets you enrich an existing KG without
    rebuilding it from scratch via neo4j_direct_class_loader_v4.py.

    Priority for config resolution:
      1. --kg-config CLI argument
      2. --dbstate-config CLI argument (for the dbstate query config)
      3. KG_CONFIG_FILE environment variable
    """
    import argparse
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="DB State Graph Integrator — enriches an existing KG with dbstategraph data.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Using environment variable (KG already loaded):
  python dbstate_graph_integrator.py

  # Explicit config paths:
  python dbstate_graph_integrator.py --kg-config config/information_graph_config.yaml

  # Override dbstate query config as well:
  python dbstate_graph_integrator.py --kg-config config/information_graph_config.yaml \\
                                     --dbstate-config config/dbstate_graph_config.yaml
        """,
    )
    parser.add_argument(
        "--kg-config",
        metavar="PATH",
        default=None,
        help="Path to main KG config YAML (falls back to KG_CONFIG_FILE env var)",
    )
    parser.add_argument(
        "--dbstate-config",
        metavar="PATH",
        default=None,
        help="Path to dbstate_graph_config.yaml (overrides the path in kg-config)",
    )
    args = parser.parse_args()

    kg_config_file = args.kg_config or os.getenv("KG_CONFIG_FILE")
    if not kg_config_file:
        parser.error(
            "No KG config supplied. Use --kg-config <path> or set KG_CONFIG_FILE."
        )

    logger.info("=" * 80)
    logger.info("DB State Graph Integrator - Standalone Execution")
    logger.info("=" * 80)
    logger.info(f"KG Config:      {kg_config_file}")
    if args.dbstate_config:
        logger.info(f"DBState Config: {args.dbstate_config}")
    logger.info("")

    try:
        with DBStateGraphIntegrator(
            kg_config_path=kg_config_file,
            dbstate_config_path=args.dbstate_config,
        ) as integrator:
            results = integrator.run()

            logger.info("")
            logger.info("Final Results:")
            logger.info(f"  Scan:  {results['scan_results']}")
            logger.info(f"  Query: {results['query_results']}")
            logger.info(f"  Store: {results['storage_stats']}")
            logger.info(f"  Time:  {results['timing']}")

    except Exception as e:
        logger.error(f"Integration failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
