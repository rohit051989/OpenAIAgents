"""
DB Operation Consistency Validator

Detects and repairs orphaned DB_OPERATION relationships in the Information Graph.

PROBLEM:
When db_operation_enricher.py runs multiple times or encounters partial failures,
JavaMethod nodes can end up with:
  - DB_OPERATION relationships to Table resources
  - BUT dbOperationCount = 0 or dbOperations = []

This causes the KG builder (_copy_step_db_operations_from_info_graph) to miss these
methods because it filters by: m.dbOperationCount > 0

ROOT CAUSE:
In db_operation_enricher.py, enrichment happens in two separate transactions:
1. _update_method_operations() -> sets count & array
2. _create_resource_relationships() -> creates relationships

If enricher runs on already-enriched method with NO NEW OPERATIONS FOUND:
- Properties get overwritten to count=0, array=[]
- Relationships are NOT deleted (early return in _create_resource_relationships)
- Result: orphaned relationships

SOLUTION:
1. Detect orphaned relationships
2. Log warnings about inconsistencies
3. Rebuild properties from actual relationships
4. Make KG builder query resilient (fallback to relationship check)
"""

import logging
from neo4j import GraphDatabase
from typing import Dict, List, Optional
import yaml
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - [%(pathname)s:%(lineno)d %(funcName)s] - %(message)s"
)
logger = logging.getLogger(__name__)


class DBOperationConsistencyValidator:
    """Validates and repairs DB operation consistency in Information Graph"""
    
    def __init__(self, config_path: str):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        neo4j_config = self.config['neo4j']
        self.driver = GraphDatabase.driver(
            neo4j_config['uri'],
            auth=(neo4j_config['user'], neo4j_config['password'])
        )
        self.database = neo4j_config.get('database_ig', 'informationgraph')
        
        self.stats = {
            'orphaned_methods': 0,
            'orphaned_relationships': 0,
            'rebuilt_methods': 0,
            'consistency_violations': 0
        }
    
    def validate_and_repair(self, repair: bool = True) -> Dict:
        """
        Validate DB operations consistency.
        
        Args:
            repair: If True, rebuild properties from relationships
        
        Returns:
            Dict with statistics about orphaned methods found and repaired
        """
        logger.info(" " + "=" * 80)
        logger.info("DB OPERATIONS CONSISTENCY VALIDATION")
        logger.info("=" * 80)
        
        # Step 1: Find orphaned relationships
        orphaned_methods = self._find_orphaned_relationships()
        
        if orphaned_methods:
            logger.warning(f"  ⚠️  Found {len(orphaned_methods)} methods with inconsistent DB operations")
            self._log_orphaned_methods(orphaned_methods)
            self.stats['consistency_violations'] = len(orphaned_methods)
            
            # Count total orphaned relationships
            total_orphaned_rels = sum(len(m['actualRels']) for m in orphaned_methods)
            self.stats['orphaned_relationships'] = total_orphaned_rels
            
            # Step 2: Optionally repair
            if repair:
                self._rebuild_properties_from_relationships(orphaned_methods)
        else:
            logger.info("  ✓ No consistency violations found")
        
        logger.info("=" * 80)
        return self.stats
    
    def _find_orphaned_relationships(self) -> List[Dict]:
        """
        Find methods with DB_OPERATION relationships but empty/zero count.
        
        Returns list of dicts with:
          - methodFqn
          - recordedCount
          - recordedOps (array stored on node)
          - actualRels (relationships that actually exist)
        """
        orphan_query = """
        MATCH (m:JavaMethod)-[rel:DB_OPERATION]->(r:Resource {type: 'TABLE'})
        WHERE (m.dbOperationCount = 0 OR m.dbOperationCount IS NULL OR 
               m.dbOperations IS NULL OR size(m.dbOperations) = 0)
        RETURN m.fqn as methodFqn,
               m.dbOperationCount as count,
               m.dbOperations as ops,
               collect(DISTINCT {
                   operationType: rel.operationType,
                   tableName: r.name,
                   confidence: rel.confidence
               }) as relOps
        ORDER BY m.fqn
        """
        
        orphaned_methods = []
        with self.driver.session(database=self.database) as session:
            result = session.run(orphan_query)
            for record in result:
                orphaned_methods.append({
                    'methodFqn': record['methodFqn'],
                    'recordedCount': record['count'] or 0,
                    'recordedOps': record['ops'] or [],
                    'actualRels': record['relOps'] or []
                })
        
        self.stats['orphaned_methods'] = len(orphaned_methods)
        return orphaned_methods
    
    def _log_orphaned_methods(self, orphaned_methods: List[Dict]) -> None:
        """Log detailed information about orphaned methods"""
        for method in orphaned_methods:
            rel_count = len(method['actualRels'])
            logger.warning(
                f"  ⚠️  {method['methodFqn']}: "
                f"recorded_count={method['recordedCount']}, "
                f"actual_relationships={rel_count}"
            )
            for rel in method['actualRels']:
                logger.warning(
                    f"      → {rel['operationType']} on {rel['tableName']} "
                    f"(confidence: {rel['confidence']})"
                )
    
    def _rebuild_properties_from_relationships(self, orphaned_methods: List[Dict]) -> None:
        """
        Rebuild dbOperationCount and dbOperations from actual relationships.
        
        This sets:
        - dbOperationCount = number of DB_OPERATION relationships
        - dbOperations = array of "OPERATION:TABLE:CONFIDENCE" strings
        """
        logger.info("  Rebuilding dbOperations properties from relationships...")
        
        rebuild_query = """
        MATCH (m:JavaMethod)-[rel:DB_OPERATION]->(r:Resource {type: 'TABLE'})
        WHERE m.fqn IN $methodFqns
        WITH m, collect(DISTINCT {
            operationType: rel.operationType,
            tableName: r.name,
            confidence: rel.confidence
        }) as relOps
        WITH m, relOps,
             [op IN relOps | op.operationType + ':' + op.tableName + ':' + op.confidence] as opStrings
        SET m.dbOperationCount = size(relOps),
            m.dbOperations = opStrings
        RETURN m.fqn, m.dbOperationCount, m.dbOperations
        """
        
        method_fqns = [m['methodFqn'] for m in orphaned_methods]
        
        with self.driver.session(database=self.database) as session:
            result = session.run(rebuild_query, methodFqns=method_fqns)
            rebuild_count = 0
            for record in result:
                rebuild_count += 1
                logger.info(
                    f"    ✓ Rebuilt {record['fqn']}: "
                    f"count={record['dbOperationCount']}, "
                    f"ops_count={len(record['dbOperations'])}"
                )
            self.stats['rebuilt_methods'] = rebuild_count
        
        logger.info(f"  ✓ Successfully rebuilt {rebuild_count} method properties")
    
    def print_statistics(self) -> None:
        """Print validation statistics"""
        logger.info("\n" + "=" * 80)
        logger.info("CONSISTENCY VALIDATION STATISTICS")
        logger.info("=" * 80)
        logger.info(f"  Orphaned methods found:        {self.stats['orphaned_methods']}")
        logger.info(f"  Orphaned relationships:        {self.stats['orphaned_relationships']}")
        logger.info(f"  Consistency violations:        {self.stats['consistency_violations']}")
        logger.info(f"  Methods rebuilt:               {self.stats['rebuilt_methods']}")
        logger.info("=" * 80 + "\n")
    
    def close(self):
        """Close Neo4j driver"""
        self.driver.close()


def validate_and_repair_db_operations(config_path: str = None, repair: bool = True, logger_instance=None) -> Dict:
    """
    Standalone function to validate and repair DB operation consistency.
    
    Can be called from other modules (e.g., manual_resource_associator.py)
    
    Args:
        config_path: Path to information_graph_config.yaml (default: env var or default path)
        repair: Whether to repair orphaned relationships (default: True)
        logger_instance: Logger instance to use (default: module logger)
    
    Returns:
        Dictionary with statistics: {
            'orphaned_methods': count,
            'orphaned_relationships': count,
            'consistency_violations': count,
            'rebuilt_methods': count
        }
    """
    import os
    
    if config_path is None:
        config_path = os.getenv("KG_CONFIG_FILE", "config/information_graph_config.yaml")
    
    validator = DBOperationConsistencyValidator(config_path)
    try:
        stats = validator.validate_and_repair(repair=repair)
        
        # Log summary if caller provided logger
        if logger_instance:
            logger_instance.info(f"DB Operation Consistency Check: {stats['orphaned_methods']} orphaned methods found, "
                               f"{stats['rebuilt_methods']} rebuilt")
        else:
            validator.print_statistics()
        
        return stats
    finally:
        validator.close()


def main():
    import os
    from dotenv import load_dotenv
    
    load_dotenv()
    config_path = os.getenv("KG_CONFIG_FILE", "config/information_graph_config.yaml")
    
    validator = DBOperationConsistencyValidator(config_path)
    try:
        # Run validation and repair
        stats = validator.validate_and_repair(repair=True)
        validator.print_statistics()
    finally:
        validator.close()


if __name__ == '__main__':
    main()
