"""Rebuild JavaMethod DB-operation properties from DB_OPERATION relationships."""

import logging
from neo4j import GraphDatabase
from typing import Dict
import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - [%(pathname)s:%(lineno)d %(funcName)s] - %(message)s"
)
logger = logging.getLogger(__name__)


class DBOperationConsistencyValidator:
    """Rebuilds JavaMethod DB-operation properties from relationship data."""
    
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
            'rebuilt_methods': 0,
            'methods_with_relationships': 0
        }

    def rebuild_all_method_properties(self) -> Dict:
        """Rebuild dbOperationCount/dbOperations for every JavaMethod from relationships."""
        logger.info(" " + "=" * 80)
        logger.info("JAVA METHOD DB OPERATION CONSOLIDATION")
        logger.info("=" * 80)
        logger.info("  Rebuilding DB operation properties for ALL JavaMethods from relationships...")

        rebuild_all_query = """
        MATCH (m:JavaMethod)
        OPTIONAL MATCH (m)-[rel:DB_OPERATION]->(r:Resource {type: 'TABLE'})
        WITH m,
             collect(DISTINCT CASE
                 WHEN rel IS NULL THEN NULL
                 ELSE rel.operationType + ':' + r.name + ':' + coalesce(rel.confidence, 'MEDIUM')
             END) as rawOps
        WITH m, [op IN rawOps WHERE op IS NOT NULL] as opStrings
        SET m.dbOperationCount = size(opStrings),
            m.dbOperations = opStrings
        RETURN count(m) as totalMethods,
               sum(CASE WHEN size(opStrings) > 0 THEN 1 ELSE 0 END) as methodsWithOps
        """

        with self.driver.session(database=self.database) as session:
            record = session.run(rebuild_all_query).single()

        self.stats['rebuilt_methods'] = record['totalMethods'] if record else 0
        self.stats['methods_with_relationships'] = record['methodsWithOps'] if record else 0
        logger.info(
            f"  ✓ Rebuilt JavaMethod DB properties for {self.stats['rebuilt_methods']} methods "
            f"({self.stats['methods_with_relationships']} with DB relationships)"
        )
        logger.info("=" * 80)
        return self.stats
    
    def print_statistics(self) -> None:
        """Print validation statistics"""
        logger.info("\n" + "=" * 80)
        logger.info("DB OPERATION CONSOLIDATION STATISTICS")
        logger.info("=" * 80)
        logger.info(f"  Methods consolidated:          {self.stats['rebuilt_methods']}")
        logger.info(f"  Methods with DB relationships: {self.stats['methods_with_relationships']}")
        logger.info("=" * 80 + "\n")
    
    def close(self):
        """Close Neo4j driver"""
        self.driver.close()


def validate_and_repair_db_operations(config_path: str = None, logger_instance=None) -> Dict:
    """
    Standalone function to rebuild JavaMethod DB-operation properties.
    
    Can be called from other modules (e.g., manual_resource_associator.py)
    
    Args:
        config_path: Path to information_graph_config.yaml (default: env var or default path)
        logger_instance: Logger instance to use (default: module logger)
    
    Returns:
        Dictionary with statistics: {
            'rebuilt_methods': count,
            'methods_with_relationships': count
        }
    """
    import os
    
    if config_path is None:
        config_path = os.getenv("KG_CONFIG_FILE", "config/information_graph_config.yaml")
    
    validator = DBOperationConsistencyValidator(config_path)
    try:
        stats = validator.rebuild_all_method_properties()
        
        if logger_instance:
            logger_instance.info(
                f"DB Operation Consolidation: {stats['rebuilt_methods']} methods consolidated, "
                f"{stats['methods_with_relationships']} with DB relationships"
            )
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
        stats = validator.rebuild_all_method_properties()
        validator.print_statistics()
    finally:
        validator.close()


if __name__ == '__main__':
    main()
