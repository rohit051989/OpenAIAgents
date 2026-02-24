"""
DB Operation Enricher

This script enriches an existing Information Graph with database operation analysis.
Runs after information_graph_builder_v3.py completes.

Supports two strategies:
1. Regex: Fast pattern-matching based analysis
2. LLM: AI-powered multi-agent analysis with context gathering

Architecture:
- Queries Neo4j for DAO classes (isDAOClass=true)
- For each DAO class, extracts all methods
- For each method:
  - Regex: Direct analysis with patterns
  - LLM: Multi-agent flow
    - Agent 1 (Evaluator): Determines if method source is sufficient
    - Agent 2 (Extractor): Extracts DB operations
    - Agent 3 (Gatherer): Finds additional required Java classes from graph
- Updates Neo4j with dbOperations and dbOperationCount
- Consolidates operations at Step level
"""

import os
from dotenv import load_dotenv
import yaml
import uuid
from neo4j import GraphDatabase
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path
import json

# Import analyzers
from classes.DAOAnalyzer import DAOAnalyzer
from classes.DataClasses import ClassInfo

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


class MultiAgentLLMAnalyzer:
    """Multi-agent LLM analyzer with context gathering capabilities"""
    
    def __init__(self, llm_config: dict, neo4j_driver):
        self.llm_config = llm_config
        self.driver = neo4j_driver
        self.provider = llm_config.get('provider', 'openai')
        self.model = llm_config.get('model', 'gpt-4')
        self.temperature = llm_config.get('temperature', 0.1)
        self.max_tokens = llm_config.get('max_tokens', 2000)
        
        # Initialize LLM client
        self._init_llm_client()
        
        # Cache for analyzed methods
        self.cache = {}
        self.cache_file = llm_config.get('cache_file', '.db_operation_cache.json')
        if llm_config.get('cache_results', True):
            self._load_cache()
    
    def _init_llm_client(self):
        """Initialize LLM client based on provider"""
        import os
        
        if self.provider == 'openai':
            from openai import OpenAI
            api_key = os.getenv(self.llm_config.get('api_key_env', 'OPENAI_API_KEY'))
            if not api_key:
                raise ValueError(f"API key not found in environment variable: {self.llm_config.get('api_key_env')}")
            self.client = OpenAI(api_key=api_key)
        
        elif self.provider == 'anthropic':
            from anthropic import Anthropic
            api_key = os.getenv(self.llm_config.get('api_key_env', 'ANTHROPIC_API_KEY'))
            if not api_key:
                raise ValueError(f"API key not found: {self.llm_config.get('api_key_env')}")
            self.client = Anthropic(api_key=api_key)
        
        elif self.provider == 'ollama':
            self.client = None  # Local Ollama
        
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")
    
    def _load_cache(self):
        """Load cache from file"""
        if Path(self.cache_file).exists():
            try:
                with open(self.cache_file, 'r') as f:
                    self.cache = json.load(f)
                logger.info(f"  Loaded {len(self.cache)} cached analyses")
            except Exception as e:
                logger.warning(f"Failed to load cache: {e}")
                self.cache = {}
    
    def _save_cache(self):
        """Save cache to file"""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save cache: {e}")
    
    def analyze_method(self, method_fqn: str, method_source: str, class_fqn: str, 
                      database: str) -> List[Dict]:
        """
        Analyze a single method using multi-agent approach
        
        Returns: List of DB operations [{"operation_type": "SELECT", "table_name": "...", ...}]
        """
        # Check cache
        cache_key = f"{method_fqn}:{hash(method_source)}"
        if cache_key in self.cache:
            logger.info(f"       Cache hit for {method_fqn}")
            return self.cache[cache_key]
        
        logger.info(f"      🤖 Analyzing {method_fqn}")
        
        # Agent 1: Evaluator - Check if method source is sufficient
        is_sufficient, missing_classes = self._agent_evaluator(method_fqn, method_source)
        
        additional_context = ""
        if not is_sufficient and missing_classes:
            # Agent 3: Gatherer - Get additional class sources from graph
            additional_context = self._agent_gatherer(missing_classes, database)
        
        # Agent 2: Extractor - Extract DB operations
        operations = self._agent_extractor(method_fqn, method_source, additional_context)
        
        # Cache result
        self.cache[cache_key] = operations
        self._save_cache()
        
        return operations
    
    def _agent_evaluator(self, method_fqn: str, method_source: str) -> Tuple[bool, List[str]]:
        """
        Agent 1: Evaluate if method source is sufficient for analysis
        
        Returns: (is_sufficient, list_of_missing_class_fqns)
        """
        prompt = f"""You are a code analyzer evaluating if a Java method's source code contains enough information to extract database operations.

**Method:** {method_fqn}

**Source Code:**
```java
{method_source}
```

**Task:**
Determine if the method source alone is sufficient to identify all database operations, or if we need additional Java class files.

You need additional classes if:
- Method calls other methods that might do DB operations (not simple getters/setters)
- Uses constants from other classes that contain SQL
- Depends on injected beans that might do DB operations

**Output Format (JSON):**
```json
{{
  "is_sufficient": true/false,
  "missing_classes": ["com.example.dao.UserDAO", "com.example.constants.SQLQueries"],
  "reasoning": "Brief explanation"
}}
```

Return ONLY the JSON:"""
        
        response = self._call_llm(prompt)
        
        # Parse response
        try:
            import re
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                result = json.loads(json_match.group(0))
                return result.get('is_sufficient', True), result.get('missing_classes', [])
        except:
            pass
        
        # Default: assume sufficient
        return True, []
    
    def _agent_gatherer(self, class_fqns: List[str], database: str) -> str:
        """
        Agent 3: Gather source code for additional classes from Neo4j graph
        
        Returns: Combined source code of all additional classes
        """
        logger.info(f"        📥 Gathering {len(class_fqns)} additional classes")
        
        additional_sources = []
        
        with self.driver.session(database=database) as session:
            for fqn in class_fqns:
                # Query graph for source path
                query = """
                MATCH (jc:JavaClass {fqn: $fqn})
                OPTIONAL MATCH (f:File {path: jc.path})
                RETURN jc.path as path, f.content as content
                """
                
                result = session.run(query, fqn=fqn)
                record = result.single()
                
                if record:
                    path = record['path']
                    content = record.get('content')
                    
                    # If content not in graph, read from file
                    if not content and path and Path(path).exists():
                        try:
                            with open(path, 'r', encoding='utf-8') as f:
                                content = f.read()
                        except Exception as e:
                            logger.warning(f"Failed to read {path}: {e}")
                    
                    if content:
                        additional_sources.append(f"\n\n// ===== {fqn} =====\n{content}")
                        logger.info(f"           Found {fqn}")
        
        return "".join(additional_sources)
    
    def _agent_extractor(self, method_fqn: str, method_source: str, 
                        additional_context: str = "") -> List[Dict]:
        """
        Agent 2: Extract DB operations from method source (with optional additional context)
        
        Returns: List of operations
        """
        context_info = f"\n\n**Additional Context Classes:**\n{additional_context}" if additional_context else ""
        
        prompt = f"""You are a database operation extractor for Java code. Analyze the method and extract all database operations.

**Method:** {method_fqn}

**Method Source:**
```java
{method_source}
```
{context_info}

**Task:**
Extract all **DIRECT** database operations from this method. 

**IMPORTANT RULES:**
1. ONLY extract operations if the method DIRECTLY uses DB APIs:
   - Spring JDBC (JdbcTemplate, NamedParameterJdbcTemplate)
   - JPA (EntityManager.persist/merge/remove/find/createQuery)
   - Hibernate (Session.save/update/delete/createQuery)
   - Raw JDBC (PreparedStatement, Statement.execute)
   - SQL in string literals or constants

2. DO NOT extract operations if the method only:
   - Calls other methods (e.g., saveAll calling save in a loop)
   - Delegates to other services
   - Is a wrapper/utility method

3. If method only contains method calls to other methods and no direct DB API usage, return empty array []

**Examples:**
- `saveAll(List items)` that loops and calls `save(item)` → [] (no direct DB operation)
- `save(Item item)` that calls `jdbcTemplate.update(...)` → [{...}] (direct DB operation)

**Output Format (JSON array):**
```json
[
  {{
    "operation_type": "SELECT",
    "table_name": "BATCH_JOBS",
    "confidence": "HIGH",
    "evidence": "jdbcTemplate.queryForObject with IFrameWorkDBQueries.FETCH_JOB_DETAILS constant"
  }}
]
```

**Important:**
- Extract actual table names from SQL (FROM/INTO/UPDATE clauses)
- If SQL is in constant, use the constant value to extract table
- confidence: HIGH (direct SQL visible), MEDIUM (inferred from method), LOW (uncertain)
- Return empty array [] if no DB operations found
- Return ONLY the JSON array

Analyze now:"""
        
        response = self._call_llm(prompt)
        
        # Parse response
        try:
            import re
            json_match = re.search(r'\[[\s\S]*\]', response)
            if json_match:
                return json.loads(json_match.group(0))
        except Exception as e:
            logger.warning(f"Failed to parse extractor response: {e}")
        
        return []
    
    def _call_llm(self, prompt: str) -> str:
        """Call LLM API"""
        if self.provider == 'openai':
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a Java code analyzer. Return only JSON responses."},
                    {"role": "user", "content": prompt}
                ],
                temperature=self.temperature,
                max_tokens=self.max_tokens
            )
            return response.choices[0].message.content.strip()
        
        elif self.provider == 'anthropic':
            response = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                messages=[{"role": "user", "content": prompt}]
            )
            return response.content[0].text.strip()
        
        elif self.provider == 'ollama':
            import requests
            response = requests.post(
                'http://localhost:11434/api/generate',
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False
                }
            )
            return response.json()['response'].strip()
        
        return ""


class DBOperationEnricher:
    """Enriches Neo4j graph with DB operation analysis"""
    
    def __init__(self, config_path: str):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        # Neo4j connection
        neo4j_config = self.config['neo4j']
        self.driver = GraphDatabase.driver(
            neo4j_config['uri'],
            auth=(neo4j_config['user'], neo4j_config['password'])
        )
        self.database = neo4j_config['database_ig']
        
        # DB analysis config
        self.db_config = self.config.get('db_operation_analysis', {})
        self.strategy = self.db_config.get('strategy', 'regex')
        
        logger.info(f"DB Operation Enricher initialized with strategy: {self.strategy.upper()}")
    
    def enrich(self):
        """Main enrichment process"""
        logger.info(" " + "=" * 80)
        logger.info("DB OPERATION ENRICHMENT")
        logger.info("=" * 80)
        logger.info(f"Strategy: {self.strategy.upper()}")
        logger.info("=" * 80)
        
        # Step 1: Query all DAO classes from graph
        dao_classes = self._get_dao_classes()
        logger.info(f" Found {len(dao_classes)} DAO classes to analyze")
        
        # Step 2: Initialize analyzer based on strategy
        if self.strategy == 'llm':
            analyzer = MultiAgentLLMAnalyzer(
                self.db_config.get('llm', {}),
                self.driver
            )
        else:
            analyzer = DAOAnalyzer(
                neo4j_driver=self.driver,
                neo4j_database=self.database
            )
        
        # Step 3: Process each DAO class
        total_methods = 0
        methods_with_ops = 0
        
        for dao_class in dao_classes:
            class_fqn = dao_class['fqn']
            class_name = dao_class['className']
            path = dao_class['path']
            
            logger.info(f"   Processing DAO: {class_name}")
            
            # Get all methods for this class
            methods = self._get_class_methods(class_fqn)
            total_methods += len(methods)
            
            for method in methods:
                method_fqn = method['fqn']
                method_name = method['methodName']
                
                # Get method source
                method_source = self._get_method_source(path, method_name)
                
                if not method_source:
                    continue
                
                # Analyze method
                if self.strategy == 'llm':
                    operations = analyzer.analyze_method(
                        method_fqn, method_source, class_fqn, self.database
                    )
                else:
                    # Regex strategy - need to reconstruct ClassInfo and MethodDef
                    class_info = self._build_class_info(path, class_fqn)
                    if class_info and method_name in class_info.methods:
                        method_def = class_info.methods[method_name]
                        operations = analyzer.analyze_method(method_def, class_info)  # Now returns List[DBOperation]
                    else:
                        operations = []
                
                # Update Neo4j
                if operations:
                    self._update_method_operations(method_fqn, operations)
                    methods_with_ops += 1
                    
                    for op in operations:
                        op_type = op.get('operation_type') if isinstance(op, dict) else op.operation_type
                        table = op.get('table_name') if isinstance(op, dict) else op.table_name
                        logger.info(f"    {method_name}() -> {op_type} {table or '?'}")
        
        logger.info(f"    Analyzed {total_methods} methods")
        logger.info(f"   Found DB operations in {methods_with_ops} methods")
        
        # Step 4: Consolidate at Step level
        self._consolidate_step_db_operations()
        
        logger.info(" " + "=" * 80)
        logger.info(" DB OPERATION ENRICHMENT COMPLETE")
        logger.info("=" * 80)
    
    def _get_dao_classes(self) -> List[Dict]:
        """Query Neo4j for all DAO classes"""
        query = """
        MATCH (jc:JavaClass {isDAOClass: true})
        RETURN jc.fqn as fqn, 
               jc.className as className, 
               jc.path as path
        ORDER BY jc.className
        """
        
        with self.driver.session(database=self.database) as session:
            result = session.run(query)
            return [dict(record) for record in result]
    
    def _get_class_methods(self, class_fqn: str) -> List[Dict]:
        """Get all methods for a class"""
        query = """
        MATCH (jc:JavaClass {fqn: $fqn})-[:HAS_METHOD]->(m:JavaMethod)
        RETURN m.fqn as fqn, m.methodName as methodName
        """
        
        with self.driver.session(database=self.database) as session:
            result = session.run(query, fqn=class_fqn)
            return [dict(record) for record in result]
    
    def _get_method_source(self, path: str, method_name: str) -> Optional[str]:
        """Extract method source code from file"""
        if not path or not Path(path).exists():
            return None
        
        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Use DAOAnalyzer's method extraction
            analyzer = DAOAnalyzer(
                neo4j_driver=self.driver,
                neo4j_database=self.database
            )
            return analyzer._extract_method_source(content, method_name)
        except Exception as e:
            logger.warning(f"Failed to read method source: {e}")
            return None
    
    def _build_class_info(self, path: str, class_fqn: str) -> Optional[ClassInfo]:
        """Build ClassInfo object for regex analysis"""
        from classes.JavaCallHierarchyParser import JavaCallHierarchyParser
        
        parser = JavaCallHierarchyParser()
        return parser.parse_java_file(path)
    
    def _update_method_operations(self, method_fqn: str, operations: List):
        """Update JavaMethod node with DB operations and create Resource nodes"""
        # Convert operations to proper format
        op_strings = []
        requires_further_analysis = False
        
        for op in operations:
            if isinstance(op, dict):
                table_name = op.get('table_name', 'UNKNOWN')
                op_str = f"{op['operation_type']}:{table_name}:{op.get('confidence', 'MEDIUM')}"
                # Check if table name is unknown or dynamic
                if table_name == 'UNKNOWN' or table_name is None or 'DYNAMIC' in str(table_name).upper():
                    requires_further_analysis = True
            else:
                table_name = op.table_name or 'UNKNOWN'
                op_str = f"{op.operation_type}:{table_name}:{op.confidence}"
                # Check if table name is unknown or dynamic
                if table_name == 'UNKNOWN' or table_name is None or 'DYNAMIC' in str(table_name).upper():
                    requires_further_analysis = True
            op_strings.append(op_str)
        
        # Update JavaMethod node
        query = """
        MATCH (m:JavaMethod {fqn: $fqn})
        SET m.dbOperations = $operations,
            m.dbOperationCount = $count,
            m.furtherAnalysisRequired = $furtherAnalysisRequired
        """
        
        with self.driver.session(database=self.database) as session:
            session.run(query, fqn=method_fqn, operations=op_strings, count=len(op_strings), furtherAnalysisRequired=requires_further_analysis)
        
        # Create Resource nodes and relationships
        self._create_resource_relationships(method_fqn, operations)
    
    def _create_resource_relationships(self, method_fqn: str, operations: List):
        """Create Resource nodes and DB_OPERATION relationships for each database table"""
        if not operations:
            return
        
        escaped_method_fqn = escape_cypher_string(method_fqn)
        
        with self.driver.session(database=self.database) as session:
            for op in operations:
                # Extract operation details
                if isinstance(op, dict):
                    table_name = op.get('table_name', 'UNKNOWN')
                    operation_type = op.get('operation_type', 'UNKNOWN')
                    confidence = op.get('confidence', 'MEDIUM')
                    entity_type = op.get('entity_type', 'UNKNOWN')
                    schema_name = op.get('schema_name', 'UNKNOWN')
                else:
                    table_name = op.table_name if hasattr(op, 'table_name') else 'UNKNOWN'
                    operation_type = op.operation_type if hasattr(op, 'operation_type') else 'UNKNOWN'
                    confidence = op.confidence if hasattr(op, 'confidence') else 'MEDIUM'
                    entity_type = op.entity_type if hasattr(op, 'entity_type') else 'UNKNOWN'
                    schema_name = op.schema_name if hasattr(op, 'schema_name') else 'UNKNOWN'
                
                # Normalize and escape values
                table_name = table_name.upper() if table_name else "UNKNOWN"
                schema_name = schema_name.upper() if schema_name else "UNKNOWN"
                
                # Skip Resource creation for DYNAMIC/UNKNOWN table names
                # These need manual resolution before Resource association
                skip_keywords = ['DYNAMIC', 'UNKNOWN', 'DYNAMIC_TABLE', 'DYNAMIC_CATALOG', 'DYNAMIC_SCHEMA']
                if any(keyword in table_name for keyword in skip_keywords):
                    logger.info(f"  Skipping Resource creation for {table_name} (requires manual resolution)")
                    continue
                
                escaped_table_name = escape_cypher_string(table_name)
                escaped_schema_name = escape_cypher_string(schema_name)
                escaped_entity_type = escape_cypher_string(entity_type if entity_type else "UNKNOWN")
                escaped_operation_type = escape_cypher_string(operation_type)
                escaped_confidence = escape_cypher_string(confidence)
                
                # Generate unique ID for new resources
                unique_id = f"RES_TABLE_{uuid.uuid4().hex[:8].upper()}"
                escaped_resource_id = escape_cypher_string(unique_id)
                
                try:
                    # Create or update Resource node
                    resource_query = f"""
                    MERGE (r:Resource {{name: '{escaped_table_name}', type: 'TABLE'}})
                    ON CREATE SET r.id = '{escaped_resource_id}',
                                  r.enabled = true,
                                  r.schemaName = '{escaped_schema_name}'
                    ON MATCH SET r.schemaName = COALESCE(r.schemaName, '{escaped_schema_name}')
                    """
                    session.run(resource_query)
                    
                    # Create relationship between JavaMethod and Resource
                    relationship_query = f"""
                    MATCH (m:JavaMethod {{fqn: '{escaped_method_fqn}'}})
                    MATCH (r:Resource {{name: '{escaped_table_name}', type: 'TABLE'}})
                    MERGE (m)-[:DB_OPERATION {{
                        operationType: '{escaped_operation_type}',
                        confidence: '{escaped_confidence}'
                    }}]->(r)
                    """
                    session.run(relationship_query)
                    
                except Exception as e:
                    logger.warning(f"Failed to create Resource relationship for {table_name}: {e}")
    
    def _consolidate_step_db_operations(self):
        """
        Consolidate database operations at Step level by traversing the call graph.
        """
        logger.info(" " + "=" * 80)
        logger.info("Consolidating Database Operations at Step Level")
        logger.info("=" * 80)
        
        # Get all Steps
        query_steps = """
        MATCH (s:Step)
        OPTIONAL MATCH (s)-[:IMPLEMENTED_BY]->(jc:JavaClass)
        RETURN s.name as stepName, 
               s.stepKind as stepKind,
               elementId(s) as stepId,
               collect(DISTINCT jc.fqn) as classNames
        """
        
        with self.driver.session(database=self.database) as session:
            result = session.run(query_steps)
            steps_data = [dict(record) for record in result]
        
        logger.info(f"  Found {len(steps_data)} Steps to process")
        
        steps_updated = 0
        
        for step_data in steps_data:
            step_name = step_data['stepName']
            step_kind = step_data['stepKind']
            step_id = step_data['stepId']
            class_names = step_data['classNames']
            
            if not class_names:
                continue
            
            # Determine entry method names
            if step_kind == "TASKLET":
                entry_method_names = ["execute"]
            elif step_kind == "CHUNK":
                entry_method_names = ["read", "process", "write"]
            else:
                continue
            
            # Find entry methods
            query_entry_methods = """
            MATCH (s:Step)
            WHERE elementId(s) = $stepId
            MATCH (s)-[:IMPLEMENTED_BY]->(jc:JavaClass)-[:HAS_METHOD]->(m:JavaMethod)
            WHERE m.methodName IN $methodNames
            RETURN elementId(m) as methodId, 
                   m.methodName as methodName,
                   m.dbOperations as dbOps,
                   m.dbOperationCount as dbOpCount
            """
            
            with self.driver.session(database=self.database) as session:
                result = session.run(query_entry_methods, 
                                    stepId=step_id, 
                                    methodNames=entry_method_names)
                entry_methods = [dict(record) for record in result]
            
            if not entry_methods:
                continue
            
            # BFS to collect all operations
            all_db_operations = set()
            
            for entry_method in entry_methods:
                method_id = entry_method['methodId']
                
                if entry_method.get('dbOps') and entry_method.get('dbOpCount', 0) > 0:
                    all_db_operations.update(entry_method['dbOps'])
                
                # BFS traversal
                visited = set()
                queue = [method_id]
                visited.add(method_id)
                
                while queue:
                    current_id = queue.pop(0)
                    
                    query_calls = """
                    MATCH (m:JavaMethod)-[:CALLS]->(called:JavaMethod)
                    WHERE elementId(m) = $methodId
                    RETURN elementId(called) as calledId,
                           called.dbOperations as dbOps,
                           called.dbOperationCount as dbOpCount
                    """
                    
                    with self.driver.session(database=self.database) as session:
                        result = session.run(query_calls, methodId=current_id)
                        called_methods = [dict(record) for record in result]
                    
                    for called in called_methods:
                        called_id = called['calledId']
                        
                        if called_id not in visited:
                            visited.add(called_id)
                            queue.append(called_id)
                            
                            if called.get('dbOps') and called.get('dbOpCount', 0) > 0:
                                all_db_operations.update(called['dbOps'])
            
            # Update Step
            if all_db_operations:
                step_ops_list = sorted(list(all_db_operations))
                
                query_update = """
                MATCH (s:Step)
                WHERE elementId(s) = $stepId
                SET s.stepDbOperations = $operations,
                    s.stepDbOperationCount = $count
                RETURN s.name as name
                """
                
                with self.driver.session(database=self.database) as session:
                    session.run(query_update, 
                               stepId=step_id,
                               operations=step_ops_list,
                               count=len(step_ops_list))
                
                steps_updated += 1
                logger.info(f"    Step '{step_name}': {len(step_ops_list)} unique DB operations")
        
        logger.info(f"    Updated {steps_updated} Steps with consolidated DB operations")
        logger.info("=" * 80)
    
    def close(self):
        """Close Neo4j driver"""
        self.driver.close()


if __name__ == '__main__':

    load_dotenv()
    config_path = os.getenv("KG_CONFIG_FILE")
    
    enricher = DBOperationEnricher(config_path)
    try:
        enricher.enrich()
    finally:
        enricher.close()
