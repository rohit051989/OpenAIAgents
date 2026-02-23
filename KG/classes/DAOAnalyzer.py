from classes.DataClasses import ClassInfo, DBOperation, MethodDef
import re
import yaml
from pathlib import Path
from typing import Tuple, Optional, Dict, List, Any
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - [%(pathname)s:%(lineno)d %(funcName)s] - %(message)s"
)
logger = logging.getLogger(__name__)


class DAOAnalyzer:
    """Analyzes DAO methods to extract database operations"""

    def __init__(self, rules_config_path: str = None, neo4j_driver=None, neo4j_database: str = None):
        """
        Initialize DAOAnalyzer with externalized rules and optional Neo4j access.
        
        Args:
            rules_config_path: Path to DAO analysis rules YAML file
            neo4j_driver: Optional Neo4j driver for querying information graph
            neo4j_database: Optional Neo4j database name for queries
        """
        if rules_config_path is None:
            rules_config_path = Path(__file__).parent.parent / 'config' / 'dao_analysis_rules.yaml'
        
        self.rules = self._load_rules(rules_config_path)
        self.neo4j_driver = neo4j_driver
        self.neo4j_database = neo4j_database
        
        # Extract frequently used rules for performance
        self.db_import_patterns = self.rules.get('db_import_patterns', [])
        self.excluded_class_suffixes = self.rules.get('excluded_class_suffixes', [])
        self.dao_method_keywords = self.rules.get('dao_method_keywords', [])
        self.operation_method_prefixes = self.rules.get('operation_method_prefixes', {})
        self.jpa_patterns = self._compile_jpa_patterns()
        self.direct_db_patterns = self.rules.get('direct_db_operation_patterns', [])
        self.table_extraction_patterns = self.rules.get('table_extraction_patterns', [])
        self.excluded_java_types = self.rules.get('excluded_java_types', [])
        self.dynamic_sql_patterns = self.rules.get('dynamic_sql_patterns', [])
        self.skip_resource_keywords = self.rules.get('skip_resource_keywords', 
                                                     ['DYNAMIC', 'UNKNOWN', 'DYNAMIC_TABLE', 
                                                      'DYNAMIC_CATALOG', 'DYNAMIC_SCHEMA'])
    
    def _load_rules(self, config_path: Path) -> Dict[str, Any]:
        """Load analysis rules from YAML configuration file"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                rules = yaml.safe_load(f)
            #logger.info(f"[OK] Loaded DAO analysis rules from: {config_path}")
            return rules
        except FileNotFoundError:
            logger.info(f"[WARN] DAO rules config not found: {config_path}, using defaults")
            return self._get_default_rules()
        except yaml.YAMLError as e:
            logger.info(f"[WARN] Error parsing DAO rules config: {e}, using defaults")
            return self._get_default_rules()
    
    def _get_default_rules(self) -> Dict[str, Any]:
        """Return minimal default rules if config file is not found"""
        return {
            'db_import_patterns': ['javax.persistence', 'org.springframework.jdbc', 'java.sql'],
            'excluded_class_suffixes': ['entity', 'model', 'dto'],
            'dao_method_keywords': ['find', 'save', 'delete', 'update', 'query'],
            'operation_method_prefixes': {
                'SELECT': ['find', 'get', 'select'],
                'INSERT': ['save', 'insert', 'create'],
                'UPDATE': ['update', 'modify'],
                'DELETE': ['delete', 'remove']
            },
            'excluded_java_types': ['List', 'Set', 'Map', 'void', 'String', 'Integer']
        }
    
    def _compile_jpa_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Compile JPA patterns from config for better performance"""
        jpa_config = self.rules.get('jpa_patterns', {})
        compiled = {}
        
        for operation, patterns in jpa_config.items():
            compiled[operation] = []
            for pattern_item in patterns:
                # Handle both simple string patterns and dict-based patterns
                if isinstance(pattern_item, dict):
                    pattern_str = pattern_item.get('pattern', '')
                else:
                    pattern_str = pattern_item
                
                if pattern_str:
                    try:
                        compiled[operation].append(re.compile(pattern_str, re.IGNORECASE))
                    except re.error as e:
                        logger.info(f"[WARN] Invalid JPA pattern for {operation}: {pattern_str} - {e}")
        
        return compiled

    def analyze_method(self, method_def: MethodDef, class_info: ClassInfo) -> Optional[DBOperation]:
        """Analyze a DAO method to detect database operations"""
        # Only analyze if it looks like a DAO
        if not self._is_dao_class(class_info):
            return None

        # Read method source
        try:
            with open(class_info.source_path, 'r', encoding='utf-8') as f:
                source = f.read()
            method_source = self._extract_method_source(source, method_def.method_name)
        except:
            method_source = ""

        # Detect operation type
        operation_type = self._detect_operation_type(method_def, method_source)
        if not operation_type:
            return None

        # Extract entity/table info
        raw_query = self._extract_query(method_source, class_info)
        entity_type, table_name = self._extract_entity_info(method_def, method_source, raw_query)

        return DBOperation(
            operation_type=operation_type,
            table_name=table_name,
            entity_type=entity_type,
            method_fqn=method_def.fqn,
            raw_query=raw_query
        )

    def _is_dao_class(self, class_info: ClassInfo) -> bool:
        """
        Check if this looks like a DAO/Repository class using configured rules.

        Returns:
            True if class appears to be a DAO/Repository, False otherwise
        """
        # Exclude interfaces - they don't have DB operation logic
        if hasattr(class_info, 'is_interface') and class_info.is_interface:
            return False
            
        name_lower = class_info.class_name.lower()

        # Check 1: Exclude Entity/Model/DTO classes using configured suffixes
        for suffix in self.excluded_class_suffixes:
            if name_lower.endswith(suffix.lower()):
                return False

        # Check 2: Class name heuristics (strongest signal)
        if 'dao' in name_lower or 'repository' in name_lower:
            return True

        # Check 3: Database-related imports using configured patterns
        has_db_imports = False
        if class_info.imports:
            for import_stmt in class_info.imports:
                for db_pattern in self.db_import_patterns:
                    if import_stmt.startswith(db_pattern):
                        has_db_imports = True
                        break
                if has_db_imports:
                    break

        if has_db_imports:
            # Additional check: class should have typical DAO method names from config
            method_names = [m.lower() for m in class_info.methods.keys()]
            has_dao_methods = any(
                any(keyword in method_name for keyword in self.dao_method_keywords)
                for method_name in method_names
            )

            if has_dao_methods:
                return True

        return False

    def _detect_operation_type(self, method_def: MethodDef, source: str) -> Optional[str]:
        """Detect database operation type using configured rules"""
        
        # First, check if method directly uses DB APIs
        if not self._has_direct_db_operation(source):
            return None
        
        method_lower = method_def.method_name.lower()

        # Method name heuristics from configuration
        for operation, prefixes in self.operation_method_prefixes.items():
            for prefix in prefixes:
                if method_lower.startswith(prefix.lower()):
                    return operation

        # Pattern matching using configured JPA patterns
        for op_type, compiled_patterns in self.jpa_patterns.items():
            for pattern in compiled_patterns:
                if pattern.search(source):
                    return op_type

        return None
    
    def _has_direct_db_operation(self, source: str) -> bool:
        """
        Check if method directly performs DB operations using configured patterns.
        
        Returns True if method contains direct DB API calls.
        """
        for pattern_item in self.direct_db_patterns:
            # Handle both simple string patterns and dict-based patterns
            if isinstance(pattern_item, dict):
                pattern_str = pattern_item.get('pattern', '')
            else:
                pattern_str = pattern_item
                
            if pattern_str:
                try:
                    if re.search(pattern_str, source, re.IGNORECASE):
                        return True
                except re.error:
                    continue
        
        return False

    def _extract_entity_info(self, method_def: MethodDef, source: str, raw_query: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
        """Extract entity type and table name using configured rules"""
        entity_type = None
        table_name = None

        # Priority 1: Extract from SQL query if available
        if raw_query and raw_query != "DYNAMIC_SQL":
            # Parse table name from SQL using configured patterns
            for pattern_item in self.table_extraction_patterns:
                # Handle both simple string patterns and dict-based patterns
                if isinstance(pattern_item, dict):
                    pattern_str = pattern_item.get('pattern', '')
                else:
                    pattern_str = pattern_item
                    
                try:
                    match = re.search(pattern_str, raw_query, re.IGNORECASE)
                    if match:
                        table_name = match.group(1).strip()
                        # Remove schema prefix if present
                        if '.' in table_name:
                            table_name = table_name.split('.')[-1]
                        logger.info(f"          Extracted table from SQL: {table_name}")
                        break
                except (re.error, IndexError):
                    continue
                    
        elif raw_query == "DYNAMIC_SQL":
            logger.info(f"          Dynamic SQL detected - table name cannot be determined statically")
            table_name = "DYNAMIC_TABLE"

        # Priority 2: From return type with 'Entity' suffix
        if not table_name and 'Entity' in method_def.return_type:
            entity_suffix = self.rules.get('entity_naming_rules', {}).get('entity_suffix', 'Entity')
            entity_type = method_def.return_type.replace(entity_suffix, '')
            table_name = self._entity_to_table(entity_type)
            logger.info(f"          Inferred table from Entity return type: {table_name}")

        # Priority 3: From JPQL query in source
        if not table_name:
            jpql_patterns = self.rules.get('jpql_entity_patterns', [])
            for pattern_item in jpql_patterns:
                # Handle both simple string patterns and dict-based patterns
                if isinstance(pattern_item, dict):
                    pattern_str = pattern_item.get('pattern', '')
                else:
                    pattern_str = pattern_item
                    
                try:
                    match = re.search(pattern_str, source, re.IGNORECASE)
                    if match:
                        entity_type = match.group(1)
                        table_name = self._entity_to_table(entity_type)
                        logger.info(f"          Inferred table from JPQL query: {table_name}")
                        break
                except (re.error, IndexError):
                    continue

        # Priority 4: Infer from return type (even non-Entity classes)
        if not table_name and method_def.return_type:
            # Extract simple class name from return type
            return_type_simple = method_def.return_type.split('.')[-1]
            
            # Remove generic type parameters: List<String> -> List
            return_type_simple = re.sub(r'<.*>', '', return_type_simple)
            
            # Check if it's a Java type using configured list
            if return_type_simple in self.excluded_java_types:
                logger.info(f"          Return type {return_type_simple} is a Java type, not a table - marking as UNKNOWN")
                table_name = "UNKNOWN"
            elif return_type_simple and return_type_simple[0].isupper():
                table_name = self._entity_to_table(return_type_simple)
                logger.info(f"          Inferred table from return type ({return_type_simple}): {table_name}")

        return entity_type, table_name.upper() if table_name else None

    def _extract_query(self, source: str, class_info: ClassInfo = None) -> Optional[str]:
        """Extract SQL/JPQL query using configured patterns"""
        
        # Use configured SQL extraction patterns
        sql_patterns = self.rules.get('sql_extraction_patterns', {})
        
        for pattern_type, pattern_config in sql_patterns.items():
            pattern_str = pattern_config.get('pattern', '')
            
            try:
                match = re.search(pattern_str, source, re.DOTALL)
                if not match:
                    continue
                
                if pattern_type == 'JPA_JPQL':
                    capture_group = pattern_config.get('capture_group', 1)
                    return match.group(capture_group).strip()
                
                elif pattern_type == 'JDBC_INLINE':
                    # Check for dynamic SQL patterns first
                    call_start = match.end() - len(match.group(0))
                    snippet = source[call_start:call_start+500]
                    
                    # Check for concatenation using configured patterns
                    for dynamic_pattern_item in self.dynamic_sql_patterns:
                        # Handle both simple string patterns and dict-based patterns
                        if isinstance(dynamic_pattern_item, dict):
                            dynamic_pattern = dynamic_pattern_item.get('pattern', '')
                            desc = dynamic_pattern_item.get('description', 'dynamic SQL')
                        else:
                            dynamic_pattern = dynamic_pattern_item
                            desc = 'dynamic SQL'
                            
                        if re.search(dynamic_pattern, snippet):
                            logger.info(f"        Detected {desc}")
                            return "DYNAMIC_SQL"
                    
                    # Normal inline query
                    capture_group = pattern_config.get('capture_group', 2)
                    if match.lastindex and match.lastindex >= capture_group:
                        return match.group(capture_group).strip()
                
                elif pattern_type == 'JDBC_CONSTANT' and class_info:
                    const_class_group = pattern_config.get('constant_class_group', 2)
                    const_name_group = pattern_config.get('constant_name_group', 3)
                    constant_class = match.group(const_class_group)
                    constant_name = match.group(const_name_group)
                    logger.info(f"        Detected constant reference: {constant_class}.{constant_name}")
                    resolved_query = self._resolve_sql_constant(constant_class, constant_name, class_info)
                    if resolved_query:
                        return resolved_query
            
            except (re.error, IndexError) as e:
                continue

        return None

    def _extract_method_source(self, file_content: str, method_name: str) -> str:
        """Extract method source from file - handles nested braces"""
        # Find method declaration
        method_pattern = rf'(public|private|protected)\s+[\w<>,\[\]\s]+\s+{re.escape(method_name)}\s*\([^)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{{'
        match = re.search(method_pattern, file_content, re.DOTALL)
        if not match:
            return ""

        # Find matching closing brace by counting braces
        start_pos = match.end() - 1  # Position of opening brace
        brace_count = 1
        pos = start_pos + 1

        while pos < len(file_content) and brace_count > 0:
            if file_content[pos] == '{':
                brace_count += 1
            elif file_content[pos] == '}':
                brace_count -= 1
            pos += 1

        if brace_count == 0:
            return file_content[match.start():pos]

        return ""

    def _resolve_sql_constant(self, constant_class: str, constant_name: str, class_info: ClassInfo) -> Optional[str]:
        """Resolve SQL constant by parsing the constant class file"""
        # Find the constant class in imports
        constant_fqn = None
        for import_stmt in class_info.imports:
            if import_stmt.endswith('.' + constant_class) or import_stmt == constant_class:
                constant_fqn = import_stmt
                break

        if not constant_fqn:
            # Try same package
            constant_fqn = f"{class_info.package}.{constant_class}"

        # Find the source file
        constant_source_path = self._find_constant_source_file(constant_fqn, class_info.source_path)
        if not constant_source_path:
            logger.info(f"        Warning: Could not find source file for constant class {constant_fqn}")
            return None

        # Parse the constant file to find the SQL string
        try:
            with open(constant_source_path, 'r', encoding='utf-8') as f:
                constant_source = f.read()

            # Pattern: public static final String CONSTANT_NAME = "SQL...";
            pattern = rf'(public\s+)?static\s+final\s+String\s+{re.escape(constant_name)}\s*=\s*\n?\s*"([\s\S]*?)";?'
            match = re.search(pattern, constant_source)
            if match:
                sql_query = match.group(2).strip()
                logger.info(f"         Resolved constant {constant_class}.{constant_name}")
                logger.info(f"          SQL: {sql_query[:80]}..." if len(sql_query) > 80 else f"          SQL: {sql_query}")
                return sql_query

            # Handle multi-line concatenation
            concat_pattern = rf'(public\s+)?static\s+final\s+String\s+{re.escape(constant_name)}\s*=\s*([\s\S]+?);'
            concat_match = re.search(concat_pattern, constant_source)
            if concat_match:
                sql_expr = concat_match.group(2)
                string_parts = re.findall(r'"([\s\S]*?)"', sql_expr)
                if string_parts:
                    sql_query = ' '.join(part.strip() for part in string_parts)
                    logger.info(f"         Resolved concatenated constant {constant_class}.{constant_name}")
                    logger.info(f"          SQL: {sql_query[:80]}..." if len(sql_query) > 80 else f"          SQL: {sql_query}")
                    return sql_query

            logger.info(f"        Warning: Could not match pattern for {constant_name} in {constant_source_path}")

        except Exception as e:
            logger.info(f"        Warning: Failed to parse constant file {constant_source_path}: {e}")

        return None

    def _find_constant_source_file(self, constant_fqn: str, current_source_path: str) -> Optional[str]:
        """Find the source file for a constant class.
        
        First tries to query the information graph (if available), then falls back to hardcoded path resolution.
        
        Args:
            constant_fqn: Fully qualified name of the constant class
            current_source_path: Path to the current source file (for fallback)
            
        Returns:
            Path to the constant source file, or None if not found
        """
        # Try querying information graph first (OPTIMIZED)
        if self.neo4j_driver and self.neo4j_database:
            try:
                query = """
                MATCH (n:JavaClass {fqn: $fqn})
                RETURN n.path as path
                LIMIT 1
                """
                
                with self.neo4j_driver.session(database=self.neo4j_database) as session:
                    result = session.run(query, fqn=constant_fqn)
                    record = result.single()
                    
                    if record and record['path']:
                        path = record['path']
                        if Path(path).exists():
                            logger.info(f"        ✅ Found constant source via graph: {constant_fqn}")
                            return path
                        else:
                            logger.info(f"        ⚠️  Graph returned path but file doesn't exist: {path}")
            except Exception as e:
                logger.debug(f"Failed to query graph for constant {constant_fqn}: {e}")
            # If graph query failed or didn't find the file, fall through to hardcoded logic
        
        # Fallback: Original hardcoded path resolution logic
        logger.info(f"        🔍 Using fallback path resolution for {constant_fqn}")
        
        # Convert FQN to relative path
        relative_path = constant_fqn.replace('.', '/') + '.java'

        # Start from the current source directory
        current_path = Path(current_source_path)
        source_root = current_path.parent

        while source_root and source_root.name not in ['java', 'src']:
            source_root = source_root.parent

        if not source_root:
            return None

        # Try to find the constant file
        potential_path = source_root / relative_path
        if potential_path.exists():
            return str(potential_path)

        # Try parent of source_root
        if source_root.parent:
            potential_path = source_root.parent / relative_path
            if potential_path.exists():
                return str(potential_path)

        return None

    def _entity_to_table(self, entity_name: str) -> str:
        """Convert entity name to table name using configured rules"""
        entity_config = self.rules.get('entity_naming_rules', {})
        entity_suffix = entity_config.get('entity_suffix', 'Entity')
        case_conversion = entity_config.get('case_conversion', 'snake_case')
        
        name = entity_name.replace(entity_suffix, '')
        
        if case_conversion == 'snake_case':
            return re.sub(r'(?<!^)(?=[A-Z])', '_', name).lower()
        elif case_conversion == 'lower':
            return name.lower()
        elif case_conversion == 'upper':
            return name.upper()
        else:
            return name
