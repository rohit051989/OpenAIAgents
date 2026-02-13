from classes.DataClasses import ClassInfo, DBOperation, MethodDef


import re
from pathlib import Path
from typing import Tuple, Optional


class DAOAnalyzer:
    """Analyzes DAO methods to extract database operations"""

    # Database-related import patterns to identify DAO/Repository classes
    DB_IMPORT_PATTERNS = [
        'javax.persistence',           # JPA annotations and EntityManager
        'org.springframework.jdbc',    # Spring JDBC templates
        'java.sql',                    # Raw JDBC (Connection, Statement, ResultSet)
        'org.springframework.data',    # Spring Data repositories
        'org.hibernate',               # Hibernate ORM
        'jakarta.persistence',         # Jakarta EE (JPA replacement for javax.persistence)
        'javax.sql',                   # DataSource and connection pooling
    ]

    JPA_PATTERNS = {
        'SELECT': [r'createQuery\s*\(\s*["\']SELECT', r'\.find\(', r'\.findAll\(', r'getResultList\('],
        'INSERT': [r'\.persist\(', r'\.save\(', r'createQuery\s*\(\s*["\']INSERT'],
        'UPDATE': [r'\.merge\(', r'\.update\(', r'createQuery\s*\(\s*["\']UPDATE'],
        'DELETE': [r'\.remove\(', r'\.delete\(', r'createQuery\s*\(\s*["\']DELETE'],
    }

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
        Check if this looks like a DAO/Repository class.
        Uses both class name heuristics and import analysis.

        Detection criteria:
        1. Class name contains 'dao' or 'repository' (case-insensitive)
        2. Class imports database-related packages (javax.persistence, org.springframework.jdbc, etc.)
        3. Excludes Entity/Model/DTO classes even if they have DB imports
        4. Excludes interfaces - only actual implementation classes can be DAOs

        Returns:
            True if class appears to be a DAO/Repository, False otherwise
        """
        # Exclude interfaces - they don't have DB operation logic, only their implementations do
        if hasattr(class_info, 'is_interface') and class_info.is_interface:
            return False
            
        name_lower = class_info.class_name.lower()

        # Exclude Entity, Model, DTO classes - these are data classes, not DAOs
        excluded_suffixes = ['entity', 'model', 'dto', 'vo', 'bean', 'pojo']
        for suffix in excluded_suffixes:
            if name_lower.endswith(suffix):
                return False

        # Check 1: Class name heuristics (strongest signal)
        if 'dao' in name_lower or 'repository' in name_lower:
            return True

        # Check 2: Database-related imports (for classes not following naming conventions)
        # Only consider if class has methods that suggest DB operations
        has_db_imports = False
        if class_info.imports:
            for import_stmt in class_info.imports:
                for db_pattern in self.DB_IMPORT_PATTERNS:
                    if import_stmt.startswith(db_pattern):
                        has_db_imports = True
                        break
                if has_db_imports:
                    break

        if has_db_imports:
            # Additional check: class should have typical DAO method names
            method_names = [m.lower() for m in class_info.methods.keys()]
            dao_method_keywords = ['find', 'save', 'delete', 'update', 'insert', 'query', 'get', 'create', 'persist']
            has_dao_methods = any(
                any(keyword in method_name for keyword in dao_method_keywords)
                for method_name in method_names
            )

            if has_dao_methods:
                return True

        return False

    def _detect_operation_type(self, method_def: MethodDef, source: str) -> Optional[str]:
        """Detect database operation type - only for direct DB operations"""
        
        # First, check if method directly uses DB APIs
        # If it only delegates to other methods, return None
        if not self._has_direct_db_operation(source):
            return None
        
        method_lower = method_def.method_name.lower()

        # Method name heuristics
        if method_lower.startswith(('find', 'get', 'select', 'query', 'search', 'fetch')):
            return 'SELECT'
        elif method_lower.startswith(('save', 'insert', 'create', 'persist', 'add')):
            return 'INSERT'
        elif method_lower.startswith(('update', 'modify', 'merge', 'edit')):
            return 'UPDATE'
        elif method_lower.startswith(('delete', 'remove')):
            return 'DELETE'

        # Pattern matching
        for op_type, patterns in self.JPA_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, source, re.IGNORECASE):
                    return op_type

        return None
    
    def _has_direct_db_operation(self, source: str) -> bool:
        """
        Check if method directly performs DB operations (not just delegation).
        
        Returns True if method contains direct DB API calls:
        - JdbcTemplate operations
        - EntityManager operations
        - Hibernate Session operations
        - Raw JDBC (PreparedStatement, Statement)
        
        Returns False if method only calls other methods.
        """
        # Patterns for direct DB operations
        direct_db_patterns = [
            # Spring JDBC
            r'jdbcTemplate\.',
            r'namedParameterJdbcTemplate\.',
            
            # JPA EntityManager
            r'entityManager\.(persist|merge|remove|find|createQuery|createNativeQuery)',
            r'\.persist\s*\(',
            r'\.merge\s*\(',
            r'\.remove\s*\(',
            
            # Hibernate Session
            r'session\.(save|update|delete|createQuery|createSQLQuery)',
            
            # Raw JDBC
            r'PreparedStatement',
            r'Statement\.execute',
            r'connection\.(prepareStatement|createStatement)',
            
            # Spring Data repository (direct query annotations)
            r'@Query\s*\(',
            r'@Modifying',
        ]
        
        for pattern in direct_db_patterns:
            if re.search(pattern, source, re.IGNORECASE):
                return True
        
        return False

    def _extract_entity_info(self, method_def: MethodDef, source: str, raw_query: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
        """Extract entity type and table name"""
        entity_type = None
        table_name = None

        # Priority 1: Extract from SQL query if available
        if raw_query and raw_query != "DYNAMIC_SQL":
            # Parse table name from SQL: SELECT FROM table_name, INSERT INTO table_name, UPDATE table_name, DELETE FROM table_name
            sql_patterns = [
                r'FROM\s+([\w.]+)',  # SELECT/DELETE FROM table
                r'INTO\s+([\w.]+)',  # INSERT INTO table
                r'UPDATE\s+([\w.]+)',  # UPDATE table
                r'JOIN\s+([\w.]+)',  # JOIN table (secondary, but useful)
            ]
            for pattern in sql_patterns:
                match = re.search(pattern, raw_query, re.IGNORECASE)
                if match:
                    table_name = match.group(1).strip()
                    # Remove schema prefix if present (e.g., SCHEMA.TABLE -> TABLE)
                    if '.' in table_name:
                        table_name = table_name.split('.')[-1]
                    print(f"          Extracted table from SQL: {table_name}")
                    break
        elif raw_query == "DYNAMIC_SQL":
            print(f"          Dynamic SQL detected - table name cannot be determined statically")
            table_name = "DYNAMIC_TABLE"

        # Priority 2: From return type
        if not table_name and 'Entity' in method_def.return_type:
            entity_type = method_def.return_type.replace('Entity', '')
            table_name = self._entity_to_table(entity_type)
            print(f"          Inferred table from Entity return type: {table_name}")

        # Priority 3: From JPQL query in source
        if not table_name:
            query_match = re.search(r'FROM\s+(\w+)', source, re.IGNORECASE)
            if query_match:
                entity_type = query_match.group(1)
                table_name = self._entity_to_table(entity_type)
                print(f"          Inferred table from JPQL query: {table_name}")

        # Priority 4: From EntityManager.find()
        if not table_name:
            find_match = re.search(r'\.find\(\s*(\w+)\.class', source)
            if find_match:
                entity_type = find_match.group(1)
                table_name = self._entity_to_table(entity_type)
                print(f"          Inferred table from EntityManager.find(): {table_name}")

        # Priority 5: Infer from return type (even non-Entity classes)
        if not table_name and method_def.return_type:
            # Extract simple class name from return type
            return_type_simple = method_def.return_type.split('.')[-1]
            
            # Remove generic type parameters: List<String> -> List
            return_type_simple = re.sub(r'<.*>', '', return_type_simple)
            
            # Exclude common Java types that are not table names
            java_types = ['List', 'Set', 'Map', 'Collection', 'String', 'Integer', 'Long', 
                         'Double', 'Float', 'Boolean', 'Object', 'void', 'int', 'long', 
                         'double', 'float', 'boolean', 'byte', 'short', 'char']
            
            if return_type_simple in java_types:
                print(f"          Return type {return_type_simple} is a Java type, not a table - marking as UNKNOWN")
                table_name = "UNKNOWN"
            elif return_type_simple and return_type_simple[0].isupper():
                table_name = self._entity_to_table(return_type_simple)
                print(f"          Inferred table from return type ({return_type_simple}): {table_name}")

        return entity_type, table_name.upper() if table_name else None

    def _extract_query(self, source: str, class_info: ClassInfo = None) -> Optional[str]:
        """Extract SQL/JPQL query including Spring JDBC constant-based queries"""
        # JPA createQuery pattern
        query_match = re.search(r'createQuery\s*\(\s*["\']([^"\']+)["\']', source, re.DOTALL)
        if query_match:
            return query_match.group(1).strip()

        # Spring JDBC inline query pattern: jdbcTemplate.query("SELECT...", ...)
        # Check for string concatenation patterns (+ operator, StringBuilder, String.format)
        jdbc_call = re.search(r'jdbcTemplate\.(query|queryForObject|queryForList|update)\s*\(', source, re.DOTALL)
        if jdbc_call:
            # Extract the SQL parameter (first parameter of the jdbcTemplate call)
            call_start = jdbc_call.end()
            # Look ahead up to 500 chars for the SQL parameter
            snippet = source[call_start:call_start+500]
            
            # Check for concatenation patterns: "..." + ... or ... + "..."
            if re.search(r'["\'][^"\']*["\']\s*\+|\+\s*["\']', snippet):
                print(f"        Detected SQL string concatenation with + operator")
                return "DYNAMIC_SQL"
            
            # Check for String.format or StringBuilder (also indicates dynamic SQL)
            if re.search(r'String\.format|StringBuilder|StringBuffer', snippet):
                print(f"        Detected dynamic SQL generation with String.format/StringBuilder")
                return "DYNAMIC_SQL"
            
            # Normal inline query: jdbcTemplate.query("SELECT...", ...)
            inline_match = re.search(r'^\s*["\']([^"\']+)["\']', snippet)
            if inline_match:
                return inline_match.group(1).strip()

        # Spring JDBC constant reference: jdbcTemplate.query(ConstantClass.CONSTANT_NAME, ...)
        # Handle multi-line calls with whitespace/newlines
        constant_match = re.search(r'jdbcTemplate\.(query|queryForObject|queryForList|update)\s*\(\s*([A-Z][\w.]*)\.([A-Z_][A-Z_0-9]*)\s*[,)]', source, re.DOTALL)
        if constant_match and class_info:
            constant_class = constant_match.group(2)
            constant_name = constant_match.group(3)
            print(f"        Detected constant reference: {constant_class}.{constant_name}")
            resolved_query = self._resolve_sql_constant(constant_class, constant_name, class_info)
            if resolved_query:
                return resolved_query

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
            print(f"        Warning: Could not find source file for constant class {constant_fqn}")
            return None

        # Parse the constant file to find the SQL string
        try:
            with open(constant_source_path, 'r', encoding='utf-8') as f:
                constant_source = f.read()

            # Pattern: public static final String CONSTANT_NAME = "SQL...";
            # Handles multi-line: public static final String CONSTANT_NAME = 
            #                       "SQL...";
            # Use [\s\S]*? to match across newlines (non-greedy)
            pattern = rf'(public\s+)?static\s+final\s+String\s+{re.escape(constant_name)}\s*=\s*\n?\s*"([\s\S]*?)";?'
            match = re.search(pattern, constant_source)
            if match:
                sql_query = match.group(2).strip()
                print(f"         Resolved constant {constant_class}.{constant_name}")
                print(f"          SQL: {sql_query[:80]}..." if len(sql_query) > 80 else f"          SQL: {sql_query}")
                return sql_query

            # Handle multi-line concatenation: "SELECT " + "FROM..." + "WHERE..."
            concat_pattern = rf'(public\s+)?static\s+final\s+String\s+{re.escape(constant_name)}\s*=\s*([\s\S]+?);'
            concat_match = re.search(concat_pattern, constant_source)
            if concat_match:
                sql_expr = concat_match.group(2)
                # Extract all string literals and concatenate
                string_parts = re.findall(r'"([\s\S]*?)"', sql_expr)
                if string_parts:
                    sql_query = ' '.join(part.strip() for part in string_parts)
                    print(f"         Resolved concatenated constant {constant_class}.{constant_name}")
                    print(f"          SQL: {sql_query[:80]}..." if len(sql_query) > 80 else f"          SQL: {sql_query}")
                    return sql_query

            print(f"        Warning: Could not match pattern for {constant_name} in {constant_source_path}")

        except Exception as e:
            print(f"        Warning: Failed to parse constant file {constant_source_path}: {e}")

        return None

    def _find_constant_source_file(self, constant_fqn: str, current_source_path: str) -> Optional[str]:
        """Find the source file for a constant class"""
        # Convert FQN to relative path
        relative_path = constant_fqn.replace('.', '/') + '.java'

        # Start from the current source directory and navigate up to find 'java' or 'src'
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

        # Try parent of source_root (e.g., src/main/java)
        if source_root.parent:
            potential_path = source_root.parent / relative_path
            if potential_path.exists():
                return str(potential_path)

        return None

    @staticmethod
    def _entity_to_table(entity_name: str) -> str:
        """Convert entity name to table name"""
        name = entity_name.replace('Entity', '')
        return re.sub(r'(?<!^)(?=[A-Z])', '_', name).lower()


