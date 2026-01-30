"""
Call Hierarchy Extension for neo4j_direct_step_loader.py

This module extends the existing Spring Batch job definitions (JobDef)
to add call hierarchy analysis starting from the source paths already
extracted by neo4j_direct_step_loader.py

Usage:
    from neo4j_direct_step_loader import parse_directory
    from call_hierarchy_extension import enrich_with_call_hierarchy, load_enriched_to_neo4j
    
    # Parse XML to get JobDef with source paths
    job_defs = parse_directory("SpringProjects")
    
    # Enrich with call hierarchy
    enriched_jobs = enrich_with_call_hierarchy(job_defs)
    
    # Load to Neo4j
    load_enriched_to_neo4j(enriched_jobs, "bolt://localhost:7687", "neo4j", "password")
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path
import re
import javalang
from neo4j import GraphDatabase

# Import from existing module
from neo4j_direct_step_loader import JobDef, StepDef, build_global_bean_map, find_xml_files


@dataclass
class MethodCall:
    """Method invocation within a method"""
    target_class: Optional[str]  # Fully qualified or simple name
    method_name: str
    line_number: int = 0


@dataclass
class MethodDef:
    """Method definition with call hierarchy"""
    class_fqn: str
    method_name: str
    return_type: str
    parameters: List[Tuple[str, str]] = field(default_factory=list)
    modifiers: List[str] = field(default_factory=list)
    calls: List[MethodCall] = field(default_factory=list)
    
    # Attached analysis results at method level
    db_operations: List['DBOperation'] = field(default_factory=list)
    procedure_calls: List['ProcedureCall'] = field(default_factory=list)
    shell_executions: List['ShellScriptExecution'] = field(default_factory=list)
    
    @property
    def signature(self) -> str:
        params = ", ".join([f"{ptype} {pname}" for ptype, pname in self.parameters])
        return f"{self.return_type} {self.method_name}({params})"
    
    @property
    def fqn(self) -> str:
        return f"{self.class_fqn}.{self.method_name}"


@dataclass
class ClassInfo:
    """Java class information"""
    package: str
    class_name: str
    fqn: str
    source_path: str
    implements: List[str] = field(default_factory=list)
    extends: Optional[str] = None
    fields: Dict[str, str] = field(default_factory=dict)  # field_name -> type
    methods: Dict[str, MethodDef] = field(default_factory=dict)  # method_name -> MethodDef
    imports: List[str] = field(default_factory=list)
    called_classes: Set[str] = field(default_factory=set)  # FQNs of classes this class calls


@dataclass
class DBOperation:
    """Database operation extracted from DAO method"""
    operation_type: str  # SELECT, INSERT, UPDATE, DELETE
    table_name: Optional[str]
    entity_type: Optional[str]
    method_fqn: str
    confidence: str = "HIGH"  # HIGH, MEDIUM, LOW
    raw_query: Optional[str] = None


class JavaCallHierarchyParser:
    """Parses Java source files to extract call hierarchy"""
    
    def __init__(self):
        self.classes: Dict[str, ClassInfo] = {}  # fqn -> ClassInfo
        
    def parse_java_file(self, file_path: str) -> Optional[ClassInfo]:
        """Parse a single Java file and extract class info with call hierarchy"""
        if not Path(file_path).exists():
            print(f"  Warning: Source file not found: {file_path}")
            return None
            
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                source = f.read()
            
            tree = javalang.parse.parse(source)
        except Exception as e:
            print(f"  Warning: Failed to parse {file_path}: {e}")
            return None
        
        # Extract package
        package = tree.package.name if tree.package else ""
        
        # Extract imports
        imports = [imp.path for imp in tree.imports] if tree.imports else []
        
        # Helper function to process a class or interface node
        def process_type_declaration(node):
            class_name = node.name
            fqn = f"{package}.{class_name}" if package else class_name
            
            # Extract implements/extends
            implements = []
            extends = None
            if hasattr(node, 'implements') and node.implements:
                implements = [self._resolve_type(imp.name, imports, package) for imp in node.implements]
            if hasattr(node, 'extends') and node.extends:
                # For interfaces, extends can be a list
                if isinstance(node.extends, list):
                    implements.extend([self._resolve_type(ext.name, imports, package) for ext in node.extends])
                else:
                    extends = self._resolve_type(node.extends.name, imports, package)
            
            class_info = ClassInfo(
                package=package,
                class_name=class_name,
                fqn=fqn,
                source_path=file_path,
                implements=implements,
                extends=extends,
                imports=imports
            )
            
            # Extract fields
            # Search for fields directly in this class node's body
            if hasattr(node, 'body') and node.body:
                for item in node.body:
                    if isinstance(item, javalang.tree.FieldDeclaration):
                        field_type = self._get_type_name(item.type)
                        for declarator in item.declarators:
                            class_info.fields[declarator.name] = field_type
            
            # Extract methods with call hierarchy
            # Search for methods directly in this class node's body
            if hasattr(node, 'body') and node.body:
                for item in node.body:
                    if isinstance(item, javalang.tree.MethodDeclaration):
                        method_def = self._parse_method(item, class_info, source)
                        class_info.methods[method_def.method_name] = method_def
            
            self.classes[fqn] = class_info
            return class_info
        
        # Try to find main class
        for path, node in tree.filter(javalang.tree.ClassDeclaration):
            return process_type_declaration(node)
        
        # Try to find interface if no class found
        for path, node in tree.filter(javalang.tree.InterfaceDeclaration):
            return process_type_declaration(node)
        
        return None
    
    def _parse_method(self, method_node, class_info: ClassInfo, source: str) -> MethodDef:
        """Parse method and extract method calls"""
        method_name = method_node.name
        return_type = self._get_type_name(method_node.return_type) if method_node.return_type else "void"
        
        # Extract parameters
        parameters = []
        if method_node.parameters:
            for param in method_node.parameters:
                param_type = self._get_type_name(param.type)
                param_name = param.name
                parameters.append((param_type, param_name))
        
        modifiers = method_node.modifiers or []
        
        # Extract method calls (pass parameters for type resolution)
        method_calls = []
        if method_node.body:
            method_calls = self._extract_method_calls(method_node.body, class_info, parameters)
        
        return MethodDef(
            class_fqn=class_info.fqn,
            method_name=method_name,
            return_type=return_type,
            parameters=parameters,
            modifiers=modifiers,
            calls=method_calls
        )
    
    def _extract_method_calls(self, body_nodes, class_info: ClassInfo, 
                             method_params: List[Tuple[str, str]] = None) -> List[MethodCall]:
        """Extract method invocations from method body"""
        calls = []
        
        if not body_nodes:
            return calls
        
        # Build parameter name -> type mapping
        param_types = {}
        if method_params:
            for param_type, param_name in method_params:
                param_types[param_name] = param_type
        
        # Build local variable name -> type mapping
        local_var_types = {}
        
        def extract_local_variables(node):
            """Extract local variable declarations from the method body"""
            if isinstance(node, javalang.tree.LocalVariableDeclaration):
                var_type = self._get_type_name(node.type)
                for declarator in node.declarators:
                    local_var_types[declarator.name] = var_type
            
            # Recursively search children
            if hasattr(node, 'children'):
                for child in node.children:
                    if child is not None:
                        if isinstance(child, list):
                            for item in child:
                                if item is not None:
                                    extract_local_variables(item)
                        else:
                            extract_local_variables(child)
        
        # First pass: extract all local variable declarations
        for node in body_nodes:
            if node is not None:
                extract_local_variables(node)
        
        # Recursively search for MethodInvocation nodes in the body
        def search_invocations(node):
            if isinstance(node, javalang.tree.MethodInvocation):
                method_name = node.member
                target_class = None
                
                # Try to determine target class from qualifier
                if node.qualifier:
                    qualifier = node.qualifier
                    
                    # Check if it's a field reference
                    if qualifier in class_info.fields:
                        target_class = class_info.fields[qualifier]
                        # Resolve short names to FQN
                        target_class = self._resolve_type(target_class, class_info.imports, class_info.package)
                    # Check if it's a method parameter
                    elif qualifier in param_types:
                        target_class = param_types[qualifier]
                        # Resolve short names to FQN
                        target_class = self._resolve_type(target_class, class_info.imports, class_info.package)
                    # Check if it's a local variable
                    elif qualifier in local_var_types:
                        target_class = local_var_types[qualifier]
                        # Resolve short names to FQN
                        target_class = self._resolve_type(target_class, class_info.imports, class_info.package)
                
                calls.append(MethodCall(
                    target_class=target_class,
                    method_name=method_name,
                    line_number=0
                ))
            
            # Recursively search children
            if hasattr(node, 'children'):
                for child in node.children:
                    if child is not None:
                        if isinstance(child, list):
                            for item in child:
                                if item is not None:
                                    search_invocations(item)
                        else:
                            search_invocations(child)
        
        # Search through all body nodes
        for node in body_nodes:
            if node is not None:
                search_invocations(node)
        
        return calls
    
    def _get_type_name(self, type_node) -> str:
        """Extract type name from type node"""
        if hasattr(type_node, 'name'):
            return type_node.name
        elif hasattr(type_node, 'sub_type'):
            base = type_node.name
            if type_node.sub_type:
                sub = self._get_type_name(type_node.sub_type)
                return f"{base}<{sub}>"
            return base
        return str(type_node)
    
    def _resolve_type(self, simple_name: str, imports: List[str], package: str) -> str:
        """Resolve simple type name to FQN using imports"""
        if '.' in simple_name:
            return simple_name
        
        for imp in imports:
            if imp.endswith('.' + simple_name):
                return imp
        
        return f"{package}.{simple_name}" if package else simple_name
    
    def _is_direct_child(self, class_path, member_path) -> bool:
        """Check if member is direct child of class (not used anymore, kept for compatibility)"""
        if len(member_path) != len(class_path) + 1:
            return False
        # Check that member_path starts with class_path
        for i, node in enumerate(class_path):
            if i >= len(member_path) or member_path[i] != node:
                return False
        return True


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
        entity_type, table_name = self._extract_entity_info(method_def, method_source)
        raw_query = self._extract_query(method_source)
        
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
        
        Returns:
            True if class appears to be a DAO/Repository, False otherwise
        """
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
        """Detect database operation type"""
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
    
    def _extract_entity_info(self, method_def: MethodDef, source: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract entity type and table name"""
        entity_type = None
        table_name = None
        
        # From return type
        if 'Entity' in method_def.return_type:
            entity_type = method_def.return_type.replace('Entity', '')
            table_name = self._entity_to_table(entity_type)
        
        # From JPQL query
        query_match = re.search(r'FROM\s+(\w+)', source, re.IGNORECASE)
        if query_match:
            entity_type = query_match.group(1)
            table_name = self._entity_to_table(entity_type)
        
        # From EntityManager.find()
        find_match = re.search(r'\.find\(\s*(\w+)\.class', source)
        if find_match:
            entity_type = find_match.group(1)
            table_name = self._entity_to_table(entity_type)
        
        return entity_type, table_name.upper() if table_name else None
    
    def _extract_query(self, source: str) -> Optional[str]:
        """Extract SQL/JPQL query"""
        query_match = re.search(r'createQuery\s*\(\s*["\']([^"\']+)["\']', source, re.DOTALL)
        if query_match:
            return query_match.group(1).strip()
        return None
    
    def _extract_method_source(self, file_content: str, method_name: str) -> str:
        """Extract method source from file"""
        pattern = rf'(public|private|protected).*\s+{re.escape(method_name)}\s*\([^)]*\)\s*\{{[^}}]*\}}'
        match = re.search(pattern, file_content, re.DOTALL)
        return match.group(0) if match else ""
    
    @staticmethod
    def _entity_to_table(entity_name: str) -> str:
        """Convert entity name to table name"""
        name = entity_name.replace('Entity', '')
        return re.sub(r'(?<!^)(?=[A-Z])', '_', name).lower()


@dataclass
class ProcedureCall:
    """Oracle/Database stored procedure call"""
    procedure_name: str
    database_type: str  # ORACLE, POSTGRES, MYSQL, etc.
    method_fqn: str
    parameters: List[str] = field(default_factory=list)
    is_function: bool = False  # True if returns value, False for procedure
    confidence: str = "HIGH"  # HIGH, MEDIUM, LOW


class OracleProcedureAnalyzer:
    """Analyzes methods that call Oracle/Database stored procedures"""
    
    # Import patterns that suggest procedure/function calls
    PROCEDURE_IMPORT_PATTERNS = [
        'java.sql.CallableStatement',
        'oracle.jdbc',
        'org.springframework.jdbc.core.CallableStatementCreator',
        'org.springframework.jdbc.core.JdbcTemplate',
        'javax.persistence.StoredProcedureQuery',
        'jakarta.persistence.StoredProcedureQuery',
    ]
    
    # Code patterns for procedure calls
    PROCEDURE_CALL_PATTERNS = {
        'ORACLE': [
            r'\{call\s+(\w+\.?\w*)\s*\(',  # {call schema.procedure_name(
            r'\{\\?\s*call\s+(\w+\.?\w*)\s*\(',  # { call procedure(
            r'createStoredProcedureQuery\s*\(\s*["\'](\w+)["\']',
        ],
        'GENERIC': [
            r'\.prepareCall\s*\(\s*["\'].*call\s+(\w+\.?\w*)',
            r'execute\s*\(\s*["\'].*CALL\s+(\w+\.?\w*)',
        ]
    }
    
    def analyze_method(self, method_def: MethodDef, class_info: ClassInfo) -> Optional[ProcedureCall]:
        """Analyze a method to detect stored procedure calls"""
        # Check if class has procedure-related imports
        if not self._has_procedure_imports(class_info):
            return None
        
        # Read method source
        try:
            with open(class_info.source_path, 'r', encoding='utf-8') as f:
                source = f.read()
            method_source = self._extract_method_source(source, method_def.method_name)
        except:
            method_source = ""
        
        if not method_source:
            return None
        
        # Detect procedure calls
        procedure_name, db_type = self._detect_procedure_call(method_source)
        if not procedure_name:
            return None
        
        # Extract parameters
        parameters = self._extract_parameters(method_source)
        
        # Determine if it's a function (returns value) or procedure
        is_function = 'registerOutParameter' in method_source or 'getInt(' in method_source or 'getString(' in method_source
        
        return ProcedureCall(
            procedure_name=procedure_name,
            database_type=db_type,
            method_fqn=method_def.fqn,
            parameters=parameters,
            is_function=is_function
        )
    
    def _has_procedure_imports(self, class_info: ClassInfo) -> bool:
        """Check if class imports procedure-related packages"""
        if not class_info.imports:
            return False
        
        for import_stmt in class_info.imports:
            for pattern in self.PROCEDURE_IMPORT_PATTERNS:
                if pattern in import_stmt:
                    return True
        return False
    
    def _detect_procedure_call(self, source: str) -> Tuple[Optional[str], str]:
        """Detect procedure name and database type from source"""
        # Check Oracle patterns
        for pattern in self.PROCEDURE_CALL_PATTERNS['ORACLE']:
            match = re.search(pattern, source, re.IGNORECASE)
            if match:
                return match.group(1), 'ORACLE'
        
        # Check generic patterns
        for pattern in self.PROCEDURE_CALL_PATTERNS['GENERIC']:
            match = re.search(pattern, source, re.IGNORECASE)
            if match:
                return match.group(1), 'UNKNOWN'
        
        return None, 'UNKNOWN'
    
    def _extract_parameters(self, source: str) -> List[str]:
        """Extract parameter names/types from procedure call"""
        params = []
        # Look for setString, setInt, setObject calls
        param_pattern = r'\.(set\w+)\s*\(\s*(\d+)\s*,\s*([^)]+)\)'
        matches = re.findall(param_pattern, source)
        for method, index, value in matches:
            params.append(f"{index}:{method}={value.strip()}")
        return params
    
    def _extract_method_source(self, file_content: str, method_name: str) -> str:
        """Extract method source from file"""
        pattern = rf'(public|private|protected).*\s+{re.escape(method_name)}\s*\([^)]*\)\s*\{{[^}}]*\}}'
        match = re.search(pattern, file_content, re.DOTALL)
        return match.group(0) if match else ""


@dataclass
class ShellScriptExecution:
    """Shell script execution detected in code"""
    script_name: Optional[str]
    method_fqn: str
    script_type: str  # BASH, SHELL, PYTHON, POWERSHELL, etc.
    arguments: List[str] = field(default_factory=list)
    execution_method: str = ""  # Runtime.exec, ProcessBuilder, etc.
    confidence: str = "HIGH"


class ShellScriptAnalyzer:
    """Analyzes methods that execute shell scripts"""
    
    # Import patterns for shell script execution
    SHELL_IMPORT_PATTERNS = [
        'java.lang.Runtime',
        'java.lang.ProcessBuilder',
        'java.lang.Process',
        'org.apache.commons.exec',
        'org.springframework.util.exec',
    ]
    
    # Code patterns for shell execution
    SHELL_EXECUTION_PATTERNS = [
        (r'Runtime\.getRuntime\(\)\.exec\s*\(\s*["\']([^"\']+)["\']', 'Runtime.exec'),
        (r'new\s+ProcessBuilder\s*\(\s*["\']([^"\']+)["\']', 'ProcessBuilder'),
        (r'\.execute\s*\(\s*["\']([^"\']+)["\']', 'Commons Exec'),
        (r'\.sh\s+([^\s;]+)', 'Shell script'),
        (r'\.bash\s+([^\s;]+)', 'Bash script'),
    ]
    
    def analyze_method(self, method_def: MethodDef, class_info: ClassInfo) -> Optional[ShellScriptExecution]:
        """Analyze a method to detect shell script execution"""
        # Check class name heuristics
        name_lower = class_info.class_name.lower()
        is_shell_related = 'shell' in name_lower or 'script' in name_lower or 'command' in name_lower
        
        # Check imports
        has_shell_imports = self._has_shell_imports(class_info)
        
        if not is_shell_related and not has_shell_imports:
            return None
        
        # Read method source
        try:
            with open(class_info.source_path, 'r', encoding='utf-8') as f:
                source = f.read()
            method_source = self._extract_method_source(source, method_def.method_name)
        except:
            method_source = ""
        
        if not method_source:
            return None
        
        # Detect shell execution
        script_name, execution_method = self._detect_shell_execution(method_source)
        if not script_name and not execution_method:
            return None
        
        # Determine script type
        script_type = self._determine_script_type(script_name if script_name else method_source)
        
        # Extract arguments
        arguments = self._extract_arguments(method_source)
        
        return ShellScriptExecution(
            script_name=script_name,
            method_fqn=method_def.fqn,
            script_type=script_type,
            arguments=arguments,
            execution_method=execution_method
        )
    
    def _has_shell_imports(self, class_info: ClassInfo) -> bool:
        """Check if class imports shell execution packages"""
        if not class_info.imports:
            return False
        
        for import_stmt in class_info.imports:
            for pattern in self.SHELL_IMPORT_PATTERNS:
                if pattern in import_stmt:
                    return True
        return False
    
    def _detect_shell_execution(self, source: str) -> Tuple[Optional[str], str]:
        """Detect shell script execution from source"""
        for pattern, method in self.SHELL_EXECUTION_PATTERNS:
            match = re.search(pattern, source, re.IGNORECASE)
            if match:
                script_name = match.group(1) if match.groups() else None
                return script_name, method
        
        return None, ""
    
    def _determine_script_type(self, script_info: str) -> str:
        """Determine script type from name or content"""
        script_info_lower = script_info.lower()
        
        if '.sh' in script_info_lower or 'bash' in script_info_lower:
            return 'BASH'
        elif '.py' in script_info_lower or 'python' in script_info_lower:
            return 'PYTHON'
        elif '.ps1' in script_info_lower or 'powershell' in script_info_lower:
            return 'POWERSHELL'
        elif '.bat' in script_info_lower or '.cmd' in script_info_lower:
            return 'BATCH'
        else:
            return 'SHELL'
    
    def _extract_arguments(self, source: str) -> List[str]:
        """Extract script arguments from source"""
        args = []
        # Look for string array or varargs patterns
        array_pattern = r'new\s+String\[\]\s*\{([^}]+)\}'
        match = re.search(array_pattern, source)
        if match:
            args_str = match.group(1)
            args = [arg.strip().strip('"\'') for arg in args_str.split(',')]
        return args
    
    def _extract_method_source(self, file_content: str, method_name: str) -> str:
        """Extract method source from file"""
        pattern = rf'(public|private|protected).*\s+{re.escape(method_name)}\s*\([^)]*\)\s*\{{[^}}]*\}}'
        match = re.search(pattern, file_content, re.DOTALL)
        return match.group(0) if match else ""


def enrich_with_call_hierarchy(job_defs: List[JobDef], global_bean_map: Dict[str, tuple[str, str]] = None) -> List[JobDef]:
    """
    Enrich existing JobDef objects with call hierarchy information.
    This extends the JobDef with parsed Java class and method information.
    
    Args:
        job_defs: List of JobDef objects from XML parsing
        global_bean_map: Dict mapping bean_id -> (class_name, source_path) from build_global_bean_map()
    """
    parser = JavaCallHierarchyParser()
    dao_analyzer = DAOAnalyzer()
    procedure_analyzer = OracleProcedureAnalyzer()
    shell_analyzer = ShellScriptAnalyzer()
    
    print("\n" + "=" * 80)
    print("Enriching Jobs with Call Hierarchy")
    print("=" * 80)
    
    all_classes = {}
    all_db_operations = []
    all_procedure_calls = []
    all_shell_executions = []
    
    # Parse XML dependencies to build field -> bean mapping
    bean_dependencies = _parse_bean_dependencies_from_jobs(job_defs)
    print(f"  Extracted {len(bean_dependencies)} bean dependencies from XML")
    
    for job in job_defs:
        print(f"\nProcessing Job: {job.name}")
        
        for step_name, step in job.steps.items():
            print(f"  Step: {step_name} ({step.step_kind})")
            
            if step.step_kind == "TASKLET" and step.class_source_path:
                # Parse tasklet class
                print(f"    Parsing Tasklet: {step.class_source_path}")
                class_info = parser.parse_java_file(step.class_source_path)
                if class_info:
                    # Apply XML dependencies to resolve field types
                    _apply_bean_dependencies(class_info, step.impl_bean, bean_dependencies, global_bean_map)
                    all_classes[class_info.fqn] = class_info
                    # Analyze execute method
                    if 'execute' in class_info.methods:
                        print(f"      Found execute() with {len(class_info.methods['execute'].calls)} method calls")
            
            elif step.step_kind == "CHUNK":
                # Parse reader
                if step.reader_source_path:
                    print(f"    Parsing Reader: {step.reader_source_path}")
                    class_info = parser.parse_java_file(step.reader_source_path)
                    if class_info:
                        _apply_bean_dependencies(class_info, step.reader_bean, bean_dependencies, global_bean_map)
                        all_classes[class_info.fqn] = class_info
                
                # Parse processor
                if step.processor_source_path:
                    print(f"    Parsing Processor: {step.processor_source_path}")
                    class_info = parser.parse_java_file(step.processor_source_path)
                    if class_info:
                        _apply_bean_dependencies(class_info, step.processor_bean, bean_dependencies, global_bean_map)
                        all_classes[class_info.fqn] = class_info
                
                # Parse writer
                if step.writer_source_path:
                    print(f"    Parsing Writer: {step.writer_source_path}")
                    class_info = parser.parse_java_file(step.writer_source_path)
                    if class_info:
                        _apply_bean_dependencies(class_info, step.writer_bean, bean_dependencies, global_bean_map)
                        all_classes[class_info.fqn] = class_info
    
    # RECURSIVE parsing: Parse all referenced classes until no new classes found
    print("\n" + "=" * 80)
    print("Recursively Parsing Referenced Classes (Services, DAOs, etc.)")
    print("=" * 80)
    
    iteration = 1
    while True:
        print(f"\n  Iteration {iteration}:")
        classes_to_parse = set()
        
        # Find all referenced classes that haven't been parsed yet
        for class_info in all_classes.values():
            for method_def in class_info.methods.values():
                for call in method_def.calls:
                    if call.target_class and call.target_class not in all_classes and call.target_class.startswith('com.'):
                        classes_to_parse.add(call.target_class)
        
        if not classes_to_parse:
            print(f"    No new classes to parse. Stopping.")
            break
        
        print(f"    Found {len(classes_to_parse)} new classes to parse")
        
        # Try to find and parse these classes using global_bean_map first
        newly_parsed = 0
        for class_fqn in classes_to_parse:
            # Try global_bean_map first (most reliable)
            source_path = _find_source_from_bean_map(class_fqn, global_bean_map)
            
            # Fallback to scanning source directories
            if not source_path:
                source_path = _find_java_source_by_fqn(class_fqn, job_defs)
            
            if source_path:
                print(f"      Parsing: {class_fqn}")
                class_info = parser.parse_java_file(source_path)
                if class_info:
                    # Check if this class has bean dependencies from XML
                    bean_id = _find_bean_id_by_class(class_fqn, global_bean_map)
                    if bean_id:
                        _apply_bean_dependencies(class_info, bean_id, bean_dependencies, global_bean_map)
                    all_classes[class_info.fqn] = class_info
                    newly_parsed += 1
            else:
                print(f"      Warning: Source not found for {class_fqn}")
        
        print(f"    Successfully parsed {newly_parsed} new classes")
        
        if newly_parsed == 0:
            break
        
        iteration += 1
        
        if iteration > 10:  # Safety limit
            print(f"    Reached maximum iteration limit (10). Stopping.")
            break
    
    # Analyze DAO methods
    print("\n" + "=" * 80)
    print("Analyzing DAO Methods")
    print("=" * 80)
    
    for class_info in all_classes.values():
        if dao_analyzer._is_dao_class(class_info):
            print(f"  DAO Class: {class_info.class_name}")
            for method_def in class_info.methods.values():
                db_op = dao_analyzer.analyze_method(method_def, class_info)
                if db_op:
                    all_db_operations.append(db_op)
                    print(f"    {method_def.method_name}() -> {db_op.operation_type} {db_op.table_name or '?'}")
    
    # Analyze Oracle/Database stored procedures
    print("\n" + "=" * 80)
    print("Analyzing Stored Procedure Calls")
    print("=" * 80)
    
    for class_info in all_classes.values():
        for method_def in class_info.methods.values():
            proc_call = procedure_analyzer.analyze_method(method_def, class_info)
            if proc_call:
                all_procedure_calls.append(proc_call)
                proc_type = "Function" if proc_call.is_function else "Procedure"
                print(f"  {class_info.class_name}.{method_def.method_name}() -> {proc_call.database_type} {proc_type}: {proc_call.procedure_name}")
    
    # Analyze shell script executions
    print("\n" + "=" * 80)
    print("Analyzing Shell Script Executions")
    print("=" * 80)
    
    for class_info in all_classes.values():
        for method_def in class_info.methods.values():
            shell_exec = shell_analyzer.analyze_method(method_def, class_info)
            if shell_exec:
                all_shell_executions.append(shell_exec)
                script_display = shell_exec.script_name if shell_exec.script_name else "[dynamic]"
                print(f"  {class_info.class_name}.{method_def.method_name}() -> {shell_exec.script_type} script: {script_display} ({shell_exec.execution_method})")
    
    # Store enrichment data (we'll add this to JobDef or return separately)
    print("\n" + "=" * 80)
    print("Enrichment Summary")
    print("=" * 80)
    print(f"  Total Classes Parsed: {len(all_classes)}")
    print(f"  Total Methods: {sum(len(c.methods) for c in all_classes.values())}")
    print(f"  Total DB Operations: {len(all_db_operations)}")
    print(f"  Total Procedure Calls: {len(all_procedure_calls)}")
    print(f"  Total Shell Script Executions: {len(all_shell_executions)}")
    
    # Attach enrichment data to job_defs (or return separately)
    # For now, we'll attach as custom attributes
    for job in job_defs:
        if not hasattr(job, 'enrichment'):
            job.enrichment = {}
        job.enrichment['classes'] = all_classes
        job.enrichment['db_operations'] = all_db_operations
        job.enrichment['procedure_calls'] = all_procedure_calls
        job.enrichment['shell_executions'] = all_shell_executions
    
    return job_defs


def _parse_bean_dependencies_from_jobs(job_defs: List[JobDef]) -> Dict[str, Dict[str, str]]:
    """
    Parse XML files to extract bean dependencies (property injections).
    Returns: Dict[bean_id, Dict[property_name, ref_bean_id]]
    """
    import xml.etree.ElementTree as ET
    
    bean_deps = {}
    xml_files = set()
    
    # Collect all unique XML files from jobs
    for job in job_defs:
        if job.source_file:
            xml_files.add(job.source_file)
            # Also add the directory to search for applicationContext.xml
            xml_dir = Path(job.source_file).parent.parent.parent.parent  # Go up to spring directory
            # Find all XML files in that directory tree
            for xml_path in Path(xml_dir).rglob('*.xml'):
                xml_files.add(str(xml_path))
    
    # Parse each XML to extract bean properties
    for xml_file in xml_files:
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            ns = {'beans': 'http://www.springframework.org/schema/beans'}
            
            for bean in root.findall('.//beans:bean', ns):
                bean_id = bean.get('id')
                if not bean_id:
                    continue
                
                bean_deps[bean_id] = {}
                
                # Extract property references
                for prop in bean.findall('beans:property', ns):
                    prop_name = prop.get('name')
                    ref_bean = prop.get('ref')
                    if prop_name and ref_bean:
                        bean_deps[bean_id][prop_name] = ref_bean
                
                # Extract constructor-arg references
                for arg in bean.findall('beans:constructor-arg', ns):
                    ref_bean = arg.get('ref')
                    arg_name = arg.get('name')
                    if ref_bean:
                        # Use name if available, otherwise use index
                        key = arg_name if arg_name else f"constructor_arg_{arg.get('index', '0')}"
                        bean_deps[bean_id][key] = ref_bean
        
        except Exception as e:
            print(f"  Warning: Failed to parse dependencies from {xml_file}: {e}")
    
    return bean_deps


def _apply_bean_dependencies(class_info: ClassInfo, bean_id: str, 
                            bean_dependencies: Dict[str, Dict[str, str]],
                            global_bean_map: Dict[str, tuple[str, str]] = None):
    """
    Apply XML bean dependencies to resolve field types more accurately.
    Updates class_info.fields with fully qualified class names from XML bean references.
    Also updates method calls that reference these fields to use the concrete implementation class.
    """
    if not bean_id or bean_id not in bean_dependencies:
        return
    
    deps = bean_dependencies[bean_id]
    field_mappings = {}  # Track old_type -> new_type mappings
    
    for field_name, ref_bean_id in deps.items():
        # Find the actual class name for the referenced bean
        if global_bean_map and ref_bean_id in global_bean_map:
            ref_class_tuple = global_bean_map[ref_bean_id]
            ref_class_name = ref_class_tuple[0]  # Extract class name from tuple (class_name, source_path)
            # Update the field type with the concrete class
            if field_name in class_info.fields:
                old_type = class_info.fields[field_name]
                class_info.fields[field_name] = ref_class_name
                field_mappings[field_name] = (old_type, ref_class_name)
                print(f"        Resolved field '{field_name}' -> {ref_class_name} (from XML)")
    
    # Update method calls to use the new concrete class types
    if field_mappings:
        _update_method_call_targets(class_info, field_mappings)


def _update_method_call_targets(class_info: ClassInfo, field_mappings: Dict[str, Tuple[str, str]]):
    """
    Update method call target_class to use concrete implementation classes from XML.
    
    Args:
        class_info: The ClassInfo object whose methods need updating
        field_mappings: Dict mapping field_name -> (old_type, new_type)
    """
    updated_count = 0
    for method_def in class_info.methods.values():
        for call in method_def.calls:
            # Check if this call's target_class matches any old field type
            if call.target_class:
                for field_name, (old_type, new_type) in field_mappings.items():
                    # Match both simple name and FQN
                    # The old_type might be a simple name (e.g., 'OrderDAO')
                    # but call.target_class is the FQN (e.g., 'com.companyname.dao.OrderDAO')
                    if call.target_class == old_type or call.target_class.endswith('.' + old_type):
                        call.target_class = new_type
                        updated_count += 1
                        break
    if updated_count > 0:
        print(f"        Updated {updated_count} method call(s) to use concrete implementation classes")


def _find_source_from_bean_map(class_fqn: str, global_bean_map: Dict[str, tuple[str, str]]) -> Optional[str]:
    """
    Find source path from global_bean_map by matching class FQN.
    The global_bean_map from neo4j_direct_step_loader already has source paths.
    """
    if not global_bean_map:
        return None
    
    # global_bean_map format: bean_id -> (class_name, source_path)
    # We need to check if any bean_class matches our class_fqn
    for bean_id, (bean_class, source_path) in global_bean_map.items():
        if bean_class == class_fqn:
            # Return the source path if it exists
            if source_path:
                return source_path
    
    return None


def _find_bean_id_by_class(class_fqn: str, global_bean_map: Dict[str, tuple[str, str]]) -> Optional[str]:
    """Find bean ID for a given class FQN from global_bean_map"""
    if not global_bean_map:
        return None
    
    for bean_id, (bean_class, source_path) in global_bean_map.items():
        # Match by class FQN
        if bean_class == class_fqn:
            return bean_id
    
    return None


def _find_java_source_by_fqn(fqn: str, job_defs: List[JobDef]) -> Optional[str]:
    """Try to find Java source file based on fully qualified name (FALLBACK)"""
    # Extract expected file path from FQN
    # e.g., com.company.service.CustomerService -> com/company/service/CustomerService.java
    file_path_parts = fqn.split('.')
    expected_path = '/'.join(file_path_parts) + '.java'
    
    # Search in source directories from job_defs
    for job in job_defs:
        for step in job.steps.values():
            for source_path in [step.class_source_path, step.reader_source_path, 
                               step.processor_source_path, step.writer_source_path]:
                if source_path:
                    # Get the base source directory
                    source_dir = Path(source_path).parent
                    while source_dir and source_dir.name not in ['java', 'src']:
                        source_dir = source_dir.parent
                    
                    if source_dir:
                        potential_path = source_dir / expected_path
                        if potential_path.exists():
                            return str(potential_path)
    
    return None


def load_enriched_to_neo4j(job_defs: List[JobDef], uri: str, user: str, password: str):
    """
    Load enriched job definitions to Neo4j, including call hierarchy
    """
    driver = GraphDatabase.driver(uri, auth=(user, password))
    
    print("\n" + "=" * 80)
    print("Loading to Neo4j")
    print("=" * 80)
    
    
    # Parse XML to get JobDef with source paths (already existing functionality)
    xml_directory = "SpringProjects"
    
    # Build global bean map (same as in parse_directory)
    xml_files = find_xml_files(xml_directory)
    global_bean_map = build_global_bean_map(xml_files, xml_directory)
    
    # Parse directory to get JobDefs
    job_defs = parse_directory(xml_directory)
    
    # Enrich with call hierarchy (new functionality) - pass global_bean_map
    enriched_jobs = enrich_with_call_hierarchy(job_defs, global_bean_map)
    
    with driver.session() as session:
        session.run("CREATE INDEX IF NOT EXISTS FOR (m:JavaMethod) ON (m.fqn)")
        session.run("CREATE INDEX IF NOT EXISTS FOR (d:DBOperation) ON (d.method_fqn)")
        
        for job in job_defs:
            if not hasattr(job, 'enrichment'):
                continue
            
            print(f"\nLoading Job: {job.name}")
            classes = job.enrichment.get('classes', {})
            db_operations = job.enrichment.get('db_operations', [])
            
            # Load classes and methods
            for class_info in classes.values():
                print(f"  Loading class: {class_info.class_name}")
                session.run("""
                    MERGE (c:JavaClass {fqn: $fqn})
                    SET c.name = $name,
                        c.package = $package,
                        c.source_path = $source_path
                """, fqn=class_info.fqn, name=class_info.class_name,
                     package=class_info.package, source_path=class_info.source_path)
                
                # Load methods
                for method_def in class_info.methods.values():
                    session.run("""
                        MATCH (c:JavaClass {fqn: $class_fqn})
                        MERGE (m:JavaMethod {fqn: $method_fqn})
                        SET m.name = $name,
                            m.return_type = $return_type,
                            m.signature = $signature
                        MERGE (c)-[:HAS_METHOD]->(m)
                    """, class_fqn=class_info.fqn, method_fqn=method_def.fqn,
                         name=method_def.method_name, return_type=method_def.return_type,
                         signature=method_def.signature)
                    
                    # Create INVOKES relationships
                    for call in method_def.calls:
                        if call.target_class:
                            target_fqn = f"{call.target_class}.{call.method_name}"
                        else:
                            target_fqn = f"{class_info.fqn}.{call.method_name}"
                        
                        session.run("""
                            MATCH (m1:JavaMethod {fqn: $source_fqn})
                            MERGE (m2:JavaMethod {fqn: $target_fqn})
                            MERGE (m1)-[:INVOKES]->(m2)
                        """, source_fqn=method_def.fqn, target_fqn=target_fqn)
            
            # Load DB operations
            for db_op in db_operations:
                print(f"  Loading DB operation: {db_op.operation_type} on {db_op.table_name}")
                session.run("""
                    MERGE (d:DBOperation {
                        method_fqn: $method_fqn,
                        operation_type: $operation_type
                    })
                    SET d.table_name = $table_name,
                        d.entity_type = $entity_type,
                        d.confidence = $confidence
                    WITH d
                    MATCH (m:JavaMethod {fqn: $method_fqn})
                    MERGE (m)-[:PERFORMS_DB_OPERATION]->(d)
                """, method_fqn=db_op.method_fqn, operation_type=db_op.operation_type,
                     table_name=db_op.table_name, entity_type=db_op.entity_type,
                     confidence=db_op.confidence)
            
            # Link Steps to JavaClass
            for step_name, step in job.steps.items():
                if step.step_kind == "TASKLET" and step.class_name:
                    session.run("""
                        MATCH (s:Step {name: $step_name})
                        MATCH (c:JavaClass {fqn: $class_fqn})
                        MERGE (s)-[:IMPLEMENTED_BY]->(c)
                    """, step_name=step_name, class_fqn=step.class_name)
                
                elif step.step_kind == "CHUNK":
                    if step.reader_class:
                        session.run("""
                            MATCH (s:Step {name: $step_name})
                            MATCH (c:JavaClass {fqn: $class_fqn})
                            MERGE (s)-[:USES_READER]->(c)
                        """, step_name=step_name, class_fqn=step.reader_class)
                    if step.writer_class:
                        session.run("""
                            MATCH (s:Step {name: $step_name})
                            MATCH (c:JavaClass {fqn: $class_fqn})
                            MERGE (s)-[:USES_WRITER]->(c)
                        """, step_name=step_name, class_fqn=step.writer_class)
                    if step.processor_class:
                        session.run("""
                            MATCH (s:Step {name: $step_name})
                            MATCH (c:JavaClass {fqn: $class_fqn})
                            MERGE (s)-[:USES_PROCESSOR]->(c)
                        """, step_name=step_name, class_fqn=step.processor_class)
    
    driver.close()
    print("\n✅ Load complete!")


if __name__ == '__main__':
    # Example usage
    from neo4j_direct_step_loader import parse_directory
    
    # Parse XML to get JobDef with source paths (already existing functionality)
    job_defs, global_bean_map = parse_directory("SpringProjects")
    
    # Enrich with call hierarchy (new functionality)
    enriched_jobs = enrich_with_call_hierarchy(job_defs, global_bean_map)
    
    # Load to Neo4j (extended with call hierarchy)
    #load_enriched_to_neo4j(
    #    enriched_jobs,
    #    uri="bolt://localhost:7687",
    #    user="neo4j",
    #    password="Rohit@123"
    #)
