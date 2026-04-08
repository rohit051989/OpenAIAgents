from classes.DataClasses import ClassInfo, MethodCall, MethodDef

import javalang
try:
    from tree_sitter import Language, Parser
    import tree_sitter_java as tsjava
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False


from pathlib import Path
from typing import Dict, List, Tuple, Optional
import re
import yaml

import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - [%(pathname)s:%(lineno)d %(funcName)s] - %(message)s"
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level config loading — resolved once at import time.
# All JavaCallHierarchyParser instances share the same mode so that every
# caller (enrichers, tests, builder) automatically picks up the project
# setting without having to pass anything to the constructor.
# ---------------------------------------------------------------------------
def _load_parser_mode() -> str:
    """Read java_parser_mode from information_graph_config.yaml.

    Falls back to 'javalang_with_treesitter_fallback' if the file cannot be
    read or the key is absent.
    """
    config_file = Path(__file__).parent.parent / "config" / "information_graph_config.yaml"
    try:
        with open(config_file, 'r', encoding='utf-8') as _f:
            _cfg = yaml.safe_load(_f)
        mode = _cfg.get('scan_options', {}).get(
            'java_parser_mode', 'javalang_with_treesitter_fallback')
        return mode
    except Exception:
        return 'javalang_with_treesitter_fallback'

_DEFAULT_PARSER_MODE: str = _load_parser_mode()


class JavaCallHierarchyParser:
    """Parses Java source files to extract call hierarchy.

    The parser mode is read automatically from
    ``config/information_graph_config.yaml`` (``scan_options.java_parser_mode``).
    Valid values:

    * ``"javalang_with_treesitter_fallback"`` (default) — JavaLang is the
      primary parser; TreeSitter is tried automatically when JavaLang cannot
      handle the file (e.g. Java 16+ records / sealed classes).  Preserves
      maximum edge-case coverage.
    * ``"treesitter_only"`` — always use TreeSitter.  Uniform behaviour
      across all Java versions; all edge cases must be handled in the
      TreeSitter code path.

    The optional *parser_mode* constructor argument can still be supplied to
    override the config value (useful in tests).
    """

    VALID_PARSER_MODES = frozenset({
        "javalang_with_treesitter_fallback",
        "treesitter_only",
    })

    def __init__(self, parser_mode: Optional[str] = None):
        # Use explicit override, else fall back to the config-loaded default.
        resolved_mode = parser_mode if parser_mode is not None else _DEFAULT_PARSER_MODE
        if resolved_mode not in self.VALID_PARSER_MODES:
            raise ValueError(
                f"Unknown parser_mode '{resolved_mode}'. "
                f"Valid values: {sorted(self.VALID_PARSER_MODES)}"
            )
        self.parser_mode = resolved_mode
        self.classes: Dict[str, ClassInfo] = {}  # fqn -> ClassInfo
        # Initialize tree-sitter parser if available
        if TREE_SITTER_AVAILABLE:
            try:
                JAVA_LANGUAGE = Language(tsjava.language())
                self.ts_parser = Parser(JAVA_LANGUAGE)
            except Exception as e:
                logger.info(f"  Warning: Could not initialize tree-sitter: {e}")
                self.ts_parser = None
        else:
            self.ts_parser = None
        logger.info(f"  JavaCallHierarchyParser initialised: parser_mode='{self.parser_mode}'")

    def parse_java_file(self, file_path: str) -> Optional[ClassInfo]:
        """Parse a single Java file and extract class info with call hierarchy.

        The parser engine used depends on ``self.parser_mode``:
        - ``"javalang_with_treesitter_fallback"``: tries JavaLang first; if JavaLang
          raises any exception the file is re-parsed with TreeSitter.
        - ``"treesitter_only"``: skips JavaLang entirely and uses TreeSitter directly.
        """
        if not Path(file_path).exists():
            logger.info(f"  Warning: Source file not found: {file_path}")
            return None

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                source = f.read()
        except Exception as e:
            logger.warning(f"  Warning: Could not read {file_path}: {e}")
            return None

        # ── TreeSitter-only mode ──────────────────────────────────────────────
        if self.parser_mode == "treesitter_only":
            if not self.ts_parser:
                logger.warning(
                    f"  parser_mode='treesitter_only' but TreeSitter is not available. "
                    f"Install tree-sitter-java. File skipped: {file_path}"
                )
                return None
            try:
                result = self._parse_with_tree_sitter(file_path, source)
                if result:
                    logger.info(f"  [treesitter_only] Parsed: {file_path}")
                else:
                    logger.info(f"  [treesitter_only] No class found in: {file_path}")
                return result
            except Exception as ts_error:
                logger.warning(
                    f"  [treesitter_only] TreeSitter failed for {file_path}: "
                    f"{type(ts_error).__name__}: {str(ts_error)[:150]}"
                )
                return None

        # ── JavaLang-primary with TreeSitter fallback (default) ───────────────
        try:
            tree = javalang.parse.parse(source)
        except Exception as e:
            # Javalang failed - try tree-sitter for modern Java syntax
            error_msg = f"{type(e).__name__}: {str(e)}" if str(e) else type(e).__name__
            logger.info(f"  Warning: javalang failed to parse {file_path}")
            logger.info(f"           Reason: {error_msg[:150]}")
            
            if self.ts_parser:
                logger.info(f"           Attempting tree-sitter fallback parser...")
                try:
                    result = self._parse_with_tree_sitter(file_path, source)
                    if result:
                        logger.info(f"            Successfully parsed with tree-sitter")
                        return result
                except Exception as ts_error:
                    logger.info(f"           ✗ tree-sitter also failed: {type(ts_error).__name__}: {str(ts_error)[:100]}")
            else:
                logger.info(f"           Note: Install tree-sitter-java for modern Java syntax support")
                logger.info(f"                 pip install tree-sitter tree-sitter-java")
            
            logger.info(f"           File will be created as a regular file node, not a JavaClass")
            return None

        # Extract package
        package = tree.package.name if tree.package else ""

        # Extract imports
        imports = [imp.path for imp in tree.imports] if tree.imports else []

        # Helper function to process a class or interface node
        def process_type_declaration(node, is_interface=False):
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
            
            logger.info(f"  Parsed with JavaLang to identify the respective implementation for : {fqn} (extends: {extends}, implements: {implements})")
            class_info = ClassInfo(
                package=package,
                class_name=class_name,
                fqn=fqn,
                source_path=file_path,
                implements=implements,
                extends=extends,
                is_interface=is_interface,
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
                        class_info.methods[method_def.method_key] = method_def

            self.classes[fqn] = class_info
            return class_info

        # Try to find main class
        for path, node in tree.filter(javalang.tree.ClassDeclaration):
            return process_type_declaration(node, is_interface=False)

        # Try to find interface if no class found
        for path, node in tree.filter(javalang.tree.InterfaceDeclaration):
            return process_type_declaration(node, is_interface=True)

        return None

    def _parse_with_tree_sitter(self, file_path: str, source: str) -> Optional[ClassInfo]:
        """
        Parse Java file using tree-sitter (fallback for modern Java syntax).
        This provides basic class structure without deep analysis.
        """
        if not self.ts_parser:
            return None
        
        tree = self.ts_parser.parse(bytes(source, "utf8"))
        root_node = tree.root_node
        
        # Extract package
        package = ""
        package_node = self._ts_find_child_by_type(root_node, "package_declaration")
        if package_node:
            package_name_node = self._ts_find_child_by_type(package_node, "scoped_identifier")
            if not package_name_node:
                package_name_node = self._ts_find_child_by_type(package_node, "identifier")
            if package_name_node:
                package = self._ts_get_text(package_name_node, source)
        
        # Extract imports
        imports = []
        for import_node in self._ts_find_children_by_type(root_node, "import_declaration"):
            import_text = self._ts_get_text(import_node, source)
            # Extract just the imported class path
            match = re.search(r'import\s+(?:static\s+)?([a-zA-Z0-9_.]+)', import_text)
            if match:
                imports.append(match.group(1))
        
        # Find class or interface declaration
        class_node = self._ts_find_child_by_type(root_node, "class_declaration")
        is_interface = False
        if not class_node:
            class_node = self._ts_find_child_by_type(root_node, "interface_declaration")
            is_interface = True
        
        if not class_node:
            return None
        
        # Extract class name
        class_name = ""
        name_node = self._ts_find_child_by_type(class_node, "identifier")
        if name_node:
            class_name = self._ts_get_text(name_node, source)

        if(class_name == "BatchJobDaoImpl"):
            logger.info(f"  Debug: Found class declaration for {class_name} in {file_path}")
        
        fqn = f"{package}.{class_name}" if package else class_name
        
        # Extract extends and implements
        extends = None
        implements = []
        
        # Handle extends/superclass
        superclass_node = self._ts_find_child_by_type(class_node, "superclass")
        if superclass_node:
            # Try different type nodes (type_identifier, generic_type, scoped_type_identifier)
            type_node = self._ts_find_child_by_type(superclass_node, "type_identifier")
            if not type_node:
                type_node = self._ts_find_child_by_type(superclass_node, "scoped_type_identifier")
            if not type_node:
                # For generic types like SomeClass<T>, get the base type
                generic_node = self._ts_find_child_by_type(superclass_node, "generic_type")
                if generic_node:
                    type_node = self._ts_find_child_by_type(generic_node, "type_identifier")
            if type_node:
                extends_name = self._ts_get_text(type_node, source)
                # Resolve to FQN using imports and package
                extends = self._resolve_type(extends_name, imports, package)
        
        # Handle implements/super_interfaces (IMPROVED for complex syntax)
        interfaces_node = self._ts_find_child_by_type(class_node, "super_interfaces")
        if interfaces_node:
            # Get all type-related children (type_identifier, scoped_type_identifier, generic_type)
            for child in interfaces_node.children:
                interface_name = None
                
                if child.type == "type_identifier":
                    interface_name = self._ts_get_text(child, source)
                elif child.type == "type_list":
                    for type_child in child.children:
                        if type_child.type == "type_identifier":
                            interface_name = self._ts_get_text(type_child, source)
                            # Resolve to FQN and add
                            implements.append(self._resolve_type(interface_name, imports, package))
                            interface_name = None  # Reset after adding
                        elif type_child.type == "scoped_type_identifier":
                            interface_name = self._ts_get_text(type_child, source)
                            # Resolve to FQN and add
                            implements.append(self._resolve_type(interface_name, imports, package))
                            interface_name = None  # Reset after adding
                elif child.type == "scoped_type_identifier":
                    # Handle qualified names like com.example.Interface
                    interface_name = self._ts_get_text(child, source)
                elif child.type == "generic_type":
                    # Handle generic types like List<String> - extract base type
                    base_type_node = self._ts_find_child_by_type(child, "type_identifier")
                    if not base_type_node:
                        base_type_node = self._ts_find_child_by_type(child, "scoped_type_identifier")
                    if base_type_node:
                        interface_name = self._ts_get_text(base_type_node, source)
                
                # Resolve and add interface name if found
                if interface_name:
                    implements.append(self._resolve_type(interface_name, imports, package))
        
        logger.info(f"  Parsed with tree-sitter to identify the respective implementation for : {fqn} (extends: {extends}, implements: {implements})")
        # Create ClassInfo with basic information
        class_info = ClassInfo(
            package=package,
            class_name=class_name,
            fqn=fqn,
            source_path=file_path,
            implements=implements,
            extends=extends,
            is_interface=is_interface,
            imports=imports
        )
        
        # Resolve body node: classes use "class_body", interfaces use "interface_body".
        # Getting this wrong means ALL methods in interface files are silently dropped.
        class_body = self._ts_find_child_by_type(class_node, "class_body")
        if class_body is None:
            class_body = self._ts_find_child_by_type(class_node, "interface_body")

        # All return-type node types a method can have in the TreeSitter Java grammar.
        # Previous code only checked "type_identifier" and "void_type", so methods with
        # generic (List<String>), array (int[]), or primitive (int, long, boolean) return
        # types all fell through and were recorded as "void" — causing wrong call-hierarchy
        # resolution and potentially skipped method overloads.
        _RETURN_TYPE_NODE_TYPES = (
            "type_identifier",         # MyClass, String, …
            "void_type",               # void
            "generic_type",            # List<String>, Map<K,V>, …
            "array_type",              # int[], String[], …
            "scoped_type_identifier",  # java.util.List, …
            "integral_type",           # int, long, short, byte, char
            "floating_point_type",     # float, double
            "boolean_type",            # boolean
        )

        # ── Extract fields FIRST so that _ts_extract_method_calls can look them ──
        # up in class_info.fields when resolving call qualifiers (e.g. when a
        # method body calls "customerDataService.process(…)", the qualifier
        # "customerDataService" must already be in class_info.fields mapped to
        # its type "CustomerDataService" before we parse any method bodies).
        if class_body:
            for field_node in self._ts_find_children_by_type(class_body, "field_declaration"):
                type_node = self._ts_find_child_by_type(field_node, "type_identifier")
                if not type_node:
                    type_node = self._ts_find_child_by_type(field_node, "integral_type")
                if not type_node:
                    type_node = self._ts_find_child_by_type(field_node, "floating_point_type")
                if not type_node:
                    type_node = self._ts_find_child_by_type(field_node, "generic_type")

                field_type = self._ts_get_text(type_node, source).split('<')[0] if type_node else "Unknown"

                for declarator in self._ts_find_children_by_type(field_node, "variable_declarator"):
                    field_name_node = self._ts_find_child_by_type(declarator, "identifier")
                    if field_name_node:
                        field_name = self._ts_get_text(field_name_node, source)
                        class_info.fields[field_name] = field_type

        if class_body:
            for method_node in self._ts_find_children_by_type(class_body, "method_declaration"):
                method_name_node = self._ts_find_child_by_type(method_node, "identifier")
                if method_name_node:
                    method_name = self._ts_get_text(method_name_node, source)
                    
                    # Extract return type — check every possible type-node kind
                    return_type = "void"
                    for rtn_type in _RETURN_TYPE_NODE_TYPES:
                        type_node = self._ts_find_child_by_type(method_node, rtn_type)
                        if type_node:
                            return_type = self._ts_get_text(type_node, source)
                            break
                    
                    # Extract modifiers
                    modifiers = []
                    modifiers_node = self._ts_find_child_by_type(method_node, "modifiers")
                    if modifiers_node:
                        for mod_child in modifiers_node.children:
                            mod_text = self._ts_get_text(mod_child, source).strip()
                            if mod_text:
                                modifiers.append(mod_text)

                    # Extract parameters (formal_parameters > formal_parameter)
                    parameters = []
                    formal_params_node = self._ts_find_child_by_type(method_node, "formal_parameters")
                    if formal_params_node:
                        for param_node in self._ts_find_children_by_type(formal_params_node, "formal_parameter"):
                            param_type_node = None
                            param_name_node = None
                            for child in param_node.children:
                                if child.type == "identifier":
                                    param_name_node = child
                                elif child.type in (
                                    "type_identifier", "generic_type", "array_type",
                                    "integral_type", "floating_point_type", "boolean_type",
                                    "void_type", "scoped_type_identifier"
                                ):
                                    param_type_node = child
                            if param_type_node and param_name_node:
                                param_type = self._ts_get_text(param_type_node, source)
                                param_name = self._ts_get_text(param_name_node, source)
                                parameters.append((param_type, param_name))

                    # Extract method calls from method body
                    # Build param_types map from the extracted parameters so the
                    # tree-sitter path can infer argument types at call sites.
                    ts_param_types = {pname: ptype for ptype, pname in parameters}
                    method_calls = self._ts_extract_method_calls(
                        method_node, class_info, source, ts_param_types)
                    
                    # Count actual code lines from the AST (excludes comment & blank lines)
                    java_line_count = self._ts_count_code_lines(method_node, source)

                    # Create MethodDef WITH calls
                    method_def = MethodDef(
                        class_fqn=fqn,
                        method_name=method_name,
                        return_type=return_type,
                        parameters=parameters,
                        modifiers=modifiers,
                        calls=method_calls,
                        line_count=java_line_count
                    )
                    class_info.methods[method_def.method_key] = method_def
        
        self.classes[fqn] = class_info
        return class_info
    
    def _ts_find_child_by_type(self, node, type_name: str):
        """Find first child node with given type"""
        for child in node.children:
            if child.type == type_name:
                return child
        return None
    
    def _ts_find_children_by_type(self, node, type_name: str):
        """Find all children nodes with given type"""
        return [child for child in node.children if child.type == type_name]
    
    def _ts_get_text(self, node, source: str) -> str:
        """Extract text from tree-sitter node"""
        return source[node.start_byte:node.end_byte]

    def _ts_count_code_lines(self, method_node, source: str) -> int:
        """Count actual Java code lines in a method using the TreeSitter AST.

        Walks the method node tree to find all comment nodes (line_comment,
        block_comment) and records which absolute source-line numbers they
        occupy.  Then counts the method's lines that are neither comment-only
        nor blank.

        Args:
            method_node: TreeSitter method_declaration node.
            source:      Full Java source text (UTF-8 string).

        Returns:
            Number of non-blank, non-comment lines in the method.
        """
        comment_lines: set = set()

        def _collect_comment_lines(node):
            if node.type in ("line_comment", "block_comment"):
                for ln in range(node.start_point[0], node.end_point[0] + 1):
                    comment_lines.add(ln)
            for child in node.children:
                _collect_comment_lines(child)

        _collect_comment_lines(method_node)

        method_text = source[method_node.start_byte:method_node.end_byte]
        method_lines = method_text.split('\n')
        start_line = method_node.start_point[0]

        code_count = 0
        for i, line in enumerate(method_lines):
            abs_line = start_line + i
            if abs_line not in comment_lines and line.strip():
                code_count += 1
        return code_count

    def _ts_extract_local_var_types(self, method_body, source: str) -> dict:
        """First-pass scan of a method body to build a local-variable name → type map.

        Mirrors the JavaLang ``extract_local_variables`` pass.  Recognises
        ``local_variable_declaration`` nodes and reads the declared type plus
        every variable-declarator name inside them.
        """
        local_var_types: dict = {}

        def _walk(node):
            if node.type == "local_variable_declaration":
                # Tree-sitter node structure:
                #   local_variable_declaration
                #     modifiers?
                #     <type node>        (type_identifier | generic_type | array_type | …)
                #     variable_declarator_list | variable_declarator
                type_node = None
                for child in node.children:
                    if child.type in (
                        "type_identifier", "generic_type", "array_type",
                        "integral_type", "floating_point_type", "boolean_type",
                        "void_type", "scoped_type_identifier",
                    ):
                        type_node = child
                        break
                if type_node:
                    var_type = self._ts_get_text(type_node, source).split('<')[0].split('.')[-1]
                    for child in node.children:
                        if child.type == "variable_declarator":
                            name_node = self._ts_find_child_by_type(child, "identifier")
                            if name_node:
                                local_var_types[self._ts_get_text(name_node, source)] = var_type
                        elif child.type == "variable_declarator_list":
                            for decl in self._ts_find_children_by_type(child, "variable_declarator"):
                                name_node = self._ts_find_child_by_type(decl, "identifier")
                                if name_node:
                                    local_var_types[self._ts_get_text(name_node, source)] = var_type
            for child in node.children:
                _walk(child)

        _walk(method_body)
        return local_var_types

    def _ts_extract_method_calls(self, method_node, class_info: ClassInfo, source: str,
                                  param_types: dict = None) -> List[MethodCall]:
        """Extract method invocations from method body using tree-sitter.

        Uses TreeSitter **named fields** (``child_by_field_name``) to extract
        the method name and qualifier from each ``method_invocation`` node
        instead of doing text-based splitting on the raw source bytes.

        The text-based split approach breaks for multi-line method chains like:
            new Foo()
                .bar(x)
                .baz(y)
        because ``source[node.start_byte:arg_list.start_byte]`` captures the
        entire chain and the resulting qualifier string contains embedded
        newlines that never match any field/param/local-var lookup.

        TreeSitter Java grammar fields for ``method_invocation``:
          - ``object``    — the receiver expression (optional)
          - ``name``      — the method name identifier (always present)
          - ``arguments`` — the argument list (always present)

        Qualifier resolution by receiver node type:
          - ``identifier``                → simple variable; look up in fields /
                                            params / local vars
          - ``this`` / ``super``          → current / parent class
          - ``method_invocation``         → chained call; resolve inner return type
          - ``object_creation_expression``→ new Foo(...); extract the constructed type
          - ``field_access``              → obj.field; check if obj is ``this``
          - everything else               → fall back to raw text lookup

        Parity with the JavaLang ``_extract_method_calls`` path:
        1. First pass — build local-variable type map.
        2. First pass — track return types for chained-call resolution.
        3. Second pass — emit ``MethodCall`` objects.
        """
        calls = []
        if param_types is None:
            param_types = {}

        method_body = self._ts_find_child_by_type(method_node, "block")
        if not method_body:
            return calls

        # ── Pass 1a: local variable types ────────────────────────────────────
        local_var_types = self._ts_extract_local_var_types(method_body, source)

        # ── Pass 1b: track return types for chained-call resolution ──────────
        # Maps simple qualifier name → {'method_name', 'return_type', 'full_call'}
        last_method_with_qualifier: dict = {}

        def _resolve_qualifier_class(qualifier_str: str) -> Optional[str]:
            """Resolve a plain string qualifier to a FQN."""
            if qualifier_str in class_info.fields:
                return self._resolve_type(class_info.fields[qualifier_str], class_info.imports, class_info.package)
            if qualifier_str in param_types:
                return self._resolve_type(param_types[qualifier_str], class_info.imports, class_info.package)
            if qualifier_str in local_var_types:
                return self._resolve_type(local_var_types[qualifier_str], class_info.imports, class_info.package)
            return self._resolve_type(qualifier_str, class_info.imports, class_info.package)

        def _resolve_object_node(object_node) -> Optional[str]:
            """Resolve the receiver (object) node of a method_invocation to a FQN.

            Handles all common receiver patterns:
              - identifier          → variable / class  name
              - this / super        → current / parent class
              - method_invocation   → chained: get inner method's return type
              - object_creation_expression → new Foo(…) → look up Foo
              - field_access        → this.field, super.field, or plain field
              - everything else     → raw text lookup
            """
            ntype = object_node.type

            # ── this / super ─────────────────────────────────────────────────
            if ntype == "this":
                return class_info.fqn
            if ntype == "super":
                return class_info.extends if class_info.extends else class_info.fqn

            # ── simple variable / class name ──────────────────────────────────
            if ntype == "identifier":
                name = self._ts_get_text(object_node, source)
                return _resolve_qualifier_class(name)

            # ── chained method call: foo.bar().baz() ──────────────────────────
            if ntype == "method_invocation":
                inner_name_node = object_node.child_by_field_name("name")
                inner_object_node = object_node.child_by_field_name("object")
                if inner_name_node:
                    inner_method_name = self._ts_get_text(inner_name_node, source)
                    inner_target = (
                        _resolve_object_node(inner_object_node)
                        if inner_object_node is not None
                        else class_info.fqn
                    )
                    if inner_target and inner_target in self.classes:
                        ici = self.classes[inner_target]
                        if ici.has_method_name(inner_method_name):
                            im = ici.get_method_by_name_and_params(inner_method_name, None)
                            resolved = self._resolve_type(im.return_type, ici.imports, ici.package)
                            logger.info(f"      [TS obj] chained {inner_method_name}() → {resolved}")
                            return resolved
                return None

            # ── new Foo(…) ────────────────────────────────────────────────────
            if ntype == "object_creation_expression":
                type_node = object_node.child_by_field_name("type")
                if type_node is None:
                    # older grammar – find first type_identifier
                    type_node = self._ts_find_child_by_type(object_node, "type_identifier")
                if type_node:
                    type_name = self._ts_get_text(type_node, source).split('<')[0]
                    return self._resolve_type(type_name, class_info.imports, class_info.package)
                return None

            # ── this.field / super.field / obj.field ─────────────────────────
            if ntype == "field_access":
                obj_sub = object_node.child_by_field_name("object")
                field_sub = object_node.child_by_field_name("field")
                if obj_sub and obj_sub.type in ("this", "super"):
                    # this.someField – look it up in class fields
                    if field_sub:
                        fname = self._ts_get_text(field_sub, source)
                        if fname in class_info.fields:
                            return self._resolve_type(class_info.fields[fname], class_info.imports, class_info.package)
                    return class_info.fqn
                # generic field_access: fall back to raw text
                raw = self._ts_get_text(object_node, source).strip()
                return _resolve_qualifier_class(raw)

            # ── parenthesized expression: (expr).method() ────────────────────
            if ntype == "parenthesized_expression":
                inner = None
                for child in object_node.children:
                    if child.type not in ('(', ')'):
                        inner = child
                        break
                if inner:
                    return _resolve_object_node(inner)
                return None

            # ── fallback: raw text ────────────────────────────────────────────
            raw = self._ts_get_text(object_node, source).strip()
            return _resolve_qualifier_class(raw)

        def _track_invocations(node):
            """Pre-pass: record return types of resolved calls for chained resolution."""
            if node.type == "method_invocation":
                name_node = node.child_by_field_name("name")
                object_node = node.child_by_field_name("object")
                if name_node and object_node and object_node.type == "identifier":
                    m_name = self._ts_get_text(name_node, source)
                    qualifier = self._ts_get_text(object_node, source)
                    target_cls = _resolve_qualifier_class(qualifier)
                    if target_cls and target_cls in self.classes:
                        tc_info = self.classes[target_cls]
                        if tc_info.has_method_name(m_name):
                            method_def = tc_info.get_method_by_name_and_params(m_name, None)
                            ret = self._resolve_type(method_def.return_type, tc_info.imports, tc_info.package)
                            last_method_with_qualifier[qualifier] = {
                                'method_name': m_name,
                                'return_type': ret,
                                'full_call': f"{qualifier}.{m_name}()",
                            }
                            logger.info(f"    [TS track] {qualifier}.{m_name}() → {ret}")
            for child in node.children:
                _track_invocations(child)

        _track_invocations(method_body)

        # ── Pass 2: emit MethodCall objects ──────────────────────────────────
        def search_invocations(node):
            if node.type == "method_invocation":
                name_node = node.child_by_field_name("name")
                if name_node is None:
                    for child in node.children:
                        search_invocations(child)
                    return

                method_name = self._ts_get_text(name_node, source)
                object_node = node.child_by_field_name("object")
                arg_list_node = node.child_by_field_name("arguments")

                target_class = None

                if object_node is not None:
                    # Resolve via AST — no text splitting needed
                    target_class = _resolve_object_node(object_node)

                    # Track the result for downstream chaining
                    if (object_node.type == "identifier"
                            and target_class and target_class in self.classes):
                        qualifier_str = self._ts_get_text(object_node, source)
                        tc_info = self.classes[target_class]
                        if tc_info.has_method_name(method_name):
                            m_def = tc_info.get_method_by_name_and_params(method_name, None)
                            ret = self._resolve_type(m_def.return_type, tc_info.imports, tc_info.package)
                            last_method_with_qualifier[qualifier_str] = {
                                'method_name': method_name,
                                'return_type': ret,
                                'full_call': f"{qualifier_str}.{method_name}()",
                            }
                else:
                    # No receiver: self-call, or tail of a chain tracked by _track_invocations
                    for qual_name, info in last_method_with_qualifier.items():
                        ret_type = info['return_type']
                        if ret_type and ret_type in self.classes:
                            if self.classes[ret_type].has_method_name(method_name):
                                target_class = ret_type
                                logger.info(f"    [TS] ✓ no-qualifier chain: {info['full_call']}.{method_name}() → {target_class}")
                                break
                    # Fallback: no chained match → treat as implicit this.method() call.
                    # Check whether the current class itself defines a method with this name.
                    if target_class is None and class_info.has_method_name(method_name):
                        target_class = class_info.fqn
                        logger.info(f"    [TS] ✓ no-qualifier self-call: {method_name}() → {target_class}")

                logger.info(f"    [TS] Adding call: {method_name}, target={target_class}, class={class_info.fqn}")
                arg_types = self._infer_arg_types_ts(arg_list_node, source, param_types, local_var_types)
                calls.append(MethodCall(
                    target_class=target_class,
                    method_name=method_name,
                    line_number=0,
                    argument_types=arg_types,
                ))

            for child in node.children:
                search_invocations(child)

        search_invocations(method_body)
        return calls


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

        # Track chained method calls: track return types of methods we've seen
        # Key: method position in source, Value: return type
        method_return_types = {}
        
        def track_method_invocations(node, depth=0):
            """First pass: track all method invocations and their return types"""
            if isinstance(node, javalang.tree.MethodInvocation):
                method_name = node.member
                qualifier = node.qualifier if node.qualifier else None
                
                # Determine the return type of this method call
                if qualifier:
                    # Method called on object/field
                    target_class = None
                    if qualifier in class_info.fields:
                        target_class = class_info.fields[qualifier]
                        target_class = self._resolve_type(target_class, class_info.imports, class_info.package)
                    elif qualifier in param_types:
                        target_class = param_types[qualifier]
                        target_class = self._resolve_type(target_class, class_info.imports, class_info.package)
                    elif qualifier in local_var_types:
                        target_class = local_var_types[qualifier]
                        target_class = self._resolve_type(target_class, class_info.imports, class_info.package)
                    
                    # Look up method and get return type
                    if target_class and target_class in self.classes:
                        target_class_info = self.classes[target_class]
                        if target_class_info.has_method_name(method_name):
                            tracked_arg_types = self._infer_arg_types_javalang(
                                node.arguments, param_types, local_var_types)
                            method_def = target_class_info.get_method_by_name_and_params(
                                method_name, tracked_arg_types)
                            return_type = self._resolve_type(method_def.return_type, target_class_info.imports, target_class_info.package)
                            # Store with unique key (node object id)
                            method_return_types[id(node)] = return_type
                            logger.info(f"    Tracked: {qualifier}.{method_name}() returns {return_type}")
                else:
                    # Method called on self
                    if class_info.has_method_name(method_name):
                        tracked_arg_types = self._infer_arg_types_javalang(
                            node.arguments, param_types, local_var_types)
                        method_def = class_info.get_method_by_name_and_params(
                            method_name, tracked_arg_types)
                        return_type = self._resolve_type(method_def.return_type, class_info.imports, class_info.package)
                        method_return_types[id(node)] = return_type
                        logger.info(f"    Tracked: {method_name}() returns {return_type}")
            
            # Recursively track children
            if hasattr(node, 'children'):
                for child in node.children:
                    if child is not None:
                        if isinstance(child, list):
                            for item in child:
                                if item is not None:
                                    track_method_invocations(item, depth + 1)
                        else:
                            track_method_invocations(child, depth + 1)
        
        # Track all method invocations first
        for node in body_nodes:
            if node is not None:
                track_method_invocations(node)

        # Track the last method invocation we've seen (for chained calls)
        last_method_with_qualifier = {}  # qualifier_name -> return_type
        
        # Recursively search for MethodInvocation nodes in the body
        def search_invocations(node):
            nonlocal last_method_with_qualifier
            
            if isinstance(node, javalang.tree.MethodInvocation):
                method_name = node.member
                target_class = None
                
                # Log every method invocation for debugging
                qualifier_type = type(node.qualifier).__name__ if node.qualifier else "None"
                logger.info(f"    Method call: {method_name}, qualifier type: {qualifier_type}")

                # Try to determine target class from qualifier
                if node.qualifier:
                    qualifier = node.qualifier

                    # Check if qualifier is itself a MethodInvocation (chained call)
                    if isinstance(node.qualifier, javalang.tree.MethodInvocation):
                        logger.info(f"    Detected chained method call (javalang): ...{node.qualifier.member}().{method_name}")
                        # Chained method call: obj.method1().method2()
                        # Get the return type of the chained method
                        chained_method_name = node.qualifier.member
                        chained_qualifier = node.qualifier.qualifier if hasattr(node.qualifier, 'qualifier') else None
                        
                        logger.info(f"      Chained method: {chained_method_name}, qualifier: {chained_qualifier}")
                        
                        # Determine which class contains the chained method
                        chained_target_class = None
                        if chained_qualifier:
                            # Method called on an object
                            logger.info(f"      Looking up qualifier: '{chained_qualifier}' (fields: {list(class_info.fields.keys())})")
                            if chained_qualifier in class_info.fields:
                                chained_target_class = class_info.fields[chained_qualifier]
                                logger.info(f"      Found in fields: {chained_target_class}")
                                chained_target_class = self._resolve_type(chained_target_class, class_info.imports, class_info.package)
                                logger.info(f"      Resolved to: {chained_target_class}")
                            elif chained_qualifier in param_types:
                                chained_target_class = param_types[chained_qualifier]
                                logger.info(f"      Found in params: {chained_target_class}")
                                chained_target_class = self._resolve_type(chained_target_class, class_info.imports, class_info.package)
                            elif chained_qualifier in local_var_types:
                                chained_target_class = local_var_types[chained_qualifier]
                                logger.info(f"      Found in local vars: {chained_target_class}")
                                chained_target_class = self._resolve_type(chained_target_class, class_info.imports, class_info.package)
                            else:
                                chained_target_class = self._resolve_type(chained_qualifier, class_info.imports, class_info.package)
                                logger.info(f"      Resolved as class: {chained_target_class}")
                        else:
                            # Method called on self
                            chained_target_class = class_info.fqn
                            logger.info(f"      Method called on self: {chained_target_class}")
                        
                        # Look up the method and get its return type
                        if chained_target_class:
                            logger.info(f"      Looking for method '{chained_method_name}' in '{chained_target_class}'")
                            if chained_target_class in self.classes:
                                chained_class_info = self.classes[chained_target_class]
                                logger.info(f"      Methods available: {[m.method_name for m in chained_class_info.methods.values()]}")
                                if chained_class_info.has_method_name(chained_method_name):
                                    chained_method = chained_class_info.get_method_by_name_and_params(
                                        chained_method_name, None)
                                    target_class = chained_method.return_type
                                    logger.info(f"      Found! Return type: {target_class}")
                                    # Resolve return type to FQN
                                    target_class = self._resolve_type(target_class, chained_class_info.imports, chained_class_info.package)
                                    logger.info(f"      ✓ Chained call resolved: {chained_qualifier}.{chained_method_name}().{method_name} -> target: {target_class}")
                                else:
                                    logger.warning(f"      ✗ Method '{chained_method_name}' not found in class '{chained_target_class}'")
                            else:
                                logger.warning(f"      ✗ Class'{chained_target_class}' not found in cache")
                    
                    # Standard qualifier handling (not a chained call)
                    elif isinstance(qualifier, str):
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
                        # Check if it's an imported class (static method call)
                        else:
                            # Try to resolve as a class name from imports
                            target_class = self._resolve_type(qualifier, class_info.imports, class_info.package)
                            # If resolved to same as qualifier, it might not be in imports (target_class will be qualifier)
                            # This is ok - we keep it as the simple name
                        
                        # Store this method's return type for potential chained calls
                        logger.info(f"    Checking if we can track: method={method_name}, target_class={target_class}, in_cache={target_class in self.classes if target_class else 'N/A'}")
                        if target_class and target_class in self.classes:
                            target_class_info = self.classes[target_class]
                            logger.info(f"    Target class has methods: {[m.method_name for m in target_class_info.methods.values()]}")
                            if target_class_info.has_method_name(method_name):
                                call_arg_types = self._infer_arg_types_javalang(
                                    node.arguments, param_types, local_var_types)
                                method_def = target_class_info.get_method_by_name_and_params(
                                    method_name, call_arg_types)
                                return_type = self._resolve_type(method_def.return_type, target_class_info.imports, target_class_info.package)
                                last_method_with_qualifier[qualifier] = {
                                    'method_name': method_name,
                                    'return_type': return_type,
                                    'full_call': f"{qualifier}.{method_name}()"
                                }
                                logger.info(f"     Stored: {qualifier}.{method_name}() returns {return_type} for potential chaining")
                            else:
                                logger.info(f"    Method {method_name} not found in {target_class}")
                        else:
                            logger.info(f"    Cannot track: target_class not in cache or None")
                else:
                    # No qualifier - check if previous method returned something we can chain on
                    # Look through tracked methods to find one whose return type might match
                    logger.info(f"    No qualifier for {method_name}. Tracked methods: {list(last_method_with_qualifier.keys())}")
                    if last_method_with_qualifier:
                        # Get the most recently tracked method
                        for qual_name, info in last_method_with_qualifier.items():
                            return_type = info['return_type']
                            logger.info(f"    Checking if {return_type} has method {method_name}")
                            if return_type and return_type in self.classes:
                                return_class_info = self.classes[return_type]
                                logger.info(f"    {return_type} has methods: {[m.method_name for m in return_class_info.methods.values()]}")
                                if return_class_info.has_method_name(method_name):
                                    target_class = return_type
                                    logger.info(f"    ✓ Chained call detected: {info['full_call']}.{method_name}() -> target: {target_class}")
                                    break
                                else:
                                    logger.info(f"    Method {method_name} not in {return_type}")
                            else:
                                logger.info(f"    {return_type} not in cache or None")
                
                logger.info(f"    Inside extract_method_calls: Adding method call: {method_name}, target_class: {target_class}, class_fqn: {class_info.fqn}")
                arg_types = self._infer_arg_types_javalang(
                    node.arguments, param_types, local_var_types)
                calls.append(MethodCall(
                    target_class=target_class,
                    method_name=method_name,
                    line_number=0,
                    argument_types=arg_types
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

    # ------------------------------------------------------------------
    # Argument-type inference helpers
    # ------------------------------------------------------------------

    def _infer_arg_type_javalang(self, arg_node,
                                  param_types: dict,
                                  local_var_types: dict) -> Optional[str]:
        """Best-effort inference of the Java type for a single call-site argument.

        Covers the most common, statically obvious cases:
          - Literals   → primitive / String type
          - MemberReference with no qualifier (local var / param)
          - ClassCreator (new Foo(...)) → class name
          - Cast → the cast target type
          - MethodInvocation → return type if resolvable from the parsed cache
        Returns None when the type cannot be determined without full type inference.
        """
        if arg_node is None:
            return None

        # Literal: "hello", 42, 3.14f, true, null, 'c' …
        if isinstance(arg_node, javalang.tree.Literal):
            val = arg_node.value
            if val == 'null':
                return None
            if val.startswith('"'):
                return 'String'
            if val.startswith("'"):
                return 'char'
            if val in ('true', 'false'):
                return 'boolean'
            if val.endswith('L') or val.endswith('l'):
                return 'long'
            if val.endswith('f') or val.endswith('F'):
                return 'float'
            if val.endswith('d') or val.endswith('D'):
                return 'double'
            if '.' in val:
                return 'double'
            return 'int'

        # Simple variable / parameter / field reference
        if isinstance(arg_node, javalang.tree.MemberReference):
            if not arg_node.qualifier:
                name = arg_node.member
                t = param_types.get(name) or local_var_types.get(name)
                return t  # may be None if not tracked
            # qualified field access (e.g. this.field) — skip for now
            return None

        # new Foo(...) → type is Foo
        if isinstance(arg_node, javalang.tree.ClassCreator):
            if arg_node.type and hasattr(arg_node.type, 'name'):
                return arg_node.type.name
            return None

        # (SomeType) expr → cast type
        if isinstance(arg_node, javalang.tree.Cast):
            if arg_node.type:
                return self._get_type_name(arg_node.type)
            return None

        return None

    def _infer_arg_types_javalang(self, arguments,
                                   param_types: dict,
                                   local_var_types: dict) -> List[Optional[str]]:
        """Return a list of best-effort types for all call-site arguments."""
        if not arguments:
            return []
        return [self._infer_arg_type_javalang(a, param_types, local_var_types)
                for a in arguments]

    def _infer_arg_types_ts(self, arg_list_node, source: str,
                             param_types: dict,
                             local_var_types: dict = None) -> List[Optional[str]]:
        """Best-effort argument type inference for tree-sitter call sites.

        Recognises:
          - string_literal                   → String
          - decimal_integer_literal / integer_literal → int
          - decimal_floating_point_literal   → double
          - true / false                     → boolean
          - null_literal                     → None
          - identifier in param_types or local_var_types → looked-up type
          - object_creation_expression       → constructed class name
          - cast_expression                  → cast target type
          Everything else → None.
        """
        if arg_list_node is None:
            return []
        if local_var_types is None:
            local_var_types = {}

        arg_types: List[Optional[str]] = []
        for child in arg_list_node.children:
            # Skip punctuation (, ) and whitespace nodes
            if child.type in (',', '(', ')'):
                continue
            t = self._infer_single_arg_type_ts(child, source, param_types, local_var_types)
            if child.type not in (',', '(', ')'):
                arg_types.append(t)
        return arg_types

    def _infer_single_arg_type_ts(self, node, source: str,
                                   param_types: dict,
                                   local_var_types: dict = None) -> Optional[str]:
        """Infer the type of a single tree-sitter argument expression node."""
        if local_var_types is None:
            local_var_types = {}
        ntype = node.type
        if ntype == 'string_literal':
            return 'String'
        if ntype in ('decimal_integer_literal', 'integer_literal', 'hex_integer_literal',
                     'octal_integer_literal', 'binary_integer_literal'):
            return 'int'
        if ntype in ('decimal_floating_point_literal', 'hex_floating_point_literal'):
            return 'double'
        if ntype == 'true' or ntype == 'false':
            return 'boolean'
        if ntype == 'null_literal':
            return None
        if ntype == 'character_literal':
            return 'char'
        if ntype == 'long_literal':
            return 'long'
        if ntype == 'float_literal':
            return 'float'

        # Simple name reference → look up in param/local map
        if ntype == 'identifier':
            name = self._ts_get_text(node, source)
            return param_types.get(name) or local_var_types.get(name)

        # (Type) expr
        if ntype == 'cast_expression':
            # first significant child is the type
            for child in node.children:
                if child.type not in ('(', ')'):
                    return self._ts_get_text(child, source).split('<')[0].split('.')[-1]

        # new Foo(...)
        if ntype == 'object_creation_expression':
            type_node = self._ts_find_child_by_type(node, 'type_identifier')
            if not type_node:
                type_node = self._ts_find_child_by_type(node, 'scoped_type_identifier')
            if type_node:
                return self._ts_get_text(type_node, source).split('<')[0].split('.')[-1]

        return None