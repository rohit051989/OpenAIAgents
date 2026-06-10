from classes.DataClasses import ClassInfo, MethodCall, MethodDef

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

logger = logging.getLogger(__name__)


class JavaCallHierarchyParser:
    """Parses Java source files to extract call hierarchy.

    The parser mode always use TreeSitter.  Uniform behaviour
      across all Java versions; all edge cases must be handled in the
      TreeSitter code path.

    """

    def __init__(self, parser_mode: Optional[str] = None):
        
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
        logger.info(f"  JavaCallHierarchyParser initialised: parser_mode='treesitter_only'")

    def parse_java_file(self, file_path: str) -> Optional[ClassInfo]:
        """Parse a single Java file and extract class info with call hierarchy.

        The parser engine uses TreeSitter directly.
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

        Recognises ``local_variable_declaration`` nodes and reads the declared type plus
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

        Path:
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


    def _resolve_type(self, simple_name: str, imports: List[str], package: str) -> str:
        """Resolve simple type name to FQN using imports"""
        if '.' in simple_name:
            return simple_name

        for imp in imports:
            if imp.endswith('.' + simple_name):
                return imp

        return f"{package}.{simple_name}" if package else simple_name

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