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

import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - [%(pathname)s:%(lineno)d %(funcName)s] - %(message)s"
)
logger = logging.getLogger(__name__)


class JavaCallHierarchyParser:
    """Parses Java source files to extract call hierarchy"""

    def __init__(self):
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

    def parse_java_file(self, file_path: str) -> Optional[ClassInfo]:
        """Parse a single Java file and extract class info with call hierarchy"""
        if not Path(file_path).exists():
            logger.info(f"  Warning: Source file not found: {file_path}")
            return None

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                source = f.read()

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
                        class_info.methods[method_def.method_name] = method_def

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
        
        # Extract methods WITH call hierarchy
        class_body = self._ts_find_child_by_type(class_node, "class_body")
        if class_body:
            for method_node in self._ts_find_children_by_type(class_body, "method_declaration"):
                method_name_node = self._ts_find_child_by_type(method_node, "identifier")
                if method_name_node:
                    method_name = self._ts_get_text(method_name_node, source)
                    
                    # Extract return type
                    return_type = "void"
                    type_node = self._ts_find_child_by_type(method_node, "type_identifier")
                    if not type_node:
                        type_node = self._ts_find_child_by_type(method_node, "void_type")
                    if type_node:
                        return_type = self._ts_get_text(type_node, source)
                    
                    # Extract method calls from method body
                    method_calls = self._ts_extract_method_calls(method_node, class_info, source)
                    
                    # Create MethodDef WITH calls
                    method_def = MethodDef(
                        class_fqn=fqn,
                        method_name=method_name,
                        return_type=return_type,
                        parameters=[],
                        modifiers=[],
                        calls=method_calls
                    )
                    class_info.methods[method_name] = method_def
        
        # Extract fields (simplified)
        if class_body:
            for field_node in self._ts_find_children_by_type(class_body, "field_declaration"):
                type_node = self._ts_find_child_by_type(field_node, "type_identifier")
                if not type_node:
                    type_node = self._ts_find_child_by_type(field_node, "integral_type")
                if not type_node:
                    type_node = self._ts_find_child_by_type(field_node, "floating_point_type")
                
                field_type = self._ts_get_text(type_node, source) if type_node else "Unknown"
                
                for declarator in self._ts_find_children_by_type(field_node, "variable_declarator"):
                    field_name_node = self._ts_find_child_by_type(declarator, "identifier")
                    if field_name_node:
                        field_name = self._ts_get_text(field_name_node, source)
                        class_info.fields[field_name] = field_type
        
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
    
    def _ts_extract_method_calls(self, method_node, class_info: ClassInfo, source: str) -> List[MethodCall]:
        """
        Extract method invocations from method body using tree-sitter.
        Recursively searches for method_invocation nodes in the method body.
        """
        
        calls = []
        
        # Find method body
        method_body = self._ts_find_child_by_type(method_node, "block")
        if not method_body:
            return calls
        
        # Recursively search for method invocations
        def search_invocations(node):
            if node.type == "method_invocation":
                # In tree-sitter, method_invocation structure:
                # - last identifier before '(' is the method name
                # - anything before that is the object/class qualifier
                
                method_name = None
                qualifier = None
                
                # Parse the method invocation text to extract components
                invocation_text = self._ts_get_text(node, source)
                
                # Find the argument_list to determine where method name ends
                arg_list_node = self._ts_find_child_by_type(node, "argument_list")
                if arg_list_node:
                    # Get text before argument list
                    call_prefix = source[node.start_byte:arg_list_node.start_byte].strip()
                    
                    # Split by dots to get qualifier and method name
                    parts = call_prefix.split('.')
                    if len(parts) > 1:
                        method_name = parts[-1]
                        qualifier = '.'.join(parts[:-1])
                    else:
                        method_name = parts[0]
                        qualifier = None
                else:
                    # Fallback: just get the last identifier
                    identifiers = [child for child in node.children if child.type == "identifier"]
                    if identifiers:
                        method_name = self._ts_get_text(identifiers[-1], source)
                        if len(identifiers) > 1:
                            qualifier = self._ts_get_text(identifiers[0], source)
                
                if not method_name:
                    return
                
                # Determine target class from qualifier
                target_class = None
                if qualifier:
                    # Check if qualifier is a chained method call (contains parentheses)
                    # e.g., "getJobsDao()" or "storedProcedureExecutor.getJobsDao()"
                    if '(' in qualifier:
                        logger.info(f"    Detected chained method call: {qualifier}.{method_name}")
                        # Extract the method name (remove parentheses and arguments)
                        # Handle nested calls: "obj.method1().method2()" -> get last method before current
                        qual_parts = qualifier.split('.')
                        last_method_part = qual_parts[-1]
                        # Extract method name before '('
                        if '(' in last_method_part:
                            chained_method_name = last_method_part.split('(')[0].strip()
                            # Determine which class contains this method
                            chained_target_class = None
                            if len(qual_parts) > 1:
                                # Method called on an object: obj.method()
                                obj_qualifier = '.'.join(qual_parts[:-1])
                                logger.info(f"      Looking up object: '{obj_qualifier}' in fields: {list(class_info.fields.keys())}")
                                if obj_qualifier in class_info.fields:
                                    chained_target_class = class_info.fields[obj_qualifier]
                                    logger.info(f"      Found field type: {chained_target_class}")
                                    chained_target_class = self._resolve_type(chained_target_class, class_info.imports, class_info.package)
                                    logger.info(f"      Resolved to FQN: {chained_target_class}")
                                else:
                                    chained_target_class = self._resolve_type(obj_qualifier, class_info.imports, class_info.package)
                                    logger.info(f"      Not a field, resolved as class: {chained_target_class}")
                            else:
                                # Method called on self: method()
                                chained_target_class = class_info.fqn
                                logger.info(f"      Method called on self: {chained_target_class}")
                            
                            # Look up the method and get its return type
                            if chained_target_class:
                                # Check in self.classes cache
                                logger.info(f"      Looking for method '{chained_method_name}' in class '{chained_target_class}'")
                                logger.info(f"      Available classes in cache: {len(self.classes)} (checking if {chained_target_class} is present: {chained_target_class in self.classes})")
                                if chained_target_class in self.classes:
                                    chained_class_info = self.classes[chained_target_class]
                                    logger.info(f"      Methods in {chained_target_class}: {list(chained_class_info.methods.keys())}")
                                    if chained_method_name in chained_class_info.methods:
                                        chained_method = chained_class_info.methods[chained_method_name]
                                        target_class = chained_method.return_type
                                        logger.info(f"      Found method! Return type: {target_class}")
                                        # Resolve return type to FQN
                                        target_class = self._resolve_type(target_class, chained_class_info.imports, chained_class_info.package)
                                        logger.info(f"      ✓ Chained call resolved: {qualifier}.{method_name} -> target class: {target_class}")
                                    else:
                                        logger.warning(f"      ✗ Method '{chained_method_name}' not found in class '{chained_target_class}'")
                                else:
                                    logger.warning(f"      ✗ Class '{chained_target_class}' not found in cache")
                    # Check if it's a field reference
                    elif qualifier in class_info.fields:
                        target_class = class_info.fields[qualifier]
                        target_class = self._resolve_type(target_class, class_info.imports, class_info.package)
                    # Check if it's a class name (static method call)
                    else:
                        target_class = self._resolve_type(qualifier, class_info.imports, class_info.package)
                
                # Add the method call
                calls.append(MethodCall(
                    target_class=target_class,
                    method_name=method_name,
                    line_number=0
                ))
            
            # Recursively search children
            for child in node.children:
                search_invocations(child)
        
        # Start searching from method body
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
                        if method_name in target_class_info.methods:
                            method_def = target_class_info.methods[method_name]
                            return_type = self._resolve_type(method_def.return_type, target_class_info.imports, target_class_info.package)
                            # Store with unique key (node object id)
                            method_return_types[id(node)] = return_type
                            logger.info(f"    Tracked: {qualifier}.{method_name}() returns {return_type}")
                else:
                    # Method called on self
                    if method_name in class_info.methods:
                        method_def = class_info.methods[method_name]
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
                                logger.info(f"      Methods available: {list(chained_class_info.methods.keys())}")
                                if chained_method_name in chained_class_info.methods:
                                    chained_method = chained_class_info.methods[chained_method_name]
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
                            logger.info(f"    Target class has methods: {list(target_class_info.methods.keys())}")
                            if method_name in target_class_info.methods:
                                method_def = target_class_info.methods[method_name]
                                return_type = self._resolve_type(method_def.return_type, target_class_info.imports, target_class_info.package)
                                last_method_with_qualifier[qualifier] = {
                                    'method_name': method_name,
                                    'return_type': return_type,
                                    'full_call': f"{qualifier}.{method_name}()"
                                }
                                logger.info(f"    ✓ Stored: {qualifier}.{method_name}() returns {return_type} for potential chaining")
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
                                logger.info(f"    {return_type} has methods: {list(return_class_info.methods.keys())}")
                                if method_name in return_class_info.methods:
                                    target_class = return_type
                                    logger.info(f"    ✓ Chained call detected: {info['full_call']}.{method_name}() -> target: {target_class}")
                                    break
                                else:
                                    logger.info(f"    Method {method_name} not in {return_type}")
                            else:
                                logger.info(f"    {return_type} not in cache or None")

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