from classes.DataClasses import ClassInfo, MethodCall, MethodDef


import javalang


from pathlib import Path
from typing import Dict, List, Tuple, Optional


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