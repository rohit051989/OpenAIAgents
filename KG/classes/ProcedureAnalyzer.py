from classes.DataClasses import ClassInfo, MethodDef, ProcedureCall


import re
from typing import List, Tuple, Optional


class ProcedureAnalyzer:
    """Analyzes Java methods for stored procedure calls"""

    # Patterns for detecting procedure calls
    PROCEDURE_PATTERNS = {
        'SimpleJdbcCall': {
            'indicators': [
                r'new\s+SimpleJdbcCall\s*\(',
                r'SimpleJdbcCall\s+\w+\s*=',
            ],
            'procedure_name': r'\.withProcedureName\s*\(\s*["\']([^"\']+)["\']',
            'function_name': r'\.withFunctionName\s*\(\s*["\']([^"\']+)["\']',
            'schema': r'\.withSchemaName\s*\(\s*["\']([^"\']+)["\']',
            'catalog': r'\.withCatalogName\s*\(\s*["\']([^"\']+)["\']',
        },
        'CallableStatement': {
            'indicators': [
                r'CallableStatement\s+\w+\s*=',
                r'\.prepareCall\s*\(',
            ],
            'call_pattern': [
                r'\{\s*call\s+([a-zA-Z0-9_.]+)\s*\(',  # {call schema.proc_name(...)}
                r'\{\s*\?\s*=\s*call\s+([a-zA-Z0-9_.]+)\s*\(',  # {? = call func_name(...)}
            ],
        },
        'StoredProcedureQuery': {
            'indicators': [
                r'createStoredProcedureQuery\s*\(\s*["\']([^"\']+)["\']',
                r'@NamedStoredProcedureQuery',
            ],
            'procedure_name': r'procedureName\s*=\s*["\']([^"\']+)["\']',
        },
    }

    def analyze_method(self, method_def: MethodDef, class_info: ClassInfo) -> Optional[ProcedureCall]:
        """
        Analyze a method for stored procedure calls.

        Args:
            method_def: Method definition with source code
            class_info: Class information

        Returns:
            ProcedureCall object if procedure call found, None otherwise
        """
        # Read method source
        try:
            with open(class_info.source_path, 'r', encoding='utf-8') as f:
                source = f.read()
            method_source = self._extract_method_source(source, method_def.method_name)
        except:
            method_source = ""

        if not method_source:
            return None

        # Check each pattern type
        for call_type, patterns in self.PROCEDURE_PATTERNS.items():
            # Check if this type of call exists
            found = False
            for indicator in patterns.get('indicators', []):
                if re.search(indicator, method_source, re.IGNORECASE):
                    found = True
                    break

            if not found:
                continue

            # Extract procedure details
            proc_result = self._extract_procedure_info(method_source, call_type, patterns)

            if proc_result:
                procedure_name, schema_name, catalog_name, is_function, parameters = proc_result

                # Build full procedure name
                full_name = procedure_name
                if schema_name:
                    full_name = f"{schema_name}.{procedure_name}"
                if catalog_name:
                    full_name = f"{catalog_name}.{full_name}"

                return ProcedureCall(
                    procedure_name=full_name,
                    database_type=self._infer_database_type(method_source),
                    method_fqn=method_def.fqn,
                    parameters=parameters,
                    is_function=is_function,
                    confidence='HIGH'
                )

        return None

    def _extract_procedure_info(self, source: str, call_type: str, patterns: dict) -> Optional[Tuple[str, Optional[str], Optional[str], bool, List[str]]]:
        """
        Extract procedure information from source code.

        Returns: (procedure_name, schema_name, catalog_name, is_function, parameters)
        """
        procedure_name = None
        schema_name = None
        catalog_name = None
        is_function = False
        parameters = []

        if call_type == 'SimpleJdbcCall':
            # Extract procedure name
            proc_match = re.search(patterns['procedure_name'], source)
            if proc_match:
                procedure_name = proc_match.group(1)

            # Check for function
            func_match = re.search(patterns['function_name'], source)
            if func_match:
                procedure_name = func_match.group(1)
                is_function = True

            # If procedure name not found as literal, check for dynamic call
            if not procedure_name:
                # Check if withProcedureName() is called (even with variable)
                if re.search(r'\.withProcedureName\s*\(', source):
                    procedure_name = "DYNAMIC_PROCEDURE"  # Placeholder for runtime-determined procedures

            # Extract schema (may also be dynamic)
            schema_match = re.search(patterns['schema'], source)
            if schema_match:
                schema_name = schema_match.group(1)
            elif re.search(r'\.withSchemaName\s*\(', source) and not schema_name:
                schema_name = "DYNAMIC_SCHEMA"

            # Extract catalog (may also be dynamic)
            catalog_match = re.search(patterns['catalog'], source)
            if catalog_match:
                catalog_name = catalog_match.group(1)
            elif re.search(r'\.withCatalogName\s*\(', source) and not catalog_name:
                catalog_name = "DYNAMIC_CATALOG"

            # Extract parameters
            parameters = self._extract_parameters(source, call_type)

        elif call_type == 'CallableStatement':
            # Extract from call pattern
            for pattern in patterns.get('call_pattern', []):
                match = re.search(pattern, source, re.IGNORECASE)
                if match:
                    full_name = match.group(1)
                    # Check if it's a function (starts with ?)
                    if '?' in pattern:
                        is_function = True

                    # Parse schema.procedure_name
                    parts = full_name.split('.')
                    if len(parts) > 1:
                        schema_name = '.'.join(parts[:-1])
                        procedure_name = parts[-1]
                    else:
                        procedure_name = full_name
                    break

            # If no match but prepareCall is present, it's a dynamic call
            if not procedure_name and re.search(r'\.prepareCall\s*\(', source):
                procedure_name = "DYNAMIC_PROCEDURE"

        elif call_type == 'StoredProcedureQuery':
            # Check indicators for procedure name
            for indicator in patterns.get('indicators', []):
                match = re.search(indicator, source, re.IGNORECASE)
                if match and match.lastindex and match.lastindex >= 1:
                    procedure_name = match.group(1)
                    break

            # Try procedure_name pattern if not found
            if not procedure_name:
                proc_match = re.search(patterns.get('procedure_name', ''), source)
                if proc_match:
                    procedure_name = proc_match.group(1)

        if procedure_name:
            return (procedure_name, schema_name, catalog_name, is_function, parameters)

        return None

    def _extract_parameters(self, source: str, call_type: str) -> List[str]:
        """Extract parameter names from procedure call"""
        parameters = []

        # Pattern for parameter declarations
        param_patterns = [
            r'declareParameters\s*\((.*?)\)',
            r'\.addInParameter\s*\(\s*["\']([^"\']+)["\']',
            r'\.addOutParameter\s*\(\s*["\']([^"\']+)["\']',
            r'setParameter\s*\(\s*["\']([^"\']+)["\']',
            r'registerOutParameter\s*\(\s*\d+\s*,\s*[\w.]+\)',  # JDBC style
        ]

        for pattern in param_patterns:
            matches = re.finditer(pattern, source)
            for match in matches:
                param_info = match.group(1) if match.lastindex >= 1 else match.group(0)
                if param_info and param_info.strip() and param_info not in parameters:
                    # Clean up parameter name
                    param_clean = re.sub(r'[,\s]+', ' ', param_info.strip())
                    parameters.append(param_clean)

        return parameters[:10]  # Limit to 10 parameters

    def _infer_database_type(self, source: str) -> str:
        """Infer database type from source code context"""
        source_lower = source.lower()

        if 'oracle' in source_lower or 'OracleTypes' in source:
            return 'ORACLE'
        elif 'postgres' in source_lower or 'postgresql' in source_lower:
            return 'POSTGRES'
        elif 'mysql' in source_lower:
            return 'MYSQL'
        elif 'sqlserver' in source_lower or 'mssql' in source_lower or 'SQLServerTypes' in source:
            return 'SQLSERVER'
        else:
            return 'UNKNOWN'

    def _extract_method_source(self, file_content: str, method_name: str) -> str:
        """Extract method source from file content"""
        # Find method declaration
        method_pattern = rf'(public|private|protected)\s+[\w<>,\[\]\s]+\s+{re.escape(method_name)}\s*\([^)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{{'
        match = re.search(method_pattern, file_content, re.DOTALL)
        if not match:
            return ""

        # Find matching closing brace
        start_pos = match.end() - 1
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