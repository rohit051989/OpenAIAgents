from classes.DataClasses import ClassInfo, MethodDef, ProcedureCall
import re
import yaml
import logging
from pathlib import Path
from typing import List, Tuple, Optional, Dict, Any


class ProcedureAnalyzer:
    """Analyzes Java methods for stored procedure calls using externalized rules"""

    def __init__(self, rules_config_path: str = None):
        """
        Initialize ProcedureAnalyzer with externalized rules.
        
        Args:
            rules_config_path: Path to procedure analysis rules YAML file
        """
        if rules_config_path is None:
            rules_config_path = Path(__file__).parent.parent / 'config' / 'procedure_analysis_rules.yaml'
        
        self.rules = self._load_rules(rules_config_path)
        
        # Extract frequently used rules
        self.procedure_patterns = self.rules.get('procedure_call_patterns', {})
        self.parameter_patterns = self.rules.get('parameter_patterns', [])
        self.max_parameters = self.rules.get('max_parameters', 10)
        self.database_type_keywords = self.rules.get('database_type_keywords', {})
        self.default_database_type = self.rules.get('default_database_type', 'UNKNOWN')
        self.skip_resource_keywords = self.rules.get('skip_resource_keywords', 
                                                     ['DYNAMIC', 'UNKNOWN', 'DYNAMIC_PROCEDURE'])
    
    def _load_rules(self, config_path: Path) -> Dict[str, Any]:
        """Load analysis rules from YAML configuration file"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                rules = yaml.safe_load(f)
            print(f"[OK] Loaded procedure analysis rules from: {config_path}")
            return rules
        except FileNotFoundError:
            print(f"[WARN] Procedure rules config not found: {config_path}, using defaults")
            return self._get_default_rules()
        except yaml.YAMLError as e:
            print(f"[WARN] Error parsing procedure rules config: {e}, using defaults")
            return self._get_default_rules()
    
    def _get_default_rules(self) -> Dict[str, Any]:
        """Return minimal default rules if config file is not found"""
        return {
            'procedure_call_patterns': {},
            'parameter_patterns': [],
            'max_parameters': 10,
            'database_type_keywords': {
                'ORACLE': ['oracle', 'OracleTypes'],
                'POSTGRESQL': ['postgres', 'postgresql'],
                'MYSQL': ['mysql']
            },
            'default_database_type': 'UNKNOWN'
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
        except Exception as e:
            # Log error but don't fail completely
            
            logging.error(f"Error reading/extracting method {method_def.method_name}: {e}")
            method_source = ""

        if not method_source:
            return None

        # Check each configured pattern type
        for call_type, patterns in self.procedure_patterns.items():
            # Check if this type of call exists
            found = False
            for indicator_item in patterns.get('indicators', []):
                # Handle both simple string patterns and dict-based patterns
                if isinstance(indicator_item, dict):
                    indicator_pattern = indicator_item.get('pattern', '')
                else:
                    indicator_pattern = indicator_item
                    
                if indicator_pattern and re.search(indicator_pattern, method_source, re.IGNORECASE):
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
        Extract procedure information from source code using configured patterns.

        Returns: (procedure_name, schema_name, catalog_name, is_function, parameters)
        """
        procedure_name = None
        schema_name = None
        catalog_name = None
        is_function = False
        parameters = []

        if call_type == 'SimpleJdbcCall':
            extraction_patterns = patterns.get('extraction_patterns', {})
            
            # Extract procedure name
            proc_config = extraction_patterns.get('procedure_name', {})
            proc_pattern = proc_config.get('pattern', '')
            if proc_pattern:
                proc_match = re.search(proc_pattern, source)
                if proc_match:
                    capture_group = proc_config.get('capture_group', 1)
                    procedure_name = proc_match.group(capture_group)

            # Check for function
            func_config = extraction_patterns.get('function_name', {})
            func_pattern = func_config.get('pattern', '')
            if func_pattern:
                func_match = re.search(func_pattern, source)
                if func_match:
                    capture_group = func_config.get('capture_group', 1)
                    procedure_name = func_match.group(capture_group)
                    is_function = True

            # If procedure name not found, check for dynamic call
            if not procedure_name:
                dynamic_detection = patterns.get('dynamic_detection', [])
                for dynamic_config in dynamic_detection:
                    dynamic_pattern = dynamic_config.get('pattern', '')
                    if dynamic_pattern and re.search(dynamic_pattern, source):
                        procedure_name = dynamic_config.get('placeholder', 'DYNAMIC_PROCEDURE')
                        break

            # Extract schema
            schema_config = extraction_patterns.get('schema_name', {})
            schema_pattern = schema_config.get('pattern', '')
            if schema_pattern:
                schema_match = re.search(schema_pattern, source)
                if schema_match:
                    capture_group = schema_config.get('capture_group', 1)
                    schema_name = schema_match.group(capture_group)
            
            # Check for dynamic schema
            if not schema_name:
                dynamic_detection = patterns.get('dynamic_detection', [])
                for dynamic_config in dynamic_detection:
                    if 'Schema' in dynamic_config.get('placeholder', ''):
                        dynamic_pattern = dynamic_config.get('pattern', '')
                        if dynamic_pattern and re.search(dynamic_pattern, source):
                            schema_name = dynamic_config.get('placeholder', 'DYNAMIC_SCHEMA')
                            break

            # Extract catalog
            catalog_config = extraction_patterns.get('catalog_name', {})
            catalog_pattern = catalog_config.get('pattern', '')
            if catalog_pattern:
                catalog_match = re.search(catalog_pattern, source)
                if catalog_match:
                    capture_group = catalog_config.get('capture_group', 1)
                    catalog_name = catalog_match.group(capture_group)
            
            # Check for dynamic catalog
            if not catalog_name:
                dynamic_detection = patterns.get('dynamic_detection', [])
                for dynamic_config in dynamic_detection:
                    if 'Catalog' in dynamic_config.get('placeholder', ''):
                        dynamic_pattern = dynamic_config.get('pattern', '')
                        if dynamic_pattern and re.search(dynamic_pattern, source):
                            catalog_name = dynamic_config.get('placeholder', 'DYNAMIC_CATALOG')
                            break

            # Extract parameters
            parameters = self._extract_parameters(source, call_type)

        elif call_type == 'CallableStatement':
            # Extract from configured extraction patterns
            extraction_patterns = patterns.get('extraction_patterns', {})
            
            # Check procedure_name pattern
            proc_config = extraction_patterns.get('procedure_name', {})
            proc_pattern = proc_config.get('pattern', '')
            if proc_pattern:
                match = re.search(proc_pattern, source, re.IGNORECASE)
                if match:
                    capture_group = proc_config.get('capture_group', 1)
                    full_name = match.group(capture_group)

                    # Parse schema.procedure_name
                    parts = full_name.split('.')
                    if len(parts) > 1:
                        schema_name = '.'.join(parts[:-1])
                        procedure_name = parts[-1]
                    else:
                        procedure_name = full_name
            
            # Check function_call pattern
            if not procedure_name:
                func_config = extraction_patterns.get('function_call', {})
                func_pattern = func_config.get('pattern', '')
                if func_pattern:
                    match = re.search(func_pattern, source, re.IGNORECASE)
                    if match:
                        capture_group = func_config.get('capture_group', 1)
                        procedure_name = match.group(capture_group)
                        is_function = True

            # If no match, check dynamic detection
            if not procedure_name:
                dynamic_detection = patterns.get('dynamic_detection', [])
                for dynamic_config in dynamic_detection:
                    dynamic_pattern = dynamic_config.get('pattern', '')
                    if dynamic_pattern and re.search(dynamic_pattern, source):
                        procedure_name = dynamic_config.get('placeholder', 'DYNAMIC_PROCEDURE')
                        break

        elif call_type == 'StoredProcedureQuery':
            # Try extraction patterns first
            extraction_patterns = patterns.get('extraction_patterns', {})
            
            # Check procedure_name pattern
            proc_config = extraction_patterns.get('procedure_name', {})
            proc_pattern = proc_config.get('pattern', '')
            if proc_pattern:
                proc_match = re.search(proc_pattern, source)
                if proc_match:
                    capture_group = proc_config.get('capture_group', 1)
                    procedure_name = proc_match.group(capture_group)
            
            # Check named_procedure pattern if not found
            if not procedure_name:
                named_config = extraction_patterns.get('named_procedure', {})
                named_pattern = named_config.get('pattern', '')
                if named_pattern:
                    named_match = re.search(named_pattern, source)
                    if named_match:
                        capture_group = named_config.get('capture_group', 1)
                        procedure_name = named_match.group(capture_group)
            
            # Check dynamic detection if still not found
            if not procedure_name:
                dynamic_detection = patterns.get('dynamic_detection', [])
                for dynamic_config in dynamic_detection:
                    dynamic_pattern = dynamic_config.get('pattern', '')
                    if dynamic_pattern and re.search(dynamic_pattern, source):
                        procedure_name = dynamic_config.get('placeholder', 'DYNAMIC_PROCEDURE')
                        break

        if procedure_name:
            return (procedure_name, schema_name, catalog_name, is_function, parameters)

        return None

    def _extract_parameters(self, source: str, call_type: str) -> List[str]:
        """Extract parameter names from procedure call using configured patterns"""
        parameters = []

        for pattern_item in self.parameter_patterns:
            # Handle both simple string patterns and dict-based patterns
            if isinstance(pattern_item, dict):
                pattern_str = pattern_item.get('pattern', '')
                capture_group = pattern_item.get('capture_group', 1)
            else:
                pattern_str = pattern_item
                capture_group = 1
                
            if not pattern_str:
                continue
                
            matches = re.finditer(pattern_str, source)
            for match in matches:
                try:
                    if match.lastindex and match.lastindex >= capture_group:
                        param_info = match.group(capture_group)
                    else:
                        param_info = match.group(0)
                    
                    if param_info and param_info.strip() and param_info not in parameters:
                        # Clean up parameter name
                        param_clean = re.sub(r'[,\s]+', ' ', param_info.strip())
                        parameters.append(param_clean)
                except IndexError:
                    continue

        return parameters[:self.max_parameters]

    def _infer_database_type(self, source: str) -> str:
        """Infer database type from source code context using configured keywords"""
        source_lower = source.lower()

        # Check each configured database type
        for db_type, keywords in self.database_type_keywords.items():
            for keyword in keywords:
                # Case-sensitive check for abbreviations (OracleTypes)
                if keyword in source or keyword.lower() in source_lower:
                    return db_type

        return self.default_database_type

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
