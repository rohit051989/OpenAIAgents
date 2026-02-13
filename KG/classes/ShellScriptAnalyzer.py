from classes.DataClasses import ClassInfo, MethodDef, ShellScriptExecution


import re
import os
import yaml
from typing import List, Tuple, Optional, Dict, Any


class ShellScriptAnalyzer:
    """
    Analyzes methods that execute shell scripts.
    Uses rules from config/shell_execution_rules.yaml instead of hardcoded patterns.
    """

    def __init__(self, rules_path: str = 'config/shell_execution_rules.yaml'):
        """Initialize analyzer with rules from config file."""
        self.rules = self._load_rules(rules_path)
        self.shell_import_patterns = self.rules.get('shell_execution_imports', {})
        self.actual_execution_patterns = self.rules.get('actual_execution_patterns', {})
        self.class_name_hints = self.rules.get('class_name_hints', {})
        self.ignore_patterns = self.rules.get('ignore_patterns', {})
        self.grey_area_indicators = self.rules.get('grey_area_indicators', {})
    
    def _load_rules(self, rules_path: str) -> Dict[str, Any]:
        """Load rules from YAML configuration file."""
        if not os.path.exists(rules_path):
            print(f"Warning: Rules file not found: {rules_path}")
            print("Using minimal default rules")
            return self._get_default_rules()
        
        try:
            with open(rules_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading rules file: {e}")
            return self._get_default_rules()
    
    def _get_default_rules(self) -> Dict[str, Any]:
        """Provide minimal default rules if config file is not available."""
        return {
            'shell_execution_imports': {
                'required': ['java.lang.Runtime', 'java.lang.ProcessBuilder', 'org.apache.commons.exec']
            },
            'actual_execution_patterns': {
                'runtime_exec': {
                    'pattern': r'Runtime\.getRuntime\(\)\.exec\s*\(',
                    'execution_method': 'Runtime.exec'
                }
            },
            'class_name_hints': {'strong': ['BatchUtils']},
            'ignore_patterns': {'method_names': [], 'class_names': []}
        }
    
    def is_shell_executor_class(self, class_info: ClassInfo) -> bool:
        """
        Determine if a class is a shell executor class.
        
        STRATEGY: Since java.lang.Runtime/Process are auto-imported and won't appear
        in imports, we check source code for ACTUAL execution patterns.
        
        CRITERIA:
        1. Not in ignore list
        2. Has strong class name hint (BatchUtils) OR relevant imports (Commons Exec, etc.)
        3. Source code contains ACTUAL execution patterns (Runtime.exec, ProcessBuilder, etc.)
        
        Args:
            class_info: ClassInfo object with class details
            
        Returns:
            True if class actually executes shell scripts/commands
        """
        # Check if class should be ignored
        if self._should_ignore_class(class_info):
            return False
        
        # Check for strong class name hints
        class_name_lower = class_info.class_name.lower()
        strong_hints = self.class_name_hints.get('strong', [])
        has_strong_hint = any(hint.lower() in class_name_lower for hint in strong_hints)
        
        # Check for shell-related imports (optional but strengthens confidence)
        has_relevant_imports = (
            self._has_required_shell_imports(class_info) or 
            self._has_optional_shell_imports(class_info)
        )
        
        # Need at least strong hint OR relevant imports to proceed
        if not (has_strong_hint or has_relevant_imports):
            return False
        
        # CRITICAL: Source must contain ACTUAL execution code
        try:
            with open(class_info.source_path, 'r', encoding='utf-8') as f:
                source = f.read()
            
            # Check if source contains ANY actual execution pattern
            for pattern_name, pattern_config in self.actual_execution_patterns.items():
                pattern = pattern_config.get('pattern', '')
                if re.search(pattern, source):
                    return True  # Found actual execution code
            
        except Exception as e:
            return False
        
        return False  # Has hints/imports but no actual execution code
    
    def _should_ignore_class(self, class_info: ClassInfo) -> bool:
        """Check if class should be ignored based on ignore patterns."""
        class_name = class_info.class_name
        ignore_class_names = self.ignore_patterns.get('class_names', [])
        
        for ignore_pattern in ignore_class_names:
            if ignore_pattern.lower() in class_name.lower():
                return True
        
        return False
    
    def _has_required_shell_imports(self, class_info: ClassInfo) -> bool:
        """
        Check if class has shell execution imports.
        At least one from the required list must be present.
        """
        if not class_info.imports:
            return False
        
        required_imports = self.shell_import_patterns.get('required', [])
        
        for import_stmt in class_info.imports:
            for required_pattern in required_imports:
                if required_pattern in import_stmt:
                    return True
        
        return False
    
    def _has_optional_shell_imports(self, class_info: ClassInfo) -> bool:
        """
        Check if class has optional shell-related imports.
        These strengthen confidence but are not required.
        """
        if not class_info.imports:
            return False
        
        optional_imports = self.shell_import_patterns.get('optional', [])
        
        for import_stmt in class_info.imports:
            for optional_pattern in optional_imports:
                if optional_pattern in import_stmt:
                    return True
        
        return False

    def analyze_method(self, method_def: MethodDef, class_info: ClassInfo, method_source: str = None) -> Optional[ShellScriptExecution]:
        """
        Analyze a method to detect ACTUAL shell script execution.
        Only returns a result if the method contains actual execution code.
        
        Args:
            method_def: Method definition
            class_info: Class information
            method_source: Optional pre-loaded method source code
            
        Returns:
            ShellScriptExecution object if method actually executes shells, None otherwise
        """
        # Read method source if not provided
        if not method_source:
            try:
                with open(class_info.source_path, 'r', encoding='utf-8') as f:
                    source = f.read()
                method_source = self._extract_method_source(source, method_def.method_name)
            except:
                return None

        if not method_source:
            return None

        # Check for ACTUAL shell execution code (not just method name)
        execution_found = None
        for pattern_name, pattern_config in self.actual_execution_patterns.items():
            pattern = pattern_config.get('pattern', '')
            if re.search(pattern, method_source):
                execution_found = pattern_config
                break
        
        if not execution_found:
            return None  # No actual execution code found

        # Detect script name or command
        script_name, execution_method = self._detect_shell_execution(method_source, execution_found)
        
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
        """Check if class imports shell execution packages (kept for compatibility)."""
        return self._has_required_shell_imports(class_info)

    def _detect_shell_execution(self, source: str, execution_pattern: Dict[str, Any]) -> Tuple[Optional[str], str]:
        """Detect shell script execution from source using matched pattern."""
        execution_method = execution_pattern.get('execution_method', 'Unknown')
        
        # Try to extract script name or command
        # Look for string literals in exec/execute calls
        string_pattern = r'["\']([^"\']+)["\']'
        matches = re.findall(string_pattern, source)
        
        if matches:
            # Return first non-trivial string (not just flags like "/c", "-c")
            for match in matches:
                if len(match) > 2 and not match.startswith('-') and not match.startswith('/'):
                    return match, execution_method
        
        return None, execution_method

    def _determine_script_type(self, script_info: str) -> str:
        """Determine script type from name or content"""
        if not script_info:
            return 'SHELL'
            
        script_info_lower = script_info.lower()

        if '.sh' in script_info_lower or 'bash' in script_info_lower or '/bin/sh' in script_info_lower:
            return 'BASH'
        elif '.py' in script_info_lower or 'python' in script_info_lower:
            return 'PYTHON'
        elif '.ps1' in script_info_lower or 'powershell' in script_info_lower:
            return 'POWERSHELL'
        elif '.bat' in script_info_lower or '.cmd' in script_info_lower or 'cmd' in script_info_lower:
            return 'BATCH'
        elif '.pl' in script_info_lower or 'perl' in script_info_lower:
            return 'PERL'
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
        """Extract method source from file with improved pattern."""
        # Simplified pattern that's more permissive with whitespace and modifiers
        # Matches: [modifiers] returnType methodName(params) [throws ...] {
        pattern = rf'(public|private|protected)\s+[\w<>,\[\]\s]+\s+{re.escape(method_name)}\s*\([^)]*\)[^{{]*{{'
        match = re.search(pattern, file_content, re.DOTALL)
        
        if not match:
            return ""
        
        # Find the matching closing brace
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