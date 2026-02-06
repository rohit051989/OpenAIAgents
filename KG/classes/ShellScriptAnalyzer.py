from classes.DataClasses import ClassInfo, MethodDef, ShellScriptExecution


import re
from typing import List, Tuple, Optional


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