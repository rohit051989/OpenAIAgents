from classes.DataClasses import ClassInfo, MethodDef, ProcedureCall


import re
from typing import List, Tuple, Optional
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - [%(pathname)s:%(lineno)d %(funcName)s] - %(message)s"
)
logger = logging.getLogger(__name__)


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