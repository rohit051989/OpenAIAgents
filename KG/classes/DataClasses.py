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


@dataclass
class ProcedureCall:
    """Oracle/Database stored procedure call"""
    procedure_name: str
    database_type: str  # ORACLE, POSTGRES, MYSQL, etc.
    method_fqn: str
    parameters: List[str] = field(default_factory=list)
    is_function: bool = False  # True if returns value, False for procedure
    confidence: str = "HIGH"  # HIGH, MEDIUM, LOW


@dataclass
class ShellScriptExecution:
    """Shell script execution detected in code"""
    script_name: Optional[str]
    method_fqn: str
    script_type: str  # BASH, SHELL, PYTHON, POWERSHELL, etc.
    arguments: List[str] = field(default_factory=list)
    execution_method: str = ""  # Runtime.exec, ProcessBuilder, etc.
    confidence: str = "HIGH"


@dataclass
class BeanDef:
    """Comprehensive bean definition with all metadata"""
    bean_id: str
    bean_class: str  # Fully qualified class name
    bean_class_name: str  # Simple class name (no package)
    class_source_path: Optional[str] = None

    # Dependencies: Dict[property_name, (dep_bean_id, dep_bean_class)]
    # Stores both beanId and beanClass for quick lookup
    property_dependencies: Dict[str, Tuple[str, str]] = field(default_factory=dict)
    constructor_dependencies: Dict[str, Tuple[str, str]] = field(default_factory=dict)

    # Processing status
    is_dependency_processed: bool = False  # True when all dependencies resolved
    source_xml_file: Optional[str] = None

    # Parsed Java class info (populated later)
    class_info: Optional[ClassInfo] = None

    def get_package(self) -> str:
        """Extract package from bean_class"""
        if '.' in self.bean_class:
            return '.'.join(self.bean_class.split('.')[:-1])
        return ""

    def get_all_dependencies(self) -> Dict[str, Tuple[str, str]]:
        """Get all dependencies (properties + constructor args)"""
        all_deps = {}
        all_deps.update(self.property_dependencies)
        all_deps.update(self.constructor_dependencies)
        return all_deps


