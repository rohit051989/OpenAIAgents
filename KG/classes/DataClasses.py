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
import logging

logger = logging.getLogger(__name__)


@dataclass(kw_only=True)
class GitMetadataNode:
    """
    Base class for nodes whose data originates from a git repository.
    All fields are keyword-only so subclasses can freely declare positional
    required fields without triggering a field-ordering TypeError.

    git_repo_name      — repository name; same for all nodes from the same repo
    git_branch_name    — branch of the first commit (or last update if modified)
    git_created_by     — 'Name <email>' of the author who introduced the file
    git_created_at     — ISO-8601 datetime of that first commit
    git_updated_by     — 'Name <email>' of the author of the most recent commit
    git_updated_at     — ISO-8601 datetime of the most recent commit
    git_last_commit_id — full 40-char SHA of the last commit touching the file
    git_file_exists    — soft-delete flag: False = file removed in target branch
                         (node kept in graph for audit trail)
    """
    git_repo_name: Optional[str] = field(default=None)
    git_branch_name: Optional[str] = field(default=None)
    git_created_by: Optional[str] = field(default=None)
    git_created_at: Optional[str] = field(default=None)
    git_updated_by: Optional[str] = field(default=None)
    git_updated_at: Optional[str] = field(default=None)
    git_last_commit_id: Optional[str] = field(default=None)
    git_file_exists: bool = field(default=True)


@dataclass
class MethodCall:
    """Method invocation within a method"""
    target_class: Optional[str]  # Fully qualified or simple name
    method_name: str
    line_number: int = 0
    argument_types: List[Optional[str]] = field(default_factory=list)  # Best-effort types of call-site arguments


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
    def method_key(self) -> str:
        """Unique key for this method within its class, incorporating parameter types to
        support overloaded methods (same name, different signatures).
        Format: ``methodName(Type1,Type2)``
        """
        param_types = ",".join(ptype for ptype, _ in self.parameters)
        return f"{self.method_name}({param_types})"

    @property
    def signature(self) -> str:
        params = ", ".join([f"{ptype} {pname}" for ptype, pname in self.parameters])
        return f"{self.return_type} {self.method_name}({params})"
    
    @property
    def fqn(self) -> str:
        """Fully-qualified, overload-unique identifier: ``{class_fqn}.{method_key}``"""
        return f"{self.class_fqn}.{self.method_key}"

    @property
    def dbOperationCount(self) -> int:
        return len(self.db_operations)

    @property
    def procedureCallCount(self) -> int:
        return len(self.procedure_calls)

    @property
    def shellExecutionCount(self) -> int:
        return len(self.shell_executions)


@dataclass
class ClassInfo(GitMetadataNode):
    """Java class information — git metadata tracks the .java source file in the repo"""
    package: str
    class_name: str
    fqn: str
    source_path: str
    implements: List[str] = field(default_factory=list)
    extends: Optional[str] = None
    is_interface: bool = False  # True if this is an interface, False if it's a class
    fields: Dict[str, str] = field(default_factory=dict)  # field_name -> type
    methods: Dict[str, MethodDef] = field(default_factory=dict)  # method_key -> MethodDef  (key = method_name(ParamType1,ParamType2))
    imports: List[str] = field(default_factory=list)
    called_classes: Set[str] = field(default_factory=set)  # FQNs of classes this class calls

    # IG graph node properties (used when writing the JavaClass node to Neo4j)
    node_type: str = "JavaClass"        # Node type label in the IG
    extension: str = ".java"            # Always .java for Java source files
    size: int = 0                       # Source file size in bytes
    file_types: str = ""                # Comma-separated IG file-type labels
    isDAOClass: bool = False            # True if identified as a DAO/repository class
    isShellExecutorClass: bool = False  # True if identified as a shell-executor class
    isTestClass: bool = False           # True if in a test source directory

    @property
    def method_count(self) -> int:
        return len(self.methods)

    # ------------------------------------------------------------------
    # Overload-aware method lookup helpers
    # ------------------------------------------------------------------

    def has_method_name(self, name: str) -> bool:
        """Return True if any overload of *name* exists in this class."""
        return any(m.method_name == name for m in self.methods.values())

    def get_methods_by_name(self, name: str) -> List[MethodDef]:
        """Return all overloads of *name* (may be empty)."""
        return [m for m in self.methods.values() if m.method_name == name]

    def get_first_method_by_name(self, name: str) -> Optional[MethodDef]:
        """Return the first overload of *name*, or None if not found."""
        for m in self.methods.values():
            if m.method_name == name:
                return m
        return None

    def get_method_by_name_and_params(self, name: str,
                                      arg_types: Optional[List[Optional[str]]] = None) -> Optional[MethodDef]:
        """Return the best-matching overload of *name* for the given call-site argument types.

        Matching priority:
        1. Name + param count + every non-None arg type matches the declared param type
        2. Name + param count only (when arg types are all None or count doesn't help)
        3. First overload with that name (last-resort fallback)

        Returns None if no overload with that name exists.
        """
        candidates = [m for m in self.methods.values() if m.method_name == name]
        if not candidates:
            return None
        if len(candidates) == 1:
            return candidates[0]

        # No argument type information – cannot distinguish overloads
        if not arg_types:
            logger.debug(f"Overload ambiguity for '{name}' ({len(candidates)} overloads): "
                         f"no arg types available, using first match")
            return candidates[0]

        # Narrow by parameter count
        by_count = [m for m in candidates if len(m.parameters) == len(arg_types)]
        if not by_count:
            # No overload matches the call-site arity; fall back
            logger.debug(f"Overload ambiguity for '{name}': no param-count match "
                         f"(call has {len(arg_types)} args), using first match")
            return candidates[0]
        if len(by_count) == 1:
            return by_count[0]

        # Score each count-matching candidate: count how many non-None arg types
        # match the corresponding declared parameter type (simple-name comparison,
        # ignoring generics and fully-qualified prefixes).
        def _simple(t: Optional[str]) -> str:
            """Strip package prefix and generic suffix for loose comparison."""
            if not t:
                return ""
            return t.split('.')[-1].split('<')[0]

        def score(m: MethodDef) -> int:
            s = 0
            for (ptype, _), atype in zip(m.parameters, arg_types):
                if atype is not None and _simple(ptype) == _simple(atype):
                    s += 1
            return s

        scores = [(score(m), m) for m in by_count]
        best_score = max(s for s, _ in scores)
        best_matches = [m for s, m in scores if s == best_score]

        if len(best_matches) == 1:
            return best_matches[0]

        # Still ambiguous – log and return the first
        logger.debug(f"Overload ambiguity for '{name}' unresolved after type scoring "
                     f"(arg_types={arg_types}), using first match")
        return best_matches[0]


@dataclass
class DBOperation:
    """Database operation extracted from DAO method"""
    operation_type: str  # SELECT, INSERT, UPDATE, DELETE
    table_name: Optional[str]
    entity_type: Optional[str]
    method_fqn: str
    confidence: str = "HIGH"  # HIGH, MEDIUM, LOW
    raw_query: Optional[str] = None
    schema_name: Optional[str] = None  # Database schema (e.g., APMDATA from APMDATA.TABLE_NAME)


@dataclass
class ProcedureCall:
    """Oracle/Database stored procedure call"""
    procedure_name: str
    database_type: str  # ORACLE, POSTGRES, MYSQL, etc.
    method_fqn: str
    schema_name: Optional[str] = None  # Database schema (e.g., APMDATA)
    package_name: Optional[str] = None  # Package name for Oracle (e.g., PKG_BATCH)
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
class BeanDef(GitMetadataNode):
    """Comprehensive bean definition — git metadata tracks the Spring XML file and its Java class"""
    bean_id: str
    bean_class: str  # Fully qualified class name
    bean_class_name: str  # Simple class name (no package)
    class_source_path: Optional[str] = None

    # Dependencies: Dict[property_name, (dep_bean_id, dep_bean_class)]
    # Stores both beanId and beanClass for quick lookup
    property_dependencies: Dict[str, Tuple[str, str]] = field(default_factory=dict)
    constructor_dependencies: Dict[str, Tuple[str, str]] = field(default_factory=dict)

    # Resolved dependencies after DI analysis: Dict[field_name, (original_type, resolved_type)]
    # Tracks what field types were resolved from generic types to actual bean classes
    resolved_dependencies: Dict[str, Tuple[str, str]] = field(default_factory=dict)

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


@dataclass
class ListenerDef(GitMetadataNode):
    """Listener definition — git metadata tracks the Spring XML file that declares it"""
    name: str
    scope: str          # "JOB", "STEP", "CHUNK", ...
    impl_bean: str      # class name (if available)
    source_path: str = ""  # Source file path for the class (if found)


@dataclass
class StepDef(GitMetadataNode):
    """Step definition — git metadata tracks the Spring XML file that declares it"""
    name: str
    step_kind: str      # "TASKLET", "CHUNK", etc.
    impl_bean: str      # tasklet ref bean name (for TASKLET steps)
    class_name: str     # Class name for the ref bean (if available)
    class_source_path: str = ""  # Source file path for the class (if found)

    # For CHUNK steps
    reader_bean: str = ""     # Reader bean reference
    reader_class: str = ""    # Reader bean class name
    reader_source_path: str = ""  # Source file path for reader class
    processor_bean: str = "" # Processor bean reference
    processor_class: str = "" # Processor bean class name
    processor_source_path: str = ""  # Source file path for processor class
    writer_bean: str = ""     # Writer bean reference
    writer_class: str = ""    # Writer bean class name
    writer_source_path: str = ""  # Source file path for writer class

    listener_names: List[str] = field(default_factory=list)


@dataclass
class BlockDef:
    id: str
    block_type: str                 # "FLOW" or "PARALLEL"
    contains_steps: List[str] = field(default_factory=list)
    contains_blocks: List[str] = field(default_factory=list)
    entry_node: str | None = None   # id of first node inside block
    entry_kind: ExecNodeKind | None = None


@dataclass
class DecisionDef(GitMetadataNode):
    """Decision definition — git metadata tracks the Spring XML file that declares it"""
    name: str
    decider_bean: str
    class_name: str = ""  # Class name for the decider bean (if available)
    class_source_path: str = ""  # Source file path for the class (if found)


@dataclass
class PrecedesEdge:
    src_kind: ExecNodeKind
    src_id: str
    dst_id: str          # we'll resolve kind later based on id presence
    on: str


@dataclass
class JobDef(GitMetadataNode):
    """Job definition — git metadata tracks the Spring XML file that declares it"""
    name: str
    source_file: str = ""  # Path to the XML file this job was parsed from

    # KG graph node properties
    id: str = ""
    description: str = ""
    enabled: bool = True
    restartable: bool = True

    steps: Dict[str, StepDef] = field(default_factory=dict)
    blocks: Dict[str, BlockDef] = field(default_factory=dict)
    decisions: Dict[str, DecisionDef] = field(default_factory=dict)
    listeners: Dict[str, ListenerDef] = field(default_factory=dict)

    job_contains_steps: List[str] = field(default_factory=list)
    job_contains_blocks: List[str] = field(default_factory=list)

    job_entry_id: str | None = None
    job_entry_kind: ExecNodeKind | None = None

    precedes: List[PrecedesEdge] = field(default_factory=list)

    # alias flow id -> parent flow block id (e.g. "J1.f1" -> "f1")
    flow_alias_to_parent: Dict[str, str] = field(default_factory=dict)


