"""
KG / IG Node Definitions with Git Metadata Support
===================================================

Python dataclass representations for nodes in the Knowledge Graph (KG) and
Information Graph (IG).  Only nodes that have NO equivalent in DataClasses.py
are defined here.  Nodes already modelled in DataClasses.py (StepDef, BlockDef,
DecisionDef, ListenerDef, JobDef, ClassInfo, MethodDef, BeanDef) are NOT
duplicated here.

Complete IG node list and git-metadata assignment
-------------------------------------------------
  Node type       | Git metadata? | Defined in
  ----------------+---------------+-------------------------------
  Bean            | YES           | DataClasses.BeanDef
  Block           | NO  (derived) | DataClasses.BlockDef
  Decision        | YES           | DataClasses.DecisionDef
  Directory       | NO  (scan root, above repos)
  File            | YES           | IGFileNodeDef (this file)
  Folder          | NO  (git tracks files not dirs)
  JavaClass       | YES           | DataClasses.ClassInfo
  JavaMethod      | NO  (belongs to JavaClass) | DataClasses.MethodDef
  Job             | YES           | DataClasses.JobDef
  Listener        | YES           | DataClasses.ListenerDef
  Node            | NO  (IG base; git lives on File subclass only)
  Package         | NO  (Java package dir, no file-level git)
  PomFile         | YES           | IGPomFileNodeDef (this file)
  Project         | NO  (project dir, no file-level git)
  PropertyFile    | YES           | IGPropertyFileNodeDef (this file)
  Repository      | NO  (repo root dir, no file-level git)
  Resource        | CONDITIONAL   | ResourceNodeDef (this file; git when foundInRepo=True)
  SpringConfig    | YES           | IGSpringConfigNodeDef (this file)
  Step            | YES           | DataClasses.StepDef

KG nodes with git metadata (extracted from repo artifacts):
  All defined in DataClasses.py: JobDef, StepDef, DecisionDef, ListenerDef, BeanDef
  (JobDef also carries id, description, enabled, restartable for the KG layer)

GitMetadataNode is defined in DataClasses.py (the project foundation) and
imported here.  All DataClass nodes that need it (ClassInfo, BeanDef, StepDef,
DecisionDef, ListenerDef, JobDef) already inherit from it there.

KG nodes WITHOUT git metadata (Excel / manual config or runtime data):
  JobGroup, ScheduleInstanceContext, SLA, Calendar, Holiday, Tag,
  JobGroupExecution, JobContextExecution, ResourceAvailabilityEvent,
  CriticalPathInstance, CriticalPathCalculated, CriticalPathSignature, DataAsset
  Resource (when foundInRepo=False — loaded from Excel)

GitMetadataNode fields
----------------------
  git_repo_name      — repo name (same for all nodes from the same repo)
  git_branch_name    — last-touched branch. First scan: current branch. Incremental:
                       updated for A/M/D files; untouched files retain prior value
  git_created_by     — "Name <email>" of author who introduced the file
  git_created_at     — ISO-8601 datetime of that first commit
  git_updated_by     — "Name <email>" of author of the most recent commit
  git_updated_at     — ISO-8601 datetime of most recent commit
  git_last_commit_id — full 40-char SHA of last commit touching the file
  git_file_exists    — soft-delete flag: False = file removed in target branch
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional

# GitMetadataNode lives in DataClasses to keep it close to the core data model
from classes.DataClasses import GitMetadataNode


# =============================================================================
# BASE: Git Metadata  (keyword-only — safe for dataclass inheritance)
# =============================================================================
# GitMetadataNode is defined in classes/DataClasses.py — imported above.
# DataClass nodes that carry git metadata: ClassInfo, BeanDef, StepDef,
# DecisionDef, ListenerDef, JobDef.


# =============================================================================
# KNOWLEDGE GRAPH — Nodes WITH git metadata
# (extracted from Spring XML / Java source files in the git repository)
#
# ALL KG nodes with git are defined in DataClasses.py — nothing to define here:
#   Job       → DataClasses.JobDef      (id, description, enabled, restartable added)
#   Step      → DataClasses.StepDef
#   Block     → DataClasses.BlockDef    (derived; no physical file)
#   Decision  → DataClasses.DecisionDef
#   Listener  → DataClasses.ListenerDef
#   Bean      → DataClasses.BeanDef
#   JavaClass → DataClasses.ClassInfo   (graph fields: node_type, extension, size,
#                                         file_types, isDAOClass, isShellExecutorClass,
#                                         isTestClass, method_count)
#   JavaMethod→ DataClasses.MethodDef   (git belongs to parent ClassInfo file;
#                                         computed: dbOperationCount etc.)
# =============================================================================


# =============================================================================
# KNOWLEDGE GRAPH — Nodes WITHOUT git metadata (Excel / manual configuration)
# =============================================================================

@dataclass
class DataAssetNodeDef:
    """KG node: a specific data operation (read/write/delete/aggregate) on a Resource."""
    id: str = ""
    description: str = ""
    enabled: bool = True
    method: str = ""                # Method name performing the operation
    methodReference: str = ""       # Fully qualified method reference


@dataclass
class JobGroupNodeDef:
    """KG node: a group of related Jobs that execute together as a unit."""
    id: str = ""
    name: str = ""
    description: str = ""
    enabled: bool = True
    createdAt: str = ""
    priority: str = ""


@dataclass
class ScheduleInstanceContextNodeDef:
    """KG node: scheduling context linking a Job to its execution flow and dependencies."""
    id: str = ""
    name: str = ""
    description: str = ""
    enabled: bool = True
    contextForEntityId: str = ""    # ID of the Job this context is for
    estimatedDurationMs: int = 0


@dataclass
class SLANodeDef:
    """KG node: Service Level Agreement defining performance expectations for a Job."""
    id: str = ""
    name: str = ""
    enabled: bool = True
    type: str = ""                  # ABSOLUTE, RELATIVE
    policy: str = ""                # finish_by_time, duration_less_than, etc.
    severity: str = ""              # CRITICAL, HIGH, MEDIUM, LOW
    durationMs: int = 0
    time: str = ""                  # e.g. "04:00:00" for ABSOLUTE type
    tz: str = ""


@dataclass
class CalendarNodeDef:
    """KG node: scheduling calendar defining when Jobs can or cannot execute."""
    id: str = ""
    name: str = ""
    description: str = ""
    enabled: bool = True
    type: str = ""                  # DAY_OF_WEEK, TIME_WINDOW, DAY_OF_MONTH, HOLIDAY
    blockedDays: List[str] = field(default_factory=list)
    startTime: str = ""
    endTime: str = ""
    tz: str = ""


@dataclass
class HolidayNodeDef:
    """KG node: a holiday date that affects Job execution schedules."""
    id: str = ""
    name: str = ""
    enabled: bool = True
    date: str = ""


@dataclass
class ResourceNodeDef(GitMetadataNode):
    """
    Unified Resource node — used in both the IG and KG.

    Resources are DB objects (TABLE, VIEW, PROCEDURE, etc.) or files that
    batch jobs depend on.  They are discovered from two sources:

      foundInRepo=True  — DB repo scan (db_repo_scanner).  The resource has a
                          physical definition file in git: full file-tree
                          properties (path, extension, size) and git metadata
                          are populated.  repoName / repoFilePath link back to
                          the source file.

      foundInRepo=False — Excel / manual config.  Only scheduling-dependency
                          properties (type, checkInterval, etc.) are set; all
                          file-tree and git fields remain at their defaults.
    """
    # Core identity — both sources
    id: str = ""
    name: str = ""
    enabled: bool = True
    type: str = ""              # TABLE, VIEW, PROCEDURE, FUNCTION, PACKAGE,
                                #   TRIGGER, SYNONYM, SEQUENCE, DATABASE_LINK,
                                #   FILE, INDEX, TYPE
    schemaName: str = ""        # DB schema (e.g. APMDATA)
    packageName: str = ""       # Oracle package name (for PROCEDURE inside a PACKAGE)

    # Source flag
    foundInRepo: bool = False   # True = from db_repo git scan; False = from Excel/config

    # Repo-sourced properties (populated when foundInRepo=True)
    repoName: str = ""          # Git repository name the definition file belongs to
    repoFilePath: str = ""      # Absolute path to the SQL/DDL file in the repo
    path: str = ""              # Same as repoFilePath — IG file-tree path
    node_type: str = "Resource" # IG node type label
    extension: str = ""         # File extension of the definition file (.sql, .ddl, etc.)
    size: int = 0               # Size of the definition file in bytes
    file_types: str = ""        # Comma-separated IG file-type labels

    # Scheduling / dependency properties (primarily Excel-sourced)
    checkInterval: int = 0      # Minutes between availability checks
    resourceLocation: str = ""  # File-system path for FILE type resources



@dataclass
class TagNodeDef:
    """KG node: a categorization label applied to Jobs, Steps, Resources, etc."""
    id: str = ""
    name: str = ""
    description: str = ""
    tagType: str = ""               # Business, Technical, etc.
    enabled: bool = True
    createdAt: str = ""


# =============================================================================
# KNOWLEDGE GRAPH — Execution / Runtime Instance Nodes (no git metadata)
# (created at runtime — no source file in any git repository)
# =============================================================================

@dataclass
class JobGroupExecutionNodeDef:
    """KG node: an execution instance of a JobGroup."""
    id: str = ""
    startTime: str = ""
    businessDate: str = ""


@dataclass
class JobContextExecutionNodeDef:
    """KG node: an execution instance of a Job through its ScheduleInstanceContext."""
    id: str = ""
    status: str = ""                # COMPLETED, FAILED, RUNNING, STOPPED, etc.
    startTime: str = ""
    endTime: str = ""
    businessDate: str = ""
    durationMs: int = 0
    volume: int = 0
    exitCode: str = ""
    exitMessage: str = ""
    retryCount: int = 0
    expectedStartTime: str = ""


@dataclass
class ResourceAvailabilityEventNodeDef:
    """KG node: event indicating when a Resource became available for a business date."""
    id: str = ""
    businessDate: str = ""
    sizemb: float = 0.0
    checksum: str = ""
    detectedBy: str = ""
    availabilityTime: str = ""


@dataclass
class CriticalPathInstanceNodeDef:
    """KG node: CPM (Critical Path Method) metrics for a specific JobContextExecution."""
    id: str = ""
    es: int = 0                     # Earliest start time (ms)
    ef: int = 0                     # Earliest finish time (ms)
    ls: int = 0                     # Latest start time (ms)
    lf: int = 0                     # Latest finish time (ms)
    slack: int = 0                  # Float/total slack (ms)
    dur: int = 0                    # Duration (ms)
    isLongest: bool = False         # True if this node is on the critical/longest path
    computedAt: str = ""


@dataclass
class CriticalPathCalculatedNodeDef:
    """KG node: overall CPM calculation results for a JobGroupExecution."""
    id: str = ""
    cpm_completion_ms: int = 0
    cpm_total_buffer_ms: int = 0
    cpm_longest_path: List[str] = field(default_factory=list)   # Array of context IDs
    cpm_critical_path: List[str] = field(default_factory=list)  # Array of context IDs
    signatureHash: str = ""
    signatureText: str = ""
    cpm_computed_at: str = ""


@dataclass
class CriticalPathSignatureNodeDef:
    """KG node: a unique critical path pattern entry in the library for a JobGroup."""
    id: str = ""
    signatureHash: str = ""
    signatureText: str = ""
    occurrenceCount: int = 0
    firstSeenAt: str = ""
    lastSeenAt: str = ""


# =============================================================================
# INFORMATION GRAPH — Structural / container nodes  (NO git metadata)
#
# Git tracks files, not directories.  Repository, Project, Folder, and Package
# nodes are all directory-level constructs with no per-file git history.
# =============================================================================

@dataclass
class IGNodeDef:
    """IG base: the 'Node' super-label applied to every entry in the IG file tree."""
    path: str = ""                  # Absolute path — unique key in the graph
    name: str = ""
    node_type: str = ""             # Repository | Project | Folder | File | Package


@dataclass
class IGRepositoryNodeDef(IGNodeDef):
    """IG node: a git repository root folder (label: Node:Repository)."""
    pass


@dataclass
class IGProjectNodeDef(IGNodeDef):
    """IG node: a Maven/Gradle project folder containing a pom.xml or build.gradle
    (label: Node:Project)."""
    pass


@dataclass
class IGFolderNodeDef(IGNodeDef):
    """IG node: any non-repo, non-project sub-folder (label: Node:Folder)."""
    pass


@dataclass
class IGPackageNodeDef(IGNodeDef):
    """IG node: a Java package folder inside src/main/java or src/test/java
    (label: Node:Package or Node:Folder)."""
    package_name: str = ""          # Last segment only, e.g. 'batch' for com.example.batch
    full_package_name: str = ""     # Full dot-separated name, e.g. com.example.batch
    available_to_scan: bool = True  # False for test packages
    package_type: str = "source"    # 'source' or 'test'


# =============================================================================
# INFORMATION GRAPH — File nodes  (WITH git metadata)
#
# Only file nodes carry per-file git history populated from git log.
# gitBranchName strategy:
#   - First scan       → set to the current/release branch being scanned
#   - Incremental scan → set to the new branch for added/modified/deleted files;
#                        unchanged files retain the branch from their last change
#
# Nodes already defined in DataClasses.py and NOT duplicated here:
#   Bean        → DataClasses.BeanDef
#   Decision    → DataClasses.DecisionDef
#   JavaClass   → DataClasses.ClassInfo   (graph fields folded in)
#   JavaMethod  → DataClasses.MethodDef   (no git — belongs to JavaClass)
#   Job         → DataClasses.JobDef      (graph fields folded in)
#   Listener    → DataClasses.ListenerDef
#   Step        → DataClasses.StepDef
#   Block       → DataClasses.BlockDef    (no git — derived construct)
# =============================================================================

@dataclass
class IGFileNodeDef(IGNodeDef, GitMetadataNode):
    """IG node: a generic tracked file in the repository (label: Node:File)."""
    extension: str = ""
    size: int = 0
    file_types: str = ""            # Comma-separated file-type labels


@dataclass
class IGSpringConfigNodeDef(IGFileNodeDef):
    """IG node: a Spring XML configuration file (labels: Node:File:SpringConfig)."""
    isMainConfig: bool = True       # True → src/main, False → src/test


@dataclass
class IGPomFileNodeDef(IGFileNodeDef):
    """IG node: a Maven pom.xml file (labels: Node:File:PomFile)."""
    pass


@dataclass
class IGPropertyFileNodeDef(IGFileNodeDef):
    """IG node: a .properties or .yml/.yaml configuration file
    (labels: Node:File:PropertyFile)."""
    pass


# =============================================================================
# INFORMATION GRAPH — Additional nodes WITHOUT git metadata
#
#   Directory   — the scan-root directory; sits above the git repositories so
#                 it has no git context of its own.
#   (JavaMethod and Block are in DataClasses.py — MethodDef and BlockDef)
# =============================================================================

@dataclass
class IGDirectoryNodeDef:
    """IG node: the root scan directory that may contain multiple repositories
    (label: Node:Directory).  Not a git artifact itself, so no git metadata."""
    path: str = ""                  # Absolute path — unique key
    name: str = ""
    node_type: str = "Directory"
