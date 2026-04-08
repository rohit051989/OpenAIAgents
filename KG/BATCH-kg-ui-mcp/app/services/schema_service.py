"""Schema service — retrieves the Knowledge Graph schema from Neo4j.

This service builds a rich, human-readable schema document covering:
  - All node labels with per-property descriptions
  - All relationship types with semantic descriptions
  - Actual relationship patterns mined from the graph
  - Semantic descriptions for every known node type
"""

import logging
from typing import Any

from neo4j import AsyncDriver

from app.core.database import kg_session

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Static descriptors — updated when the KG schema changes
# ---------------------------------------------------------------------------

_PROPERTY_DESCRIPTIONS: dict[str, dict[str, str]] = {
    "JobGroup": {
        "id": "Unique identifier for the JobGroup",
        "name": "Name of the JobGroup",
        "enabled": "Whether the JobGroup is enabled (boolean)",
        "createdAt": "Timestamp when the JobGroup was created",
        "description": "Description of the JobGroup",
        "priority": "Priority level of the JobGroup",
        "cpm_completion_ms": "CPM computed completion time in milliseconds",
        "cpm_computed_at": "Timestamp when CPM was last computed",
        "cpm_critical_path": "Critical path steps as computed by CPM analysis",
        "cpm_longest_path": "Longest path steps as computed by CPM analysis",
        "cpm_total_buffer_ms": "Total buffer time in milliseconds",
    },
    "Job": {
        "id": "Unique identifier for the Job",
        "name": "Name of the Job",
        "enabled": "Whether the Job is enabled (boolean)",
        "createdAt": "Timestamp when the Job was created",
        "sourceFile": "Source Spring XML configuration file path",
        "restartable": "Whether the Job is restartable (boolean)",
        "description": "Description of the Job",
    },
    "Step": {
        "id": "Unique identifier for the Step",
        "name": "Name of the Step",
        "className": "Java class name implementing the Step",
        "implBean": "Spring bean name for Step implementation",
        "stepKind": "Type of Step: TASKLET, CHUNK, etc.",
        "commitInterval": "Commit interval for chunk-oriented steps",
        "enabled": "Whether the Step is enabled (boolean)",
    },
    "Block": {
        "id": "Unique identifier for the Block",
        "type": "Block type: FLOW, SPLIT (parallel execution)",
        "name": "Name of the Block",
    },
    "Decision": {
        "id": "Unique identifier for the Decision",
        "name": "Name of the Decision point",
        "deciderBean": "Spring bean implementing decision logic",
    },
    "ScheduleInstanceContext": {
        "id": "Unique identifier for the ScheduleInstanceContext",
        "name": "Name of the context",
        "enabled": "Whether the context is enabled (boolean)",
        "contextForEntityId": "ID of the entity (Job) this context is for",
        "description": "Description of the context",
        "estimatedDurationMs": "Estimated duration in milliseconds",
        "cpm_computed_at": "Timestamp when CPM was computed",
        "cpm_dur_ms": "CPM computed duration in milliseconds",
        "cpm_ef_ms": "CPM earliest finish time in milliseconds",
        "cpm_es_ms": "CPM earliest start time in milliseconds",
        "cpm_is_longest_path": "Whether on the longest/critical path (boolean)",
        "cpm_lf_ms": "CPM latest finish time in milliseconds",
        "cpm_ls_ms": "CPM latest start time in milliseconds",
        "cpm_slack_ms": "CPM slack time in milliseconds",
    },
    "Tag": {
        "id": "Unique identifier for the Tag",
        "name": "Name of the Tag",
        "description": "Description of the Tag",
        "enabled": "Whether the Tag is enabled (boolean)",
        "tagType": "Type of Tag: Business, Technical, etc.",
        "createdAt": "Timestamp when the Tag was created",
    },
    "Resource": {
        "id": "Unique identifier for the Resource",
        "name": "Name of the Resource",
        "type": "Resource type: FILE, TABLE, etc.",
        "enabled": "Whether the Resource is enabled (boolean)",
        "checkInterval": "Interval in minutes to check resource availability",
        "resourceLocation": "File path for FILE type resources",
        "schemaName": "Database schema name for TABLE type resources",
        "description": "Description of the Resource",
    },
    "DataAsset": {
        "id": "Unique identifier for the DataAsset",
        "description": "Description of the data operation",
        "method": "Method name performing the operation",
        "methodReference": "Fully qualified method reference",
        "enabled": "Whether the DataAsset is enabled (boolean)",
    },
    "SLA": {
        "id": "Unique identifier for the SLA",
        "name": "Name of the SLA",
        "policy": "SLA policy: finish_by_time, duration_less_than, etc.",
        "severity": "Severity level: CRITICAL, HIGH, MEDIUM, LOW",
        "enabled": "Whether the SLA is enabled (boolean)",
        "type": "SLA type: ABSOLUTE, RELATIVE",
        "time": "Absolute time for completion (e.g., 04:00:00)",
        "durationMs": "Maximum duration in milliseconds",
        "tz": "Time zone for the SLA",
    },
    "Calendar": {
        "id": "Unique identifier for the Calendar",
        "name": "Name of the Calendar",
        "type": "Calendar type: DAY_OF_WEEK, TIME_WINDOW, DAY_OF_MONTH, HOLIDAY",
        "description": "Description of the Calendar",
        "enabled": "Whether the Calendar is enabled (boolean)",
        "blockedDays": "List of blocked days (for DAY_OF_WEEK or DAY_OF_MONTH)",
        "startTime": "Start time for TIME_WINDOW type",
        "endTime": "End time for TIME_WINDOW type",
        "tz": "Time zone for the Calendar",
    },
    "Holiday": {
        "id": "Unique identifier for the Holiday",
        "name": "Name of the Holiday",
        "date": "Date of the Holiday",
        "enabled": "Whether the Holiday is enabled (boolean)",
    },
    "Listener": {
        "id": "Unique identifier for the Listener",
        "name": "Name of the Listener",
        "implBean": "Spring bean implementing listener logic",
        "scope": "Listener scope: JOB, STEP",
    },
    "JobGroupExecution": {
        "id": "Unique execution identifier for JobGroupExecution",
        "businessDate": "Business date for the execution",
        "startTime": "Start time of the execution",
        "endTime": "End time of the execution",
        "status": "Execution status: COMPLETED, FAILED, RUNNING, etc.",
        "durationMs": "Duration in milliseconds",
    },
    "JobContextExecution": {
        "id": "Unique execution identifier for JobContextExecution",
        "businessDate": "Business date for the execution",
        "startTime": "Start time of the execution",
        "endTime": "End time of the execution",
        "status": "Execution status: COMPLETED, FAILED, RUNNING, etc.",
        "exitCode": "Exit code from execution",
        "exitMessage": "Exit message or error message",
        "retryCount": "Number of retries attempted",
        "durationMs": "Duration in milliseconds",
        "volume": "Data volume processed",
        "expectedStartTime": "Expected start time based on schedule",
    },
    "StepExecution": {
        "id": "Unique execution identifier for StepExecution",
        "stepId": "ID of the Step being executed",
        "startTime": "Start time of the execution",
        "endTime": "End time of the execution",
        "status": "Execution status: COMPLETED, FAILED, etc.",
        "exitCode": "Exit code from execution",
        "readCount": "Number of items read",
        "writeCount": "Number of items written",
        "durationMs": "Duration in milliseconds",
        "createdAt": "Timestamp when execution record was created",
        "updatedAt": "Timestamp when execution record was last updated",
    },
    "ResourceAvailabilityEvent": {
        "id": "Unique identifier for the event",
        "resourceId": "ID of the Resource",
        "timestamp": "Timestamp when resource became available",
        "available": "Availability status (boolean)",
        "checksum": "Checksum of the resource",
        "size": "Size of the resource in KB",
        "detectedBy": "Entity that detected the availability",
        "createdAt": "Timestamp when event was created",
        "updatedAt": "Timestamp when event was last updated",
    },
    "CriticalPathInstance": {
        "id": "Unique identifier for CriticalPathInstance",
        "es": "Earliest start time in milliseconds",
        "ef": "Earliest finish time in milliseconds",
        "ls": "Latest start time in milliseconds",
        "lf": "Latest finish time in milliseconds",
        "slack": "Slack time in milliseconds",
        "dur": "Duration in milliseconds",
        "isLongest": "Whether this is on the longest/critical path (boolean)",
        "computedAt": "Timestamp when CPM was computed",
    },
    "CriticalPathCalculated": {
        "id": "Unique identifier for CriticalPathCalculated",
        "cpm_completion_ms": "Total completion time in milliseconds",
        "cpm_total_buffer_ms": "Total buffer time in milliseconds",
        "cpm_longest_path": "Longest path as array of context IDs",
        "cpm_critical_path": "Critical path as array of context IDs",
        "signatureHash": "Hash of the critical path signature",
        "signatureText": "Text representation of the critical path",
        "cpm_computed_at": "Timestamp when CPM was computed",
    },
    "CriticalPathSignature": {
        "id": "Unique identifier for CriticalPathSignature",
        "signatureHash": "Hash of the critical path signature",
        "signatureText": "Text representation of the critical path",
        "occurrenceCount": "Number of times this signature has occurred",
        "firstSeenAt": "Timestamp when first seen",
        "lastSeenAt": "Timestamp when last seen",
    },
    "JavaClass": {
        "fqn": "Fully qualified name of the Java class",
        "className": "Simple class name",
        "package": "Package name",
        "path": "File system path to the Java source file",
    },
    "JavaMethod": {
        "fqn": "Fully qualified name including class and method",
        "methodName": "Name of the method",
        "classFqn": "Fully qualified name of the containing class",
        "dbOperations": "List of database operations performed",
        "dbOperationCount": "Count of database operations",
        "procedureCalls": "List of stored procedure calls",
        "procedureCallCount": "Count of stored procedure calls",
    },
}

_NODE_DESCRIPTIONS: dict[str, str] = {
    "JobGroup": "Group of related Jobs that execute together as a unit",
    "Job": "Spring Batch job definition with configuration and steps",
    "Step": "Individual step within a Job representing a unit of work",
    "Block": "Grouping construct for parallel (SPLIT) or sequential (FLOW) step execution",
    "Decision": "Decision point in job flow that determines next step based on custom logic",
    "ScheduleInstanceContext": "Scheduling context for a Job, linking it to execution flow and dependencies",
    "Tag": "Categorization label for Jobs, Steps, Resources, or other entities",
    "Resource": "External dependency such as FILE or TABLE that Jobs/Steps require",
    "DataAsset": "Specific data operation (read/write/delete/aggregate) on a Resource",
    "SLA": "Service Level Agreement defining performance expectations",
    "Calendar": "Scheduling calendar defining when Jobs can or cannot execute",
    "Holiday": "Holiday date that affects Job execution schedules",
    "Listener": "Event listener attached to Jobs or Steps for lifecycle hooks",
    "JobGroupExecution": "Execution instance of a JobGroup",
    "JobContextExecution": "Execution instance of a Job through its ScheduleInstanceContext",
    "StepExecution": "Execution instance of a Step",
    "ResourceAvailabilityEvent": "Event indicating when a Resource became available",
    "CriticalPathInstance": "CPM metrics for a specific JobContextExecution",
    "CriticalPathCalculated": "CPM calculation results for a JobGroupExecution",
    "CriticalPathSignature": "Unique critical path pattern library for a JobGroup",
    "JavaClass": "Java class from the codebase (from Information Graph)",
    "JavaMethod": "Java method from the codebase with database operations (from Information Graph)",
}

_RELATIONSHIP_DESCRIPTIONS: dict[str, str] = {
    "HAS_JOB": "Links JobGroup to its contained Jobs",
    "FOR_JOB": "Links ScheduleInstanceContext to the Job it represents",
    "FOR_GROUP": "Links ScheduleInstanceContext to the JobGroup it belongs to",
    "PRECEDES": "Links ScheduleInstanceContext/Step/Decision to its successor in execution flow",
    "ENTRY": "Links JobGroup/Job/Block to its entry point (ScheduleInstanceContext or Step)",
    "CONTAINS": "Links Job to its Steps or Blocks; also links Block to its contained Steps",
    "HAS_LISTENER": "Links Job to its Listener",
    "HAS_TAG": "Links entity (Job, Step, Resource, etc.) to its Tag",
    "Require_Resource": "Links JobGroup or Job to required Resource",
    "HAS_SLA": "Links entity (JobGroup, Job, Resource) to its SLA",
    "RELATIVE_TO_RESOURCE": "Links SLA to Resource it's relative to (for relative SLAs)",
    "CAN_EXECUTE_ON": "Links JobGroup or Job to Calendar allowing execution",
    "CANNOT_EXECUTE_ON": "Links JobGroup or Job to Calendar blocking execution",
    "BLOCKS_ON": "Links Calendar to Holidays that block execution",
    "FOR_RESOURCE": "Links DataAsset or ResourceAvailabilityEvent to its parent Resource",
    "READS_FROM": "Links Step to DataAsset it reads from",
    "WRITES_TO": "Links Step to DataAsset it writes to",
    "DELETES_FROM": "Links Step to DataAsset it deletes from",
    "AGGREGATES_ON": "Links Step to DataAsset it aggregates on",
    "IMPLEMENTED_BY": "Links Step to JavaClass that implements it",
    "HAS_METHOD": "Links JavaClass to its JavaMethod",
    "CALLS": "Links JavaMethod to another JavaMethod it calls",
    "USES_CLASS": "Links JavaClass to another JavaClass it depends on",
    "EXECUTES_JOB_GROUP": "Links JobGroupExecution to JobGroup being executed",
    "EXECUTES_JOB_CONTEXT": "Links JobGroupExecution to JobContextExecution",
    "EXECUTES_CONTEXT": "Links JobContextExecution to ScheduleInstanceContext being executed",
    "EXECUTES_JOB": "Links JobContextExecution to Job being executed",
    "FOR_RUN": "Links ResourceAvailabilityEvent or CriticalPathInstance to execution instance",
    "IMPACTED": "Links ResourceAvailabilityEvent to execution instance it impacted",
    "HAS_CRITICAL_PATH_CALCULATED": "Links JobGroupExecution to its CriticalPathCalculated results",
    "HAS_CRITICAL_PATH_SIGNATURE": "Links JobGroup/JobGroupExecution/CriticalPathCalculated to CriticalPathSignature",
    "FOR_CONTEXT": "Links CriticalPathInstance to ScheduleInstanceContext it represents",
}

# ---------------------------------------------------------------------------
# Cypher queries
# ---------------------------------------------------------------------------

_Q_LABELS = "MATCH (n) UNWIND labels(n) AS label RETURN collect(DISTINCT label) AS labels"
_Q_REL_TYPES = "CALL db.relationshipTypes() YIELD relationshipType RETURN collect(relationshipType) AS rels"
_Q_NODE_PROPS = """
MATCH (n) WHERE $label IN labels(n)
UNWIND keys(n) AS k
RETURN collect(DISTINCT k) AS props
LIMIT 1
"""
_Q_REL_PATTERNS = """
MATCH (a)-[r]->(b)
WITH DISTINCT labels(a)[0] AS source_label, type(r) AS rel_type, labels(b)[0] AS target_label
RETURN source_label, rel_type, target_label
ORDER BY source_label, rel_type, target_label
"""


# ---------------------------------------------------------------------------
# Public service function
# ---------------------------------------------------------------------------

async def get_kg_schema(driver: AsyncDriver) -> dict[str, Any]:
    """Retrieve the full Knowledge Graph schema from Neo4j.

    Combines live graph introspection with static human-readable descriptors
    to produce a rich schema document usable by LLM agents.

    Args:
        driver: The shared Neo4j async driver.

    Returns:
        Dictionary with keys: ``nodes_with_descriptions``, ``nodes_properties``,
        ``relationships_with_descriptions``, ``relationship_patterns``,
        ``description``.
    """
    logger.info("Fetching KG schema")
    async with kg_session(driver) as session:
        # Node labels
        labels_result = await session.run(_Q_LABELS)
        labels_record = await labels_result.single()
        labels: list[str] = labels_record["labels"] if labels_record else []

        # Relationship types
        rels_result = await session.run(_Q_REL_TYPES)
        rels_record = await rels_result.single()
        relationships: list[str] = rels_record["rels"] if rels_record else []

        # Per-label property introspection
        node_properties: dict[str, dict[str, str]] = {}
        for label in labels:
            props_result = await session.run(_Q_NODE_PROPS, {"label": label})
            props_record = await props_result.single()
            props: list[str] = props_record["props"] if props_record else []
            if props:
                label_desc = _PROPERTY_DESCRIPTIONS.get(label, {})
                node_properties[label] = {
                    prop: label_desc.get(prop, f"Property '{prop}' of node '{label}'")
                    for prop in props
                }

        # Relationship patterns
        relationship_patterns: list[dict[str, str]] = []
        pattern_result = await session.run(_Q_REL_PATTERNS)
        async for record in pattern_result:
            relationship_patterns.append({
                "source": record["source_label"],
                "relationship": record["rel_type"],
                "target": record["target_label"],
                "pattern": (
                    f"({record['source_label']})"
                    f"-[:{record['rel_type']}]->"
                    f"({record['target_label']})"
                ),
            })

    return {
        "nodes_with_descriptions": {
            label: _NODE_DESCRIPTIONS.get(label, f"Node type: {label}")
            for label in labels
        },
        "nodes_properties": node_properties,
        "relationships_with_descriptions": {
            rel: _RELATIONSHIP_DESCRIPTIONS.get(rel, f"Relationship type: {rel}")
            for rel in relationships
        },
        "relationship_patterns": relationship_patterns,
        "description": (
            "Spring Batch Knowledge Graph with class-level definitions, "
            "execution instances, Java code lineage, and CPM critical path analysis"
        ),
    }
