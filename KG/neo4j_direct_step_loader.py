from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Literal
import xml.etree.ElementTree as ET
from neo4j import GraphDatabase
import os
from pathlib import Path

# ---------- Model types ----------

ExecNodeKind = Literal["step", "block", "decision"]


@dataclass
class ListenerDef:
    name: str
    scope: str          # "JOB", "STEP", "CHUNK", ...
    impl_bean: str      # class name (if available)


@dataclass
class StepDef:
    name: str
    step_kind: str      # "TASKLET", "CHUNK", etc.
    impl_bean: str      # tasklet ref bean name (for TASKLET steps)
    class_name: str     # Class name for the ref bean (if available)
    
    # For CHUNK steps
    reader_bean: str = ""     # Reader bean reference
    reader_class: str = ""    # Reader bean class name
    processor_bean: str = "" # Processor bean reference
    processor_class: str = "" # Processor bean class name
    writer_bean: str = ""     # Writer bean reference
    writer_class: str = ""    # Writer bean class name
    
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
class DecisionDef:
    name: str
    decider_bean: str
    class_name: str = ""  # Class name for the decider bean (if available)


@dataclass
class PrecedesEdge:
    src_kind: ExecNodeKind
    src_id: str
    dst_id: str          # we'll resolve kind later based on id presence
    on: str


@dataclass
class JobDef:
    name: str
    source_file: str = ""  # Path to the XML file this job was parsed from

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


# ---------- XML parsing ----------

BATCH_NS = "http://www.springframework.org/schema/batch"
BEANS_NS = "http://www.springframework.org/schema/beans"
N_BATCH = f"{{{BATCH_NS}}}"
N_BEANS = f"{{{BEANS_NS}}}"


def parse_spring_batch_xml(xml_path: str, bean_class_map: Dict[str, str] = None) -> List[JobDef]:
    """
    Parse Spring Batch XML file and extract job definitions.
    
    Args:
        xml_path: Path to the XML file
        bean_class_map: Optional global bean map. If not provided, will only use beans from this file.
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()
    job_defs: List[JobDef] = []

    # If no global bean map provided, create a local one (for backward compatibility)
    if bean_class_map is None:
        bean_class_map = {}
        for bean_el in root.findall(f"./{N_BEANS}bean"):
            bid = bean_el.get("id")
            bclass = bean_el.get("class", "")
            if bid:
                bean_class_map[bid] = bclass

    # Find the job
    job_els = root.findall(f".//{N_BATCH}job")
    if not job_els:
        print(f"No <batch:job> found in XML: {xml_path}")
        return job_defs
    else:
        print(f"Found {len(job_els)} <batch:job>(s) in XML: {xml_path}")
        for job_el in job_els:
            job_defs.append(parse_job_defination(job_el, root, bean_class_map, xml_path))        

        return job_defs

def parse_job_defination(job_el, root, bean_class_map, xml_path: str = "") -> JobDef:
    # For now, just pick the first job
    job_id = job_el.get("id", "UNKNOWN_JOB")
    job = JobDef(name=job_id, source_file=xml_path)

    # 3) Parse global flows (top-level <batch:flow> directly under <beans>)
    parse_global_flows(root, job, bean_class_map)

    # 4) Parse job content (steps, split, flow refs, decisions, listeners)
    parse_job_element(job_el, job, bean_class_map)

    # 5) Normalize flow aliases in PRECEDES edges (J1.f1 -> f1)
    normalize_flow_aliases(job)

    return job

def parse_global_flows(root: ET.Element, job: JobDef, bean_class_map: Dict[str, str]) -> None:
    """Parse top-level <batch:flow id="..."> elements as FLOW blocks."""
    for flow_el in root.findall(f"./{N_BATCH}flow"):
        flow_id = flow_el.get("id")
        if not flow_id:
            continue

        block = BlockDef(id=flow_id, block_type="FLOW")

        # Children: steps and decisions
        first_node_id = None
        first_node_kind: ExecNodeKind | None = None
        step_ids: List[str] = []

        for child in flow_el:
            if child.tag == f"{N_BATCH}step":
                sid = child.get("id")
                if not sid:
                    continue
                parse_step_element(child, job, bean_class_map)
                step_ids.append(sid)
                if first_node_id is None:
                    first_node_id = sid
                    first_node_kind = "step"
            elif child.tag == f"{N_BATCH}decision":
                did = child.get("id")
                if not did:
                    continue
                parse_decision_element(child, job, bean_class_map)
                if first_node_id is None:
                    first_node_id = did
                    first_node_kind = "decision"

        block.contains_steps = step_ids
        block.entry_node = first_node_id
        block.entry_kind = first_node_kind
        job.blocks[flow_id] = block


def parse_job_element(job_el: ET.Element, job: JobDef, bean_class_map: Dict[str, str]) -> None:
    """Parse <batch:job> children: steps, split, flow refs, decisions, listeners."""

    # Job listeners
    listeners_el = job_el.find(f"{N_BATCH}listeners")
    if listeners_el is not None:
        for l_el in listeners_el.findall(f"{N_BATCH}listener"):
            ref = l_el.get("ref")
            if not ref:
                continue
            impl_class = bean_class_map.get(ref, "")
            
            # Flag if bean reference exists but class not found
            if ref and not impl_class:
                print(f"    ⚠️  Warning: Listener references bean '{ref}' but class not found in bean definitions")
            
            job.listeners[ref] = ListenerDef(
                name=ref,
                scope="JOB",
                impl_bean=impl_class or ref,
            )

    # Job children in order
    for child in job_el:
        tag = child.tag

        # Skip <listeners> (already handled)
        if tag == f"{N_BATCH}listeners":
            continue

        if tag == f"{N_BATCH}step":
            sid = child.get("id")
            if not sid:
                continue
            parse_step_element(child, job, bean_class_map)
            job.job_contains_steps.append(sid)
            if job.job_entry_id is None:
                job.job_entry_id = sid
                job.job_entry_kind = "step"

        elif tag == f"{N_BATCH}split":
            split_id = child.get("id")
            if not split_id:
                continue
            parse_split_element(child, job, bean_class_map)
            job.job_contains_blocks.append(split_id)
            if job.job_entry_id is None:
                job.job_entry_id = split_id
                job.job_entry_kind = "block"

        elif tag == f"{N_BATCH}flow":
            # This is a job-level flow reference, typically: <flow id="J1.f1" parent="f1" next="...">
            flow_id = child.get("id")
            parent_id = child.get("parent")
            if parent_id:
                # alias -> parent mapping: e.g. "J1.f1" -> "f1"
                if flow_id:
                    job.flow_alias_to_parent[flow_id] = parent_id

                # job uses this parent flow block
                if parent_id not in job.job_contains_blocks:
                    job.job_contains_blocks.append(parent_id)

                next_target = child.get("next")
                if next_target:
                    job.precedes.append(
                        PrecedesEdge(
                            src_kind="block",
                            src_id=parent_id,
                            dst_id=next_target,
                            on="COMPLETED",
                        )
                    )
            # Job-level <flow> is an executable node, but entry is still S1 in our toy

        elif tag == f"{N_BATCH}decision":
            did = child.get("id")
            if not did:
                continue
            parse_decision_element(child, job, bean_class_map)
            # We do NOT add decision to CONTAINS; it's only in PRECEDES graph.


def parse_step_element(step_el: ET.Element, job: JobDef, bean_class_map: Dict[str, str]) -> None:
    sid = step_el.get("id")
    if not sid:
        return

    # Find tasklet element
    tasklet_el = step_el.find(f"{N_BATCH}tasklet")
    if tasklet_el is None:
        return
    
    # Check if it's a chunk-based step or tasklet-based step
    chunk_el = tasklet_el.find(f"{N_BATCH}chunk")
    
    if chunk_el is not None:
        # CHUNK-based step
        step_kind = "CHUNK"
        
        # Extract reader, processor, writer references
        reader_bean = chunk_el.get("reader", "")
        processor_bean = chunk_el.get("processor", "")
        writer_bean = chunk_el.get("writer", "")
        
        # Resolve class names from bean map
        reader_class = bean_class_map.get(reader_bean, "") if reader_bean else ""
        processor_class = bean_class_map.get(processor_bean, "") if processor_bean else ""
        writer_class = bean_class_map.get(writer_bean, "") if writer_bean else ""
        
        # Flag unresolved bean references
        if reader_bean and not reader_class:
            print(f"    ⚠️  Warning: Step '{sid}' reader references bean '{reader_bean}' but class not found")
        if processor_bean and not processor_class:
            print(f"    ⚠️  Warning: Step '{sid}' processor references bean '{processor_bean}' but class not found")
        if writer_bean and not writer_class:
            print(f"    ⚠️  Warning: Step '{sid}' writer references bean '{writer_bean}' but class not found")
        
        if sid not in job.steps:
            job.steps[sid] = StepDef(
                name=sid,
                step_kind=step_kind,
                impl_bean="",  # Not used for chunk steps
                class_name="",  # Not used for chunk steps
                reader_bean=reader_bean,
                reader_class=reader_class,
                processor_bean=processor_bean,
                processor_class=processor_class,
                writer_bean=writer_bean,
                writer_class=writer_class,
            )
    else:
        # TASKLET-based step
        step_kind = "TASKLET"
        impl_ref = tasklet_el.get("ref", "")
        class_name = bean_class_map.get(impl_ref, "") if impl_ref else ""
        
        # Flag if bean reference exists but class not found
        if impl_ref and not class_name:
            print(f"    ⚠️  Warning: Step '{sid}' references bean '{impl_ref}' but class not found in bean definitions")
        
        if sid not in job.steps:
            job.steps[sid] = StepDef(
                name=sid,
                step_kind=step_kind,
                impl_bean=impl_ref or sid,
                class_name=class_name,
            )

    # next="..." attribute
    next_attr = step_el.get("next")
    if next_attr:
        job.precedes.append(
            PrecedesEdge(
                src_kind="step",
                src_id=sid,
                dst_id=next_attr,
                on="COMPLETED",
            )
        )

    # Optional nested <next on="..." to="..."> inside step (for S9/S10 in our toy)
    for next_el in step_el.findall(f"{N_BATCH}next"):
        on_val = next_el.get("on", "*")
        to_val = next_el.get("to")
        if to_val:
            job.precedes.append(
                PrecedesEdge(
                    src_kind="step",
                    src_id=sid,
                    dst_id=to_val,
                    on=on_val,
                )
            )


def parse_decision_element(dec_el: ET.Element, job: JobDef, bean_class_map: Dict[str, str]) -> None:
    did = dec_el.get("id")
    decider = dec_el.get("decider") or ""
    if not did:
        return

    # Resolve decider class name from bean map
    class_name = bean_class_map.get(decider, "") if decider else ""
    
    # Flag if bean reference exists but class not found
    if decider and not class_name:
        print(f"    ⚠️  Warning: Decision '{did}' references bean '{decider}' but class not found in bean definitions")

    if did not in job.decisions:
        job.decisions[did] = DecisionDef(name=did, decider_bean=decider, class_name=class_name)

    # Nested <next on="..." to="...">
    for next_el in dec_el.findall(f"{N_BATCH}next"):
        on_val = next_el.get("on", "*")
        to_val = next_el.get("to")
        if to_val:
            job.precedes.append(
                PrecedesEdge(
                    src_kind="decision",
                    src_id=did,
                    dst_id=to_val,
                    on=on_val,
                )
            )


def parse_split_element(split_el: ET.Element, job: JobDef, bean_class_map: Dict[str, str]) -> None:
    split_id = split_el.get("id")
    if not split_id:
        return

    # parallel block
    block = BlockDef(
        id=split_id,
        block_type="PARALLEL",
    )
    job.blocks[split_id] = block

    # split next="S8"
    next_attr = split_el.get("next")
    if next_attr:
        job.precedes.append(
            PrecedesEdge(
                src_kind="block",
                src_id=split_id,
                dst_id=next_attr,
                on="COMPLETED",
            )
        )

    # child flows -> create branch blocks
    branch_index = 1
    for flow_el in split_el.findall(f"{N_BATCH}flow"):
        branch_id = f"{split_id}_branch{branch_index}"
        branch_index += 1

        branch_block = BlockDef(
            id=branch_id,
            block_type="FLOW",
        )

        first_node_id = None
        first_node_kind: ExecNodeKind | None = None
        step_ids: List[str] = []

        for child in flow_el:
            if child.tag == f"{N_BATCH}step":
                sid = child.get("id")
                if not sid:
                    continue
                parse_step_element(child, job, bean_class_map)
                step_ids.append(sid)
                if first_node_id is None:
                    first_node_id = sid
                    first_node_kind = "step"
            elif child.tag == f"{N_BATCH}decision":
                did = child.get("id")
                if not did:
                    continue
                parse_decision_element(child, job, bean_class_map)
                if first_node_id is None:
                    first_node_id = did
                    first_node_kind = "decision"

        branch_block.contains_steps = step_ids
        branch_block.entry_node = first_node_id
        branch_block.entry_kind = first_node_kind

        job.blocks[branch_id] = branch_block
        block.contains_blocks.append(branch_id)


def normalize_flow_aliases(job: JobDef) -> None:
    """Convert edges pointing to alias flows (e.g. 'J1.f1') to the parent block id ('f1')."""
    if not job.flow_alias_to_parent:
        return

    alias_map = job.flow_alias_to_parent
    for edge in job.precedes:
        if edge.dst_id in alias_map:
            edge.dst_id = alias_map[edge.dst_id]


# ---------- Cypher generation ----------

def generate_cypher(job: JobDef) -> str:
    lines: List[str] = []

    # Job - Create Job node with source file path
    source_file = job.source_file.replace("\\", "\\\\").replace("'", "\\'")  # Escape for Cypher
    lines.append(f"MERGE (:Job {{name: '{job.name}', sourceFile: '{source_file}'}});")

    # Steps
    for step in job.steps.values():
        if step.step_kind == "CHUNK":
            # For chunk-based steps, create step with reader, processor, writer info
            lines.append(
                "MERGE (:Step {name: '%s', stepKind: '%s', "
                "readerBean: '%s', readerClass: '%s', "
                "processorBean: '%s', processorClass: '%s', "
                "writerBean: '%s', writerClass: '%s'});" %
                (step.name, step.step_kind,
                 step.reader_bean, step.reader_class,
                 step.processor_bean, step.processor_class,
                 step.writer_bean, step.writer_class)
            )
        else:
            # For tasklet-based steps
            lines.append(
                "MERGE (:Step {name: '%s', stepKind: '%s', implBean: '%s', className: '%s'});" %
                (step.name, step.step_kind, step.impl_bean, step.class_name)
            )

    # Blocks
    for block in job.blocks.values():
        lines.append(
            "MERGE (:Block {id: '%s', blockType: '%s'});" %
            (block.id, block.block_type)
        )

    # Decisions
    for dec in job.decisions.values():
        lines.append(
            "MERGE (:Decision {name: '%s', deciderBean: '%s', className: '%s'});" %
            (dec.name, dec.decider_bean, dec.class_name)
        )

    # Listeners
    for listener in job.listeners.values():
        lines.append(
            "MERGE (:Listener {name: '%s', scope: '%s', implBean: '%s'});" %
            (listener.name, listener.scope, listener.impl_bean)
        )

    # Job CONTAINS
    for sid in job.job_contains_steps:
        lines.append(
            "MATCH (j:Job {name:'%s'}) "
            "MATCH (s:Step {name:'%s'}) "
            "MERGE (j)-[:CONTAINS]->(s);" % (job.name, sid)
        )

    for bid in job.job_contains_blocks:
        lines.append(
            "MATCH (j:Job {name:'%s'}) "
            "MATCH (b:Block {id:'%s'}) "
            "MERGE (j)-[:CONTAINS]->(b);" % (job.name, bid)
        )

    # Block CONTAINS
    for block in job.blocks.values():
        for sid in block.contains_steps:
            lines.append(
                "MATCH (b:Block {id:'%s'}) "
                "MATCH (s:Step {name:'%s'}) "
                "MERGE (b)-[:CONTAINS]->(s);" % (block.id, sid)
            )
        for child_bid in block.contains_blocks:
            lines.append(
                "MATCH (b1:Block {id:'%s'}) "
                "MATCH (b2:Block {id:'%s'}) "
                "MERGE (b1)-[:CONTAINS]->(b2);" % (block.id, child_bid)
            )

    # ENTRY
    if job.job_entry_id and job.job_entry_kind:
        if job.job_entry_kind == "step":
            lines.append(
                "MATCH (j:Job {name:'%s'})"
                " MATCH (n:Step {name:'%s'}) "
                "MERGE (j)-[:ENTRY]->(n);" % (job.name, job.job_entry_id)
            )
        elif job.job_entry_kind == "block":
            lines.append(
                "MATCH (j:Job {name:'%s'})"
                " MATCH (n:Block {id:'%s'}) "
                "MERGE (j)-[:ENTRY]->(n);" % (job.name, job.job_entry_id)
            )

    for block in job.blocks.values():
        if block.entry_node and block.entry_kind:
            if block.entry_kind == "step":
                lines.append(
                    "MATCH (b:Block {id:'%s'}) MATCH (n:Step {name:'%s'}) "
                    "MERGE (b)-[:ENTRY]->(n);" % (block.id, block.entry_node)
                )
            elif block.entry_kind == "decision":
                lines.append(
                    "MATCH (b:Block {id:'%s'}) MATCH (n:Decision {name:'%s'}) "
                    "MERGE (b)-[:ENTRY]->(n);" % (block.id, block.entry_node)
                )

    # PRECEDES edges
    def dst_pattern(dst_id: str) -> str:
        if dst_id in job.blocks:
            return "(dst:Block {id:'%s'})" % dst_id
        if dst_id in job.steps:
            return "(dst:Step {name:'%s'})" % dst_id
        if dst_id in job.decisions:
            return "(dst:Decision {name:'%s'})" % dst_id
        # fallback: assume step
        return "(dst:Step {name:'%s'})" % dst_id

    for edge in job.precedes:
        if edge.src_kind == "step":
            src_pat = "(src:Step {name:'%s'})" % edge.src_id
        elif edge.src_kind == "block":
            src_pat = "(src:Block {id:'%s'})" % edge.src_id
        else:  # decision
            src_pat = "(src:Decision {name:'%s'})" % edge.src_id

        dst_pat = dst_pattern(edge.dst_id)
        lines.append(
            "MATCH %s MATCH %s "
            "MERGE (src)-[:PRECEDES {on:'%s'}]->(dst);" %
            (src_pat, dst_pat, edge.on)
        )

    # HAS_LISTENER edges
    for listener_name, listener in job.listeners.items():
        if listener.scope == "JOB":
            lines.append(
                "MATCH (j:Job {name:'%s'}) MATCH (l:Listener {name:'%s'}) "
                "MERGE (j)-[:HAS_LISTENER]->(l);" %
                (job.name, listener_name)
            )

    # (Step-level / chunk-level listeners can be added similarly if present in XML)

    return "\n".join(lines)

def execute_cypher_statements(uri: str, user: str, password: str, cypher: str) -> None:
    
    statements = [s.strip() for s in cypher.split(";") if s.strip()]
    driver = GraphDatabase.driver(uri, auth=(user, password))
    with driver.session() as session:
        for stmt in statements:
            session.run(stmt)
    driver.close()


def find_xml_files(directory: str) -> List[str]:
    """Recursively find all XML files in directory and subdirectories, excluding pom.xml"""
    xml_files = []
    directory_path = Path(directory)
    
    if not directory_path.exists():
        raise ValueError(f"Directory does not exist: {directory}")
    
    if not directory_path.is_dir():
        raise ValueError(f"Path is not a directory: {directory}")
    
    # Recursively find all XML files
    for xml_file in directory_path.rglob("*.xml"):
        # Exclude pom.xml files
        if xml_file.name.lower() != "pom.xml":
            xml_files.append(str(xml_file))
    
    return xml_files


def extract_bean_definitions(xml_path: str) -> Dict[str, str]:
    """
    Extract bean definitions from an XML file.
    
    Args:
        xml_path: Path to the XML file
        
    Returns:
        Dictionary mapping bean ID to class name
    """
    bean_map: Dict[str, str] = {}
    
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        
        # Extract all bean definitions
        for bean_el in root.findall(f".//{N_BEANS}bean"):
            bean_id = bean_el.get("id")
            bean_class = bean_el.get("class", "")
            if bean_id and bean_class:
                bean_map[bean_id] = bean_class
        
        return bean_map
    except Exception as e:
        print(f"  Warning: Failed to extract beans from {xml_path}: {e}")
        return bean_map


def build_global_bean_map(xml_files: List[str]) -> Dict[str, str]:
    """
    Build a global bean map from all XML files (first pass).
    
    Args:
        xml_files: List of XML file paths
        
    Returns:
        Dictionary mapping bean ID to class name across all files
    """
    global_bean_map: Dict[str, str] = {}
    
    print("\n=== First Pass: Building Global Bean Map ===")
    for xml_file in xml_files:
        bean_map = extract_bean_definitions(xml_file)
        if bean_map:
            print(f"  {os.path.basename(xml_file)}: Found {len(bean_map)} bean(s)")
            # Merge into global map, with warning on duplicates
            for bean_id, bean_class in bean_map.items():
                if bean_id in global_bean_map and global_bean_map[bean_id] != bean_class:
                    print(f"    Warning: Bean ID '{bean_id}' redefined. "
                          f"Previous: {global_bean_map[bean_id]}, New: {bean_class}")
                global_bean_map[bean_id] = bean_class
    
    print(f"\nGlobal bean map built: {len(global_bean_map)} unique bean(s)")
    return global_bean_map


def parse_directory(directory: str) -> List[JobDef]:
    """
    Parse all XML files in directory and subdirectories, returning a single merged JobDef.
    Uses a two-pass approach:
    1. First pass: Build global bean map from all XML files
    2. Second pass: Parse batch jobs using the global bean map
    
    This ensures bean references across different XML files are resolved correctly.
    """
    xml_files = find_xml_files(directory)
    
    if not xml_files:
        raise ValueError(f"No XML files found in directory: {directory}")
    
    print(f"Found {len(xml_files)} XML file(s) to parse:")
    for xml_file in xml_files:
        print(f"  - {xml_file}")
    
    # FIRST PASS: Build global bean map from all XML files
    global_bean_map = build_global_bean_map(xml_files)
    
    print(f"\nTotal beans in global map: {len(global_bean_map)}")
    # SECOND PASS: Parse batch jobs using the global bean map
    print("\n=== Second Pass: Parsing Batch Jobs ===")
    all_job_defs = []
    
    for xml_file in xml_files:
        try:
            print(f"\nParsing: {os.path.basename(xml_file)}")
            job_defs = parse_spring_batch_xml(xml_file, global_bean_map)
            all_job_defs.extend(job_defs)
            if job_defs:
                print(f"  Found {len(job_defs)} job(s): {[j.name for j in job_defs]}")
            else:
                print(f"  No batch jobs found")
            
            # Show which beans were resolved for steps and decisions in this file
            for job in job_defs:
                # Count resolved beans for tasklet steps
                tasklet_steps = [s for s in job.steps.values() if s.step_kind == "TASKLET"]
                chunk_steps = [s for s in job.steps.values() if s.step_kind == "CHUNK"]
                
                resolved_tasklet_steps = sum(1 for step in tasklet_steps if step.class_name)
                unresolved_tasklet_steps = sum(1 for step in tasklet_steps if step.impl_bean and not step.class_name)
                
                # For chunk steps, count if all three beans are resolved
                resolved_chunk_steps = sum(1 for step in chunk_steps 
                                          if (not step.reader_bean or step.reader_class) and
                                             (not step.processor_bean or step.processor_class) and
                                             (not step.writer_bean or step.writer_class))
                unresolved_chunk_beans = sum(
                    (1 if step.reader_bean and not step.reader_class else 0) +
                    (1 if step.processor_bean and not step.processor_class else 0) +
                    (1 if step.writer_bean and not step.writer_class else 0)
                    for step in chunk_steps
                )
                
                resolved_decisions = sum(1 for dec in job.decisions.values() if dec.class_name)
                unresolved_decisions = sum(1 for dec in job.decisions.values() if dec.decider_bean and not dec.class_name)
                
                total_steps = len(job.steps)
                if total_steps > 0 or resolved_decisions > 0 or unresolved_decisions > 0:
                    msg_parts = []
                    if tasklet_steps:
                        msg_parts.append(f"{resolved_tasklet_steps}/{len(tasklet_steps)} tasklet step bean(s)")
                    if chunk_steps:
                        msg_parts.append(f"{resolved_chunk_steps}/{len(chunk_steps)} chunk step(s)")
                    if unresolved_chunk_beans > 0:
                        msg_parts.append(f"{unresolved_chunk_beans} unresolved chunk bean(s)")
                    
                    print(f"    Job '{job.name}': Resolved {', '.join(msg_parts)}, "
                          f"{resolved_decisions}/{len(job.decisions)} decision bean(s)")
                    
                    if unresolved_tasklet_steps > 0:
                        print(f"      ⚠️  {unresolved_tasklet_steps} unresolved tasklet step bean(s)")
                    if unresolved_chunk_beans > 0:
                        print(f"      ⚠️  {unresolved_chunk_beans} unresolved chunk bean reference(s)")
                    if unresolved_decisions > 0:
                        print(f"      ⚠️  {unresolved_decisions} unresolved decision bean(s)")
        except Exception as e:
            print(f"  Warning: Failed to parse {xml_file}: {e}")
            import traceback
            traceback.print_exc()
            continue
    
    if not all_job_defs:
        raise ValueError(f"No valid job definitions found in directory: {directory}")
    
    print(f"\n=== Summary ===")
    print(f"Total jobs found: {len(all_job_defs)}")
    print(f"Job details:")
    for job in all_job_defs:
        print(f"  - '{job.name}' from {os.path.basename(job.source_file)}")
    
    # Calculate overall statistics
    total_steps = sum(len(job.steps) for job in all_job_defs)
    total_tasklet_steps = sum(sum(1 for s in job.steps.values() if s.step_kind == "TASKLET") for job in all_job_defs)
    total_chunk_steps = sum(sum(1 for s in job.steps.values() if s.step_kind == "CHUNK") for job in all_job_defs)
    total_decisions = sum(len(job.decisions) for job in all_job_defs)
    total_listeners = sum(len(job.listeners) for job in all_job_defs)
    
    resolved_tasklet_steps = sum(
        sum(1 for step in job.steps.values() if step.step_kind == "TASKLET" and step.class_name) 
        for job in all_job_defs
    )
    unresolved_tasklet_steps = sum(
        sum(1 for step in job.steps.values() if step.step_kind == "TASKLET" and step.impl_bean and not step.class_name) 
        for job in all_job_defs
    )
    
    # For chunk steps, count unresolved beans
    unresolved_chunk_beans = sum(
        sum(
            (1 if step.reader_bean and not step.reader_class else 0) +
            (1 if step.processor_bean and not step.processor_class else 0) +
            (1 if step.writer_bean and not step.writer_class else 0)
            for step in job.steps.values() if step.step_kind == "CHUNK"
        )
        for job in all_job_defs
    )
    
    resolved_decisions = sum(sum(1 for dec in job.decisions.values() if dec.class_name) for job in all_job_defs)
    unresolved_decisions = sum(sum(1 for dec in job.decisions.values() if dec.decider_bean and not dec.class_name) for job in all_job_defs)
    
    print(f"\nTotal Steps: {total_steps} (Tasklet: {total_tasklet_steps}, Chunk: {total_chunk_steps})")
    print(f"  Tasklet Steps - Resolved: {resolved_tasklet_steps}, Unresolved: {unresolved_tasklet_steps}")
    if total_chunk_steps > 0:
        print(f"  Chunk Steps: {total_chunk_steps} (Unresolved beans: {unresolved_chunk_beans})")
    print(f"Total Decisions: {total_decisions} (Resolved: {resolved_decisions}, Unresolved: {unresolved_decisions})")
    print(f"Total Listeners: {total_listeners}")
    
    if unresolved_tasklet_steps > 0 or unresolved_chunk_beans > 0 or unresolved_decisions > 0:
        print(f"\n⚠️  There are unresolved bean references. Check the warnings above for details.")
        
        # Print list of tasklet steps with unresolved beans
        if unresolved_tasklet_steps > 0:
            print(f"\n⚠️  Tasklet Steps with unresolved bean references:")
            for job in all_job_defs:
                unresolved_step_list = [(step.name, step.impl_bean) for step in job.steps.values() 
                                       if step.step_kind == "TASKLET" and step.impl_bean and not step.class_name]
                if unresolved_step_list:
                    print(f"  Job '{job.name}' (from: {job.source_file}):")
                    for step_name, bean_ref in unresolved_step_list:
                        print(f"    - Step '{step_name}' -> Bean '{bean_ref}'")
        
        # Print list of chunk steps with unresolved beans
        if unresolved_chunk_beans > 0:
            print(f"\n⚠️  Chunk Steps with unresolved bean references:")
            for job in all_job_defs:
                chunk_steps_with_issues = []
                for step in job.steps.values():
                    if step.step_kind == "CHUNK":
                        unresolved = []
                        if step.reader_bean and not step.reader_class:
                            unresolved.append(f"reader='{step.reader_bean}'")
                        if step.processor_bean and not step.processor_class:
                            unresolved.append(f"processor='{step.processor_bean}'")
                        if step.writer_bean and not step.writer_class:
                            unresolved.append(f"writer='{step.writer_bean}'")
                        if unresolved:
                            chunk_steps_with_issues.append((step.name, unresolved))
                
                if chunk_steps_with_issues:
                    print(f"  Job '{job.name}' (from: {job.source_file}):")
                    for step_name, unresolved_list in chunk_steps_with_issues:
                        print(f"    - Step '{step_name}' -> {', '.join(unresolved_list)}")
        
        # Print list of decisions with unresolved beans
        if unresolved_decisions > 0:
            print(f"\n⚠️  Decisions with unresolved bean references:")
            for job in all_job_defs:
                unresolved_decision_list = [(dec.name, dec.decider_bean) for dec in job.decisions.values() 
                                           if dec.decider_bean and not dec.class_name]
                if unresolved_decision_list:
                    print(f"  Job '{job.name}' (from: {job.source_file}):")
                    for dec_name, bean_ref in unresolved_decision_list:
                        print(f"    - Decision '{dec_name}' -> Bean '{bean_ref}'")
     
    return all_job_defs


# ---------- Example entry point ----------

if __name__ == "__main__":
    # Point this to your directory containing Spring Batch XML files
    # Can use single file or directory
    xml_directory = "sample_data"  # Change this to your directory path
    uri = "bolt://localhost:7687"
    user = "neo4j"
    password = "Welcome@321"

    # Parse all XML files in directory and merge into single JobDef
    job_defs = parse_directory(xml_directory)
    print(f"\nParsed and merged job definitions: {job_defs}")
    # Generate and optionally execute Cypher statements
    cypher = generate_cypher(job_defs[0])
    # print(cypher)
    # execute_cypher_statements(uri, user, password, cypher)
    
    # For now just print; you can paste into Neo4j Browser,
    # or execute via neo4j Python driver.
    
