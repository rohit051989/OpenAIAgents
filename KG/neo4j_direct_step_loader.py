from __future__ import annotations
import os
from typing import Dict, List, Literal, Tuple
import xml.etree.ElementTree as ET
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - [%(pathname)s:%(lineno)d %(funcName)s] - %(message)s"
)
logger = logging.getLogger(__name__)

from classes.DataClasses import (
    ListenerDef, StepDef, BlockDef, DecisionDef, PrecedesEdge, JobDef
)

# ---------- Model types ----------

ExecNodeKind = Literal["step", "block", "decision"]


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
        bean_class_map: global bean map.
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()
    job_defs: List[JobDef] = []

    # Find the job
    job_els = root.findall(f".//{N_BATCH}job")
    if not job_els:
        logger.info(f"No <batch:job> found in XML: {xml_path}")
        return job_defs
    else:
        logger.info(f"Found {len(job_els)} <batch:job>(s) in XML: {xml_path}")
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
            # Extract class name and source path from tuple if bean_class_map contains tuples
            bean_info = bean_class_map.get(ref, ("", ""))
            impl_class = bean_info[0] if isinstance(bean_info, tuple) else bean_info
            source_path = bean_info[1] if isinstance(bean_info, tuple) else ""
            
            # Flag if bean reference exists but class not found
            if ref and not impl_class:
                logger.info(f"Warning: Listener references bean '{ref}' but class not found in bean definitions")
            
            job.listeners[ref] = ListenerDef(
                name=ref,
                scope="JOB",
                impl_bean=impl_class or ref,
                source_path=source_path,
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
        
        # Resolve class names and source paths from bean map
        reader_info = bean_class_map.get(reader_bean, ("", "")) if reader_bean else ("", "")
        processor_info = bean_class_map.get(processor_bean, ("", "")) if processor_bean else ("", "")
        writer_info = bean_class_map.get(writer_bean, ("", "")) if writer_bean else ("", "")
        
        reader_class = reader_info[0] if isinstance(reader_info, tuple) else (reader_info if reader_info else "")
        reader_source = reader_info[1] if isinstance(reader_info, tuple) else ""
        processor_class = processor_info[0] if isinstance(processor_info, tuple) else (processor_info if processor_info else "")
        processor_source = processor_info[1] if isinstance(processor_info, tuple) else ""
        writer_class = writer_info[0] if isinstance(writer_info, tuple) else (writer_info if writer_info else "")
        writer_source = writer_info[1] if isinstance(writer_info, tuple) else ""
        
        # Flag unresolved bean references
        if reader_bean and not reader_class:
            logger.info(f"Warning: Step '{sid}' reader references bean '{reader_bean}' but class not found")
        if processor_bean and not processor_class:
            logger.info(f"Warning: Step '{sid}' processor references bean '{processor_bean}' but class not found")
        if writer_bean and not writer_class:
            logger.info(f"Warning: Step '{sid}' writer references bean '{writer_bean}' but class not found")
        
        if sid not in job.steps:
            job.steps[sid] = StepDef(
                name=sid,
                step_kind=step_kind,
                impl_bean="",  # Not used for chunk steps
                class_name="",  # Not used for chunk steps
                reader_bean=reader_bean,
                reader_class=reader_class,
                reader_source_path=reader_source,
                processor_bean=processor_bean,
                processor_class=processor_class,
                processor_source_path=processor_source,
                writer_bean=writer_bean,
                writer_class=writer_class,
                writer_source_path=writer_source,
            )
    else:
        # TASKLET-based step
        step_kind = "TASKLET"
        impl_ref = tasklet_el.get("ref", "")
        
        # Resolve class name and source path from bean map
        bean_info = bean_class_map.get(impl_ref, ("", "")) if impl_ref else ("", "")
        class_name = bean_info[0] if isinstance(bean_info, tuple) else (bean_info if bean_info else "")
        source_path = bean_info[1] if isinstance(bean_info, tuple) else ""
        
        # Flag if bean reference exists but class not found
        if impl_ref and not class_name:
            logger.info(f"Warning: Step '{sid}' references bean '{impl_ref}' but class not found in bean definitions")
        
        if sid not in job.steps:
            job.steps[sid] = StepDef(
                name=sid,
                step_kind=step_kind,
                impl_bean=impl_ref or sid,
                class_name=class_name,
                class_source_path=source_path,
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

    # Resolve decider class name and source path from bean map
    bean_info = bean_class_map.get(decider, ("", "")) if decider else ("", "")
    class_name = bean_info[0] if isinstance(bean_info, tuple) else (bean_info if bean_info else "")
    source_path = bean_info[1] if isinstance(bean_info, tuple) else ""
    
    # Flag if bean reference exists but class not found
    if decider and not class_name:
        logger.info(f"Warning: Decision '{did}' references bean '{decider}' but class not found in bean definitions")

    if did not in job.decisions:
        job.decisions[did] = DecisionDef(name=did, decider_bean=decider, class_name=class_name, class_source_path=source_path)

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
    #lines.append(f"MERGE (j:Job {{name: '{job.name}'}}) SET j.sourceFile = '{source_file}';")
    lines.append(f"""MERGE (j:Job {{id: '{job.name}', 
                 name: '{job.name}', 
                 sourceFile: '{source_file}'}}) 
                 ON CREATE SET j.createdAt = datetime(), j.enabled = true 
                 ON MATCH SET j.lastSeenAt = datetime();""")

    # Steps
    for step in job.steps.values():
        if step.step_kind == "CHUNK":
            # For chunk-based steps, create step with reader, processor, writer info
            # Escape paths for Cypher
            reader_src = step.reader_source_path.replace("\\", "\\\\").replace("'", "\\'") if step.reader_source_path else ""
            processor_src = step.processor_source_path.replace("\\", "\\\\").replace("'", "\\'") if step.processor_source_path else ""
            writer_src = step.writer_source_path.replace("\\", "\\\\").replace("'", "\\'") if step.writer_source_path else ""
            
            lines.append(
                "MERGE (:Step {name: '%s', stepKind: '%s', "
                "readerBean: '%s', readerClass: '%s', readerSourcePath: '%s', "
                "processorBean: '%s', processorClass: '%s', processorSourcePath: '%s', "
                "writerBean: '%s', writerClass: '%s', writerSourcePath: '%s'});" %
                (step.name, step.step_kind,
                 step.reader_bean, step.reader_class, reader_src,
                 step.processor_bean, step.processor_class, processor_src,
                 step.writer_bean, step.writer_class, writer_src)
            )
        else:
            # For tasklet-based steps
            # Escape path for Cypher
            class_src = step.class_source_path.replace("\\", "\\\\").replace("'", "\\'") if step.class_source_path else ""
            lines.append(
                "MERGE (:Step {name: '%s', stepKind: '%s', implBean: '%s', className: '%s', path: '%s'});" %
                (step.name, step.step_kind, step.impl_bean, step.class_name, class_src)
            )

    # Blocks
    for block in job.blocks.values():
        lines.append(
            "MERGE (:Block {id: '%s', blockType: '%s'});" %
            (block.id, block.block_type)
        )

    # Decisions
    for dec in job.decisions.values():
        # Escape path for Cypher
        dec_src = dec.class_source_path.replace("\\", "\\\\").replace("'", "\\'") if dec.class_source_path else ""
        lines.append(
            "MERGE (:Decision {name: '%s', deciderBean: '%s', className: '%s', path: '%s'});" %
            (dec.name, dec.decider_bean, dec.class_name, dec_src)
        )

    # Listeners
    for listener in job.listeners.values():
        # Escape path for Cypher
        listener_src = listener.source_path.replace("\\", "\\\\").replace("'", "\\'") if listener.source_path else ""
        lines.append(
            "MERGE (:Listener {name: '%s', scope: '%s', implBean: '%s', path: '%s'});" %
            (listener.name, listener.scope, listener.impl_bean, listener_src)
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


if __name__ == "__main__":
    # Point this to your directory containing Spring Batch XML files
    # Can use single file or directory
    #xml_directory = "sample_data"  # Change this to your directory path
    xml_directory = "SpringProjects"  # Change this to your directory path
    uri = "bolt://localhost:7687"
    user = "neo4j"
    password = "Rohit@123"  # Change this to your Neo4j password


def parse_directory(global_bean_map: Dict[str, Tuple[str, str]], xml_files: List[str]) -> List[JobDef]:
    """
    Parse all XML files in directory and subdirectories, returning a single merged JobDef.
    Uses a two-pass approach:
    1. First pass: Build global bean map from all XML files
    2. Second pass: Parse batch jobs using the global bean map

    This ensures bean references across different XML files are resolved correctly.
    """

    # SECOND PASS: Parse batch jobs using the global bean map
    logger.info(" === Second Pass: Parsing Batch Jobs ===")
    all_job_defs = []

    for xml_file in xml_files:
        try:
            logger.info(f" Parsing: {os.path.basename(xml_file)}")
            job_defs = parse_spring_batch_xml(xml_file, global_bean_map)
            all_job_defs.extend(job_defs)
            if job_defs:
                logger.info(f"  Found {len(job_defs)} job(s): {[j.name for j in job_defs]}")
            else:
                logger.info(f"  No batch jobs found")

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

                    logger.info(f"    Job '{job.name}': Resolved {', '.join(msg_parts)}, "
                          f"{resolved_decisions}/{len(job.decisions)} decision bean(s)")

                    if unresolved_tasklet_steps > 0:
                        logger.info(f"        {unresolved_tasklet_steps} unresolved tasklet step bean(s)")
                    if unresolved_chunk_beans > 0:
                        logger.info(f"        {unresolved_chunk_beans} unresolved chunk bean reference(s)")
                    if unresolved_decisions > 0:
                        logger.info(f"        {unresolved_decisions} unresolved decision bean(s)")
        except Exception as e:
            logger.info(f"Warning: Failed to parse {xml_file}: {e}")
            import traceback
            traceback.print_exc()
            continue

    if not all_job_defs:
        raise ValueError(f"No valid job definitions found in the provided XML files.")

    logger.info(f" === Summary ===")
    logger.info(f"Total jobs found: {len(all_job_defs)}")
    logger.info(f"Job details:")
    for job in all_job_defs:
        logger.info(f"  - '{job.name}' from {os.path.basename(job.source_file)}")

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

    logger.info(f" Total Steps: {total_steps} (Tasklet: {total_tasklet_steps}, Chunk: {total_chunk_steps})")
    logger.info(f"  Tasklet Steps - Resolved: {resolved_tasklet_steps}, Unresolved: {unresolved_tasklet_steps}")
    if total_chunk_steps > 0:
        logger.info(f"  Chunk Steps: {total_chunk_steps} (Unresolved beans: {unresolved_chunk_beans})")
    logger.info(f"Total Decisions: {total_decisions} (Resolved: {resolved_decisions}, Unresolved: {unresolved_decisions})")
    logger.info(f"Total Listeners: {total_listeners}")

    if unresolved_tasklet_steps > 0 or unresolved_chunk_beans > 0 or unresolved_decisions > 0:
        logger.info(f"   There are unresolved bean references. Check the warnings above for details.")

        # Print list of tasklet steps with unresolved beans
        if unresolved_tasklet_steps > 0:
            logger.info(f"   Tasklet Steps with unresolved bean references:")
            for job in all_job_defs:
                unresolved_step_list = [(step.name, step.impl_bean) for step in job.steps.values()
                                       if step.step_kind == "TASKLET" and step.impl_bean and not step.class_name]
                if unresolved_step_list:
                    logger.info(f"  Job '{job.name}' (from: {job.source_file}):")
                    for step_name, bean_ref in unresolved_step_list:
                        logger.info(f"    - Step '{step_name}' -> Bean '{bean_ref}'")

        # Print list of chunk steps with unresolved beans
        if unresolved_chunk_beans > 0:
            logger.info(f"   Chunk Steps with unresolved bean references:")
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
                    logger.info(f"  Job '{job.name}' (from: {job.source_file}):")
                    for step_name, unresolved_list in chunk_steps_with_issues:
                        logger.info(f"    - Step '{step_name}' -> {', '.join(unresolved_list)}")

        # Print list of decisions with unresolved beans
        if unresolved_decisions > 0:
            logger.info(f"   Decisions with unresolved bean references:")
            for job in all_job_defs:
                unresolved_decision_list = [(dec.name, dec.decider_bean) for dec in job.decisions.values()
                                           if dec.decider_bean and not dec.class_name]
                if unresolved_decision_list:
                    logger.info(f"  Job '{job.name}' (from: {job.source_file}):")
                    for dec_name, bean_ref in unresolved_decision_list:
                        logger.info(f"    - Decision '{dec_name}' -> Bean '{bean_ref}'")

    return all_job_defs

    # Parse all XML files in directory and merge into single JobDef
    #job_defs, global_bean_map = parse_directory(xml_directory)
    #logger.info(f" Parsed and merged job definitions: {job_defs}")
    # Generate and optionally execute Cypher statements
    #cypher = generate_cypher(job_defs[0])
    # logger.info(cypher)
    #execute_cypher_statements(uri, user, password, cypher)
    
    # For now just print; you can paste into Neo4j Browser,
    # or execute via neo4j Python driver.
    
