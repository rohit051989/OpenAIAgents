"""
Call Hierarchy Extension V2 for Spring Batch Jobs

This is a redesigned version that handles complex legacy Spring Batch projects
with a more scalable architecture:

1. Scans ALL Spring XML files (not just job XMLs)
2. Creates two global bean maps (by beanId and by beanClass) with comprehensive BeanDef objects
3. Handles dependencies with proper resolution and pending processing
4. Leverages neo4j_direct_step_loader for XML scanning and job parsing
5. More robust for real-world legacy projects

Architecture:
- BeanDef: Comprehensive bean definition with all metadata
- Two Global Maps: Fast lookup by both beanId and beanClass
- Lazy dependency resolution with pending markers
- Reuses existing JavaCallHierarchyParser and DAOAnalyzer
"""

from __future__ import annotations
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path
import re
import xml.etree.ElementTree as ET

import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - [%(pathname)s:%(lineno)d %(funcName)s] - %(message)s"
)
logger = logging.getLogger(__name__)

# Import from existing modules
from classes.DataClasses import BeanDef
from classes.JavaCallHierarchyParser import JavaCallHierarchyParser
from classes.SpringBeanRegistry import SpringBeanRegistry
from classes.DataClasses import (
    JobDef
)
from classes.DataClasses import (
    ClassInfo
)


def enrich_with_call_hierarchy_v2(
    job_defs: List[JobDef],
    registry: SpringBeanRegistry,
    global_bean_map: Dict[str, Tuple[str, str, str]]
) -> List[JobDef]:
    """
    Step 4-5: Build call hierarchy using the comprehensive bean registry.
    This is the enhanced version that leverages dual-indexed bean maps.
    
    Note: DB operation analysis has been moved to a separate script (db_operation_enricher.py)
    to allow for configurable analysis strategies after the graph is built.
    
    Args:
        job_defs: List of JobDef objects from parse_directory
        registry: SpringBeanRegistry with all beans
        global_bean_map: Original global bean map for compatibility
        
    Returns:
        Enriched JobDef list with call hierarchy
    """
    logger.info(" " + "=" * 80)
    logger.info("Step 4-5: Building Call Hierarchy (V2)")
    logger.info("=" * 80)
    
    parser = JavaCallHierarchyParser()
    
    all_classes = {}
    parsed_classes_cache = set()  # Track what we've already parsed
    
    # Process initial job step classes
    logger.info("   Processing Job Step Classes:")
    for job in job_defs:
        logger.info(f"     Job: {job.name}")
        
        for step_name, step in job.steps.items():
            logger.info(f"      Step: {step_name} ({step.step_kind})")
            
            if step.step_kind == "TASKLET" and step.class_source_path:
                _parse_and_enrich_class(
                    step.impl_bean, step.class_source_path, parser, 
                    registry, all_classes, parsed_classes_cache
                )
            
            elif step.step_kind == "CHUNK":
                if step.reader_source_path:
                    _parse_and_enrich_class(
                        step.reader_bean, step.reader_source_path, parser,
                        registry, all_classes, parsed_classes_cache
                    )
                if step.processor_source_path:
                    _parse_and_enrich_class(
                        step.processor_bean, step.processor_source_path, parser,
                        registry, all_classes, parsed_classes_cache
                    )
                if step.writer_source_path:
                    _parse_and_enrich_class(
                        step.writer_bean, step.writer_source_path, parser,
                        registry, all_classes, parsed_classes_cache
                    )
    
    # Recursive parsing of referenced classes
    logger.info("   Recursively Parsing Referenced Classes:")
    iteration = 1
    max_iterations = 20  # Increased for complex projects
    
    while iteration <= max_iterations:
        logger.info(f"     Iteration {iteration}:")
        
        # Collect all referenced classes not yet parsed
        classes_to_parse = set()
        for class_info in all_classes.values():
            for method_def in class_info.methods.values():
                for call in method_def.calls:
                    if (call.target_class and 
                        call.target_class not in parsed_classes_cache and
                        call.target_class.startswith('com.')):
                        classes_to_parse.add(call.target_class)
        
        if not classes_to_parse:
            logger.info(f"      No new classes to parse. Stopping.")
            break
        
        logger.info(f"      Found {len(classes_to_parse)} new classes to parse")
        
        newly_parsed = 0
        for class_fqn in classes_to_parse:
            logger.info(f"        Processing class: {class_fqn}")
            # Use registry for faster lookup
            source_path = _find_source_from_registry(class_fqn, registry)
            
            # Fallback to original_bean_map
            if not source_path:
                source_path = _find_source_from_bean_map_v2(class_fqn, global_bean_map)
            
            # Fallback to file system search
            if not source_path:
                source_path = _find_java_source_by_fqn_v2(class_fqn, job_defs)
            
            if source_path:
                # Find bean_id from registry for dependency resolution
                bean_id = _find_bean_id_from_registry(class_fqn, registry)
                logger.info(f"          Processing class {class_fqn} With Source: {source_path} and (bean_id: {bean_id})")
                if _parse_and_enrich_class(
                    bean_id, source_path, parser, registry, 
                    all_classes, parsed_classes_cache
                ):
                    newly_parsed += 1
            else:
                parsed_classes_cache.add(class_fqn)  # Mark as attempted
        
        logger.info(f"      Successfully parsed {newly_parsed} new classes")
        
        if newly_parsed == 0:
            break
        
        iteration += 1
    
    # Note: DB operation analysis moved to separate script (db_operation_enricher.py)
    # Note: Stored procedure analysis moved to separate script (procedure_call_enricher.py)
    # Note: Shell script execution analysis moved to separate script (shell_execution_enricher.py)
    # This allows for configurable analysis strategies after graph is built
    
    # Build call hierarchy graph: populate called_classes for each class
    logger.info("   Building Call Hierarchy Graph:")
    for class_info in all_classes.values():
        for method_def in class_info.methods.values():
            for call in method_def.calls:
                if call.target_class and call.target_class in all_classes:
                    class_info.called_classes.add(call.target_class)
    
    # Store enrichment data
    logger.info(" " + "=" * 80)
    logger.info("Enrichment Summary")
    logger.info("=" * 80)
    logger.info(f"  Total Classes Parsed: {len(all_classes)}")
    logger.info(f"  Total Methods: {sum(len(c.methods) for c in all_classes.values())}")
    logger.info(f"  Total Method Calls: {sum(sum(len(m.calls) for m in c.methods.values()) for c in all_classes.values())}")
      
    # Build job-specific enrichment: only classes used in that job's steps
    logger.info("   Building Job-Specific Call Graphs:")
    for job in job_defs:
        if not hasattr(job, 'enrichment'):
            job.enrichment = {}
        
        # Collect step classes (classes directly used in job steps)
        step_classes = set()
        for step in job.steps.values():
            if step.step_kind == "TASKLET" and step.class_name:
                step_classes.add(step.class_name)
            elif step.step_kind == "CHUNK":
                if step.reader_class:
                    step_classes.add(step.reader_class)
                if step.processor_class:
                    step_classes.add(step.processor_class)
                if step.writer_class:
                    step_classes.add(step.writer_class)
        
        # Store only step classes (with their call hierarchy)
        job.enrichment['step_classes'] = {fqn: all_classes[fqn] for fqn in step_classes if fqn in all_classes}
        job.enrichment['all_classes_cache'] = all_classes  # Reference to all classes for traversal
        job.enrichment['registry'] = registry
        
        logger.info(f"    Job '{job.name}': {len(step_classes)} step classes")
    
    return job_defs


def _parse_and_enrich_class(
    bean_id: Optional[str],
    source_path: str,
    parser: JavaCallHierarchyParser,
    registry: SpringBeanRegistry,
    all_classes: Dict[str, ClassInfo],
    parsed_cache: Set[str]
) -> bool:
    """
    Helper to parse a Java class and enrich with bean dependencies.
    Returns True if successfully parsed, False otherwise.
    """
    if not Path(source_path).exists():
        return False
    
    # Parse Java file
    class_info = parser.parse_java_file(source_path)
    if not class_info:
        return False
    
    # Mark as parsed
    logger.info(f"          Parsed class: {class_info.fqn} from {source_path}")
    parsed_cache.add(class_info.fqn)
    
    # Apply bean dependencies from registry
    if bean_id:
        composite_key = registry.make_composite_key(bean_id, class_info.fqn)
        bean_def = registry.get_by_composite_key(composite_key)
        #bean_def = registry.get_by_id(bean_id)
        if bean_def:
            _apply_bean_dependencies_v2(class_info, bean_def)
            bean_def.class_info = class_info
    else:
        # Try to find bean by class
        bean_defs = registry.get_by_class(class_info.fqn)
        if bean_defs:
            _apply_bean_dependencies_v2(class_info, bean_defs[0])
    
    # Store in all_classes
    all_classes[class_info.fqn] = class_info
    
    # Update registry with parsed class info
    #if bean_id:
    #    composite_key = registry.make_composite_key(bean_id, class_info.fqn)
    #    bean_def = registry.get_by_composite_key(composite_key)
        #bean_def = registry.get_by_id(bean_id)
    #    if bean_def:
    #        bean_def.class_info = class_info
    
    return True


def _apply_bean_dependencies_v2(class_info: ClassInfo, bean_def: BeanDef):
    """
    Apply bean dependencies using the registry for fast lookup.
    Updates field types and method call targets.
    Stores resolved dependencies in the BeanDef for later reference.
    """
    field_mappings = {}
    all_deps = bean_def.get_all_dependencies()
    
    for dep in all_deps.items():
        field_name, (dep_type, dep_bean_id, dep_bean_class_obj) = dep
        if dep_type == "type:ref" and field_name in class_info.fields and dep_bean_class_obj:
            old_type = class_info.fields[field_name]
            dep_bean_class = dep_bean_class_obj.split(':')[-1]  # Extract actual class name
            class_info.fields[field_name] = dep_bean_class
            field_mappings[field_name] = (old_type, dep_bean_class)
            logger.info(f"          Resolved field '{field_name}' -> {dep_bean_class}")
    
    # Store resolved dependencies in BeanDef
    if field_mappings:
        bean_def.resolved_dependencies = field_mappings
        logger.info(f"          Stored {len(field_mappings)} resolved dependencies in BeanDef '{bean_def.bean_id}'")
    
    # Update method call targets
    if field_mappings:
        updated_count = 0
        for method_def in class_info.methods.values():
            for call in method_def.calls:
                if call.target_class:
                    for field_name, (old_type, new_type) in field_mappings.items():
                        if call.target_class == old_type or call.target_class.endswith('.' + old_type):
                            call.target_class = new_type
                            updated_count += 1
                            break
        if updated_count > 0:
            logger.info(f"          Updated {updated_count} method call(s)")


def _find_source_from_registry(class_fqn: str, registry: SpringBeanRegistry) -> Optional[str]:
    """Find source path using the bean registry"""
    bean_defs = registry.get_by_class(class_fqn)
    for bean_def in bean_defs:
        if bean_def.class_source_path:
            return bean_def.class_source_path
    return None


def _find_bean_id_from_registry(class_fqn: str, registry: SpringBeanRegistry) -> Optional[str]:
    """Find bean ID for a class using the registry"""
    bean_defs = registry.get_by_class(class_fqn)
    if bean_defs:
        return bean_defs[0].bean_id
    return None


def _find_source_from_bean_map_v2(class_fqn: str, global_bean_map: Dict[str, Tuple[str, str, str]]) -> Optional[str]:
    """Fallback: Find source path from original global_bean_map with composite keys"""
    for composite_key, (bean_class, source_path, _) in global_bean_map.items():  # Unpack 3-tuple
        if bean_class == class_fqn and source_path:
            return source_path
    return None


def _find_java_source_by_fqn_v2(fqn: str, job_defs: List[JobDef]) -> Optional[str]:
    """Fallback: Search for Java source file by FQN"""
    file_path_parts = fqn.split('.')
    expected_path = '/'.join(file_path_parts) + '.java'
    
    for job in job_defs:
        for step in job.steps.values():
            for source_path in [step.class_source_path, step.reader_source_path,
                               step.processor_source_path, step.writer_source_path]:
                if source_path:
                    source_dir = Path(source_path).parent
                    while source_dir and source_dir.name not in ['java', 'src']:
                        source_dir = source_dir.parent
                    
                    if source_dir:
                        potential_path = source_dir / expected_path
                        if potential_path.exists():
                            return str(potential_path)
    
    return None

