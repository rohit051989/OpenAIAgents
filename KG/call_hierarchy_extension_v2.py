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
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path
import re
import xml.etree.ElementTree as ET

# Import from existing modules
from neo4j_direct_step_loader_v2 import (
    JobDef, StepDef, find_xml_files, parse_directory,
    build_global_bean_map as original_build_global_bean_map
)
from call_hierarchy_extension import (
    JavaCallHierarchyParser, DAOAnalyzer, OracleProcedureAnalyzer, ShellScriptAnalyzer,
    ClassInfo
)


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


class SpringBeanRegistry:
    """
    Central registry for all Spring beans with dual-indexed maps.
    Provides fast lookup by both beanId and beanClass.
    """
    
    def __init__(self):
        self.beans_by_id: Dict[str, BeanDef] = {}
        self.beans_by_class: Dict[str, List[BeanDef]] = {}  # Multiple beans can have same class
        self.pending_processing: Set[str] = set()  # Bean IDs pending dependency processing
        
    def add_bean(self, bean_def: BeanDef):
        """Add a bean to both indexes"""
        # Add to ID index
        if bean_def.bean_id in self.beans_by_id:
            print(f"  Warning: Bean ID '{bean_def.bean_id}' already exists. Overwriting.")
        self.beans_by_id[bean_def.bean_id] = bean_def
        
        # Add to class index
        if bean_def.bean_class not in self.beans_by_class:
            self.beans_by_class[bean_def.bean_class] = []
        self.beans_by_class[bean_def.bean_class].append(bean_def)
        
        # Mark as pending if not processed
        if not bean_def.is_dependency_processed:
            self.pending_processing.add(bean_def.bean_id)
    
    def get_by_id(self, bean_id: str) -> Optional[BeanDef]:
        """Get bean by ID"""
        return self.beans_by_id.get(bean_id)
    
    def get_by_class(self, bean_class: str) -> List[BeanDef]:
        """Get all beans with the specified class"""
        return self.beans_by_class.get(bean_class, [])
    
    def mark_processed(self, bean_id: str):
        """Mark a bean as dependency-processed"""
        if bean_id in self.beans_by_id:
            self.beans_by_id[bean_id].is_dependency_processed = True
            self.pending_processing.discard(bean_id)
    
    def has_pending(self) -> bool:
        """Check if there are beans pending processing"""
        return len(self.pending_processing) > 0
    
    def get_stats(self) -> Dict[str, int]:
        """Get registry statistics"""
        return {
            'total_beans': len(self.beans_by_id),
            'unique_classes': len(self.beans_by_class),
            'pending_processing': len(self.pending_processing),
            'with_source_path': sum(1 for b in self.beans_by_id.values() if b.class_source_path)
        }



def build_global_bean_registry(spring_xml_files: List[str], original_bean_map: Dict[str, Tuple[str, str]]) -> SpringBeanRegistry:
    """
    Step 2: Build comprehensive bean registry with dual indexes.
    Creates BeanDef objects for all beans with proper dependency tracking.
    
    Args:
        spring_xml_files: List of Spring XML files to process
        original_bean_map: Original bean map for source path reference
        
    Returns:
        SpringBeanRegistry with all beans indexed
    """
    print("\n" + "=" * 80)
    print("Step 2: Building Global Bean Registry")
    print("=" * 80)
    
    registry = SpringBeanRegistry()
    
    
    # Process each XML file
    for xml_file in spring_xml_files:
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            ns = {'beans': 'http://www.springframework.org/schema/beans'}
            
            for bean_elem in root.findall('.//beans:bean', ns):
                bean_id = bean_elem.get('id')
                bean_class = bean_elem.get('class')
                
                if not bean_id or not bean_class:
                    continue
                
                # Extract simple class name
                bean_class_name = bean_class.split('.')[-1] if '.' in bean_class else bean_class
                
                # Get source path from original map
                source_path = None
                if bean_id in original_bean_map:
                    source_path = original_bean_map[bean_id][1]
                
                # Create BeanDef
                bean_def = BeanDef(
                    bean_id=bean_id,
                    bean_class=bean_class,
                    bean_class_name=bean_class_name,
                    class_source_path=source_path,
                    source_xml_file=xml_file
                )
                
                # Extract property dependencies
                for prop in bean_elem.findall('beans:property', ns):
                    prop_name = prop.get('name')
                    ref_bean_id = prop.get('ref')
                    prop_value = prop.get('value')
                    
                    if prop_name and ref_bean_id:
                        # Get referenced bean class if available
                        ref_bean_class = _resolve_dependency_class(ref_bean_id, registry, original_bean_map)
                        bean_def.property_dependencies[prop_name] = (f"type:ref",f"ref_bean_id:{ref_bean_id}", f"ref_bean_class:{ref_bean_class}")
                    elif prop_name and prop_value:
                        # Literal value, no dependency
                        bean_def.property_dependencies[prop_name] = (f"type:value",f"value:{prop_value}", "")
                
                # Extract constructor dependencies
                for arg in bean_elem.findall('beans:constructor-arg', ns):
                    ref_bean_id = arg.get('ref')
                    arg_name = arg.get('name')
                    arg_value = arg.get('value')

                    if ref_bean_id and not arg_value:
                        key = arg_name if arg_name else f"constructor_arg_{arg.get('index', '0')}"
                        ref_bean_class = _resolve_dependency_class(ref_bean_id, registry, original_bean_map)
                        bean_def.constructor_dependencies[key] = (f"type:ref",f"ref_bean_id:{ref_bean_id}", f"ref_bean_class:{ref_bean_class}")
                    
                    elif ref_bean_id and arg_value:
                        key = arg_name if arg_name else f"constructor_arg_{arg.get('index', '0')}"
                        bean_def.constructor_dependencies[key] = (f"type:value",f"value:{arg_value}", "")

                # Add to registry
                registry.add_bean(bean_def)
                
        except Exception as e:
            print(f"  Warning: Failed to process {xml_file}: {e}")
    
    # Print statistics
    stats = registry.get_stats()
    print(f"\n  Registry Statistics:")
    print(f"    Total Beans: {stats['total_beans']}")
    print(f"    Unique Classes: {stats['unique_classes']}")
    print(f"    With Source Path: {stats['with_source_path']}")
    print(f"    Pending Processing: {stats['pending_processing']}")
    
    return registry


def _resolve_dependency_class(ref_bean_id: str, registry: SpringBeanRegistry, 
                               original_bean_map: Dict[str, Tuple[str, str]]) -> str:
    """
    Helper to resolve dependency bean class.
    Returns the class name if available, otherwise empty string.
    """
    # Try registry first
    existing_bean = registry.get_by_id(ref_bean_id)
    if existing_bean:
        return existing_bean.bean_class
    
    # Try original bean map
    if ref_bean_id in original_bean_map:
        return original_bean_map[ref_bean_id][0]
    
    return ""


def enrich_with_call_hierarchy_v2(
    job_defs: List[JobDef],
    registry: SpringBeanRegistry,
    global_bean_map: Dict[str, Tuple[str, str]]
) -> List[JobDef]:
    """
    Step 4-5: Build call hierarchy using the comprehensive bean registry.
    This is the enhanced version that leverages dual-indexed bean maps.
    
    Args:
        job_defs: List of JobDef objects from parse_directory
        registry: SpringBeanRegistry with all beans
        global_bean_map: Original global bean map for compatibility
        
    Returns:
        Enriched JobDef list with call hierarchy
    """
    print("\n" + "=" * 80)
    print("Step 4-5: Building Call Hierarchy (V2)")
    print("=" * 80)
    
    parser = JavaCallHierarchyParser()
    dao_analyzer = DAOAnalyzer()
    procedure_analyzer = OracleProcedureAnalyzer()
    shell_analyzer = ShellScriptAnalyzer()
    
    all_classes = {}
    all_db_operations = []
    all_procedure_calls = []
    all_shell_executions = []
    parsed_classes_cache = set()  # Track what we've already parsed
    
    # Process initial job step classes
    print("\n  Processing Job Step Classes:")
    for job in job_defs:
        print(f"\n    Job: {job.name}")
        
        for step_name, step in job.steps.items():
            print(f"      Step: {step_name} ({step.step_kind})")
            
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
    print("\n  Recursively Parsing Referenced Classes:")
    iteration = 1
    max_iterations = 20  # Increased for complex projects
    
    while iteration <= max_iterations:
        print(f"\n    Iteration {iteration}:")
        
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
            print(f"      No new classes to parse. Stopping.")
            break
        
        print(f"      Found {len(classes_to_parse)} new classes to parse")
        
        newly_parsed = 0
        for class_fqn in classes_to_parse:
            # Use registry for faster lookup
            source_path = _find_source_from_registry(class_fqn, registry)
            
            # Fallback to global_bean_map
            if not source_path:
                source_path = _find_source_from_bean_map_v2(class_fqn, global_bean_map)
            
            # Fallback to file system search
            if not source_path:
                source_path = _find_java_source_by_fqn_v2(class_fqn, job_defs)
            
            if source_path:
                # Find bean_id from registry for dependency resolution
                bean_id = _find_bean_id_from_registry(class_fqn, registry)
                
                if _parse_and_enrich_class(
                    bean_id, source_path, parser, registry, 
                    all_classes, parsed_classes_cache
                ):
                    newly_parsed += 1
            else:
                parsed_classes_cache.add(class_fqn)  # Mark as attempted
        
        print(f"      Successfully parsed {newly_parsed} new classes")
        
        if newly_parsed == 0:
            break
        
        iteration += 1
    
    # Analyze DAO methods
    print("\n  Analyzing DAO Methods:")
    for class_info in all_classes.values():
        if dao_analyzer._is_dao_class(class_info):
            print(f"    DAO Class: {class_info.class_name}")
            for method_def in class_info.methods.values():
                db_op = dao_analyzer.analyze_method(method_def, class_info)
                if db_op:
                    method_def.db_operations.append(db_op)  # Attach to method
                    all_db_operations.append(db_op)  # Also collect for summary
                    print(f"      {method_def.method_name}() -> {db_op.operation_type} {db_op.table_name or '?'}")
    
    # Analyze Oracle/Database stored procedures
    print("\n  Analyzing Stored Procedure Calls:")
    for class_info in all_classes.values():
        for method_def in class_info.methods.values():
            proc_call = procedure_analyzer.analyze_method(method_def, class_info)
            if proc_call:
                method_def.procedure_calls.append(proc_call)  # Attach to method
                all_procedure_calls.append(proc_call)  # Also collect for summary
                proc_type = "Function" if proc_call.is_function else "Procedure"
                print(f"    {class_info.class_name}.{method_def.method_name}() -> {proc_call.database_type} {proc_type}: {proc_call.procedure_name}")
    
    # Analyze shell script executions
    print("\n  Analyzing Shell Script Executions:")
    for class_info in all_classes.values():
        for method_def in class_info.methods.values():
            shell_exec = shell_analyzer.analyze_method(method_def, class_info)
            if shell_exec:
                method_def.shell_executions.append(shell_exec)  # Attach to method
                all_shell_executions.append(shell_exec)  # Also collect for summary
                script_display = shell_exec.script_name if shell_exec.script_name else "[dynamic]"
                print(f"    {class_info.class_name}.{method_def.method_name}() -> {shell_exec.script_type} script: {script_display} ({shell_exec.execution_method})")
    
    # Build call hierarchy graph: populate called_classes for each class
    print("\n  Building Call Hierarchy Graph:")
    for class_info in all_classes.values():
        for method_def in class_info.methods.values():
            for call in method_def.calls:
                if call.target_class and call.target_class in all_classes:
                    class_info.called_classes.add(call.target_class)
    
    # Store enrichment data
    print("\n" + "=" * 80)
    print("Enrichment Summary")
    print("=" * 80)
    print(f"  Total Classes Parsed: {len(all_classes)}")
    print(f"  Total Methods: {sum(len(c.methods) for c in all_classes.values())}")
    print(f"  Total Method Calls: {sum(sum(len(m.calls) for m in c.methods.values()) for c in all_classes.values())}")
    print(f"  Total DB Operations: {len(all_db_operations)}")
    print(f"  Total Procedure Calls: {len(all_procedure_calls)}")
    print(f"  Total Shell Script Executions: {len(all_shell_executions)}")
    
    # Build job-specific enrichment: only classes used in that job's steps
    print("\n  Building Job-Specific Call Graphs:")
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
        
        print(f"    Job '{job.name}': {len(step_classes)} step classes")
    
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
    parsed_cache.add(class_info.fqn)
    
    # Apply bean dependencies from registry
    if bean_id:
        bean_def = registry.get_by_id(bean_id)
        if bean_def:
            _apply_bean_dependencies_v2(class_info, bean_def)
    else:
        # Try to find bean by class
        bean_defs = registry.get_by_class(class_info.fqn)
        if bean_defs:
            _apply_bean_dependencies_v2(class_info, bean_defs[0])
    
    # Store in all_classes
    all_classes[class_info.fqn] = class_info
    
    # Update registry with parsed class info
    if bean_id:
        bean_def = registry.get_by_id(bean_id)
        if bean_def:
            bean_def.class_info = class_info
    
    return True


def _apply_bean_dependencies_v2(class_info: ClassInfo, bean_def: BeanDef):
    """
    Apply bean dependencies using the registry for fast lookup.
    Updates field types and method call targets.
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
            print(f"          Resolved field '{field_name}' -> {dep_bean_class}")
    
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
            print(f"          Updated {updated_count} method call(s)")


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


def _find_source_from_bean_map_v2(class_fqn: str, global_bean_map: Dict[str, Tuple[str, str]]) -> Optional[str]:
    """Fallback: Find source path from original global_bean_map"""
    for bean_id, (bean_class, source_path) in global_bean_map.items():
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


def build_call_hierarchy_v2(root_directory: str) -> Tuple[List[JobDef], SpringBeanRegistry]:
    """
    Main entry point for V2 call hierarchy builder.
    Orchestrates all steps and returns enriched job definitions.
    
    Args:
        root_directory: Root directory containing Spring Batch projects
        
    Returns:
        Tuple of (enriched JobDef list, SpringBeanRegistry)
    """
    print("\n" + "=" * 80)
    print("CALL HIERARCHY BUILDER V2")
    print("=" * 80)
    
    # Step 1: Scan all Spring XML files
    spring_xml_files = find_xml_files(root_directory)

    # Step 2: Build original bean map for source paths
    original_bean_map = original_build_global_bean_map(spring_xml_files, root_directory)
    
    # Step 2: Build comprehensive bean registry
    registry = build_global_bean_registry(spring_xml_files, original_bean_map)
    
    # Step 3: Parse batch job definitions
    job_defs = parse_directory(original_bean_map, spring_xml_files)
    
    # Step 4-5: Enrich with call hierarchy
    enriched_jobs = enrich_with_call_hierarchy_v2(job_defs, registry, original_bean_map)
    
    print("\n" + "=" * 80)
    print("✅ CALL HIERARCHY BUILD COMPLETE")
    print("=" * 80)
    
    return enriched_jobs, registry


if __name__ == '__main__':
    # Example usage
    root_directory = "SpringProjects"
    
    # Build call hierarchy with V2 architecture
    enriched_jobs, registry = build_call_hierarchy_v2(root_directory)
    
    # Print summary
    print("\n" + "=" * 80)
    print("FINAL SUMMARY")
    print("=" * 80)
    print(f"  Total Jobs: {len(enriched_jobs)}")
    print(f"  Bean Registry: {registry.get_stats()}")
    
    for job in enriched_jobs:
        if hasattr(job, 'enrichment'):
            step_classes = job.enrichment.get('step_classes', {})
            all_classes_cache = job.enrichment.get('all_classes_cache', {})
            
            # Count operations from step classes and their call hierarchy
            visited = set()
            def count_operations_recursive(class_fqn, visited_set):
                if class_fqn in visited_set or class_fqn not in all_classes_cache:
                    return 0, 0, 0
                visited_set.add(class_fqn)
                class_info = all_classes_cache[class_fqn]
                db = sum(len(m.db_operations) for m in class_info.methods.values())
                proc = sum(len(m.procedure_calls) for m in class_info.methods.values())
                shell = sum(len(m.shell_executions) for m in class_info.methods.values())
                # Recurse into called classes
                for called_class in class_info.called_classes:
                    sub_db, sub_proc, sub_shell = count_operations_recursive(called_class, visited_set)
                    db += sub_db
                    proc += sub_proc
                    shell += sub_shell
                return db, proc, shell
            
            total_db_ops = 0
            total_proc_calls = 0
            total_shell_execs = 0
            for step_class_fqn in step_classes.keys():
                db, proc, shell = count_operations_recursive(step_class_fqn, visited)
                total_db_ops += db
                total_proc_calls += proc
                total_shell_execs += shell
            
            print(f"\n  Job '{job.name}':")
            print(f"    Step Classes: {len(step_classes)}")
            print(f"    Total Classes in Call Hierarchy: {len(visited)}")
            print(f"    DB Operations: {total_db_ops}")
            print(f"    Procedure Calls: {total_proc_calls}")
            print(f"    Shell Executions: {total_shell_execs}")
