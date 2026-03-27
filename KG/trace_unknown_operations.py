"""
Trace Unknown Operations in Call Hierarchy

This script helps identify which JavaMethod(s) in the call hierarchy have UNKNOWN/DYNAMIC operations.
Usage:
    python test/trace_unknown_operations.py --step <step_name>
    python test/trace_unknown_operations.py --job <job_name>
    
Examples:
    python test/trace_unknown_operations.py --step customerProcessingStep
    python test/trace_unknown_operations.py --job CUSTOMER_PROCESSING_JOB
"""

import sys
import os
import yaml
import argparse
from collections import deque

sys.path.insert(0, 'D:\\Iris\\practice\\GenAI\\code\\Batch_KG')

from neo4j import GraphDatabase
from dotenv import load_dotenv

load_dotenv()

# Load configuration
config_file_path = os.getenv('KG_CONFIG_FILE', 'config/information_graph_config.yaml')
with open(config_file_path, 'r') as f:
    config = yaml.safe_load(f)

# Load grey area keywords
grey_area = config.get('grey_area_keywords', {})
CORE_KEYWORDS = grey_area.get('core', ['UNKNOWN', 'DYNAMIC', 'PARAMETERIZED'])
scan_options = config.get('scan_options', {})
jobs_to_scan = scan_options.get('jobs_to_build', [])

driver = GraphDatabase.driver(
    config['neo4j']['uri'],
    auth=(config['neo4j']['user'], config['neo4j']['password'])
)


def has_grey_area(operations):
    """Check if operations list contains grey area entries"""
    if not operations:
        return False
    keywords = CORE_KEYWORDS
    return any(any(kw in op for kw in keywords) for op in operations)


def get_grey_area_entries(operations):
    """Extract grey area entries from operations list"""
    if not operations:
        return []
    keywords = CORE_KEYWORDS
    return [op for op in operations if any(kw in op for kw in keywords)]


def trace_step_operations(step_name, database):
    """Trace operations for a specific Step"""
    print("\n" + "="*80)
    print(f"TRACING OPERATIONS FOR STEP: {step_name}")
    print("="*80)
    
    with driver.session(database=database) as session:
        # Get Step details
        query_step = """
        MATCH (s:Step {name: $stepName})
        RETURN s.name as name,
               s.stepKind as kind,
               s.implBean as implBean,
               s.readerBean as readerBean,
               s.writerBean as writerBean,
               s.processorBean as processorBean,
               elementId(s) as stepId,
               s.stepDbOperations as dbOps,
               s.stepProcedureCalls as procCalls,
               s.stepShellExecutions as shellExecs
        """
        result = session.run(query_step, stepName=step_name)
        step_record = result.single()
        
        if not step_record:
            print(f"Error Step '{step_name}' not found!")
            return
        
        step_kind = step_record['kind']
        step_id = step_record['stepId']
        
        print(f"\nStep Kind: {step_kind}")
        bean_parts = []
        if step_record['implBean']:
            bean_parts.append(f"implBean={step_record['implBean']}")
        if step_record['readerBean']:
            bean_parts.append(f"readerBean={step_record['readerBean']}")
        if step_record['processorBean']:
            bean_parts.append(f"processorBean={step_record['processorBean']}")
        if step_record['writerBean']:
            bean_parts.append(f"writerBean={step_record['writerBean']}")
        print(f"Bean ID(s): {', '.join(bean_parts) if bean_parts else 'N/A'}")
        
        # Show Step-level operations
        print("\n" + "-"*80)
        print("STEP-LEVEL OPERATIONS:")
        print("-"*80)
        
        db_ops = step_record['dbOps'] or []
        proc_calls = step_record['procCalls'] or []
        shell_execs = step_record['shellExecs'] or []
        
        if db_ops:
            print(f"\n  DB Operations ({len(db_ops)}):")
            for op in db_ops:
                marker = "Warning   " if has_grey_area([op]) else "Looks Perfect "
                print(f"    {marker}{op}")
        
        if proc_calls:
            print(f"\n  Procedure Calls ({len(proc_calls)}):")
            for proc in proc_calls:
                marker = "Warning   " if has_grey_area([proc]) else "Looks Perfect "
                print(f"    {marker}{proc}")
        
        if shell_execs:
            print(f"\n  Shell Executions ({len(shell_execs)}):")
            for shell in shell_execs:
                marker = "Warning   " if has_grey_area([shell]) else "Looks Perfect "
                print(f"    {marker}{shell}")
        
        # Determine entry method names
        if step_kind == "TASKLET":
            entry_method_names = ["execute"]
        elif step_kind == "CHUNK":
            entry_method_names = ["read", "process", "write"]
        else:
            print(f"\nError Unknown step kind: {step_kind}")
            return
        
        # Find entry methods
        query_entry = """
        MATCH (s:Step)
        WHERE elementId(s) = $stepId
        MATCH (s)-[:IMPLEMENTED_BY]->(jc:JavaClass)
        MATCH (jc)-[:HAS_METHOD]->(m:JavaMethod)
        WHERE m.methodName IN $methodNames
        RETURN elementId(m) as methodId,
               m.methodName as methodName,
               m.fqn as fqn,
               m.dbOperations as dbOps,
               m.procedureCalls as procCalls,
               m.shellExecutions as shellExecs,
               m.furtherAnalysisRequired as needsAnalysis
        """
        
        result = session.run(query_entry, stepId=step_id, methodNames=entry_method_names)
        entry_methods = [dict(record) for record in result]
        
        if not entry_methods:
            print(f"\nError No entry methods found for step kind: {step_kind}")
            return
        
        print("\n" + "="*80)
        print("CALL HIERARCHY ANALYSIS:")
        print("="*80)
        
        # Process each entry method
        for entry_method in entry_methods:
            print(f"\n{'='*80}")
            print(f"Entry Method: {entry_method['methodName']}()")
            print(f"FQN: {entry_method['fqn']}")
            print(f"{'='*80}")
            
            # Check entry method itself
            has_grey = False
            if has_grey_area(entry_method.get('dbOps')):
                has_grey = True
                print(f"\nWarning   GREY AREA in entry method:")
                print(f"  Method: {entry_method['fqn']}")
                print(f"  DB Operations:")
                for op in get_grey_area_entries(entry_method.get('dbOps')):
                    print(f"    - {op}")
            
            if has_grey_area(entry_method.get('procCalls')):
                has_grey = True
                print(f"\nWarning   GREY AREA in entry method:")
                print(f"  Method: {entry_method['fqn']}")
                print(f"  Procedure Calls:")
                for proc in get_grey_area_entries(entry_method.get('procCalls')):
                    print(f"    - {proc}")
            
            if has_grey_area(entry_method.get('shellExecs')):
                has_grey = True
                print(f"\nWarning   GREY AREA in entry method:")
                print(f"  Method: {entry_method['fqn']}")
                print(f"  Shell Executions:")
                for shell in get_grey_area_entries(entry_method.get('shellExecs')):
                    print(f"    - {shell}")
            
            # BFS traversal to find grey areas in called methods
            visited = set()
            queue = deque([(entry_method['methodId'], [entry_method['fqn']])])
            visited.add(entry_method['methodId'])
            
            found_grey_areas = []
            
            while queue:
                current_id, path = queue.popleft()
                
                # Get called methods
                query_calls = """
                MATCH (m:JavaMethod)-[:CALLS]->(called:JavaMethod)
                WHERE elementId(m) = $methodId
                RETURN elementId(called) as calledId,
                       called.fqn as fqn,
                       called.dbOperations as dbOps,
                       called.procedureCalls as procCalls,
                       called.shellExecutions as shellExecs,
                       called.furtherAnalysisRequired as needsAnalysis
                """
                
                result = session.run(query_calls, methodId=current_id)
                called_methods = [dict(record) for record in result]
                
                for called in called_methods:
                    called_id = called['calledId']
                    called_fqn = called['fqn']
                    
                    if called_id not in visited:
                        visited.add(called_id)
                        new_path = path + [called_fqn]
                        queue.append((called_id, new_path))
                        
                        # Check for grey areas
                        grey_db = get_grey_area_entries(called.get('dbOps'))
                        grey_proc = get_grey_area_entries(called.get('procCalls'))
                        grey_shell = get_grey_area_entries(called.get('shellExecs'))
                        
                        if grey_db or grey_proc or grey_shell:
                            found_grey_areas.append({
                                'fqn': called_fqn,
                                'path': new_path,
                                'dbOps': grey_db,
                                'procCalls': grey_proc,
                                'shellExecs': grey_shell,
                                'needsAnalysis': called.get('needsAnalysis', False)
                            })
            
            # Report findings
            if found_grey_areas:
                print(f"\nWarning   Found {len(found_grey_areas)} method(s) with GREY AREA operations in call hierarchy:")
                print()
                
                for idx, grey in enumerate(found_grey_areas, 1):
                    print(f"\n{idx}. Method: {grey['fqn']}")
                    print(f"   furtherAnalysisRequired: {grey['needsAnalysis']}")
                    print(f"\n   Call Path ({len(grey['path'])} methods):")
                    for i, method in enumerate(grey['path'], 1):
                        indent = "   " + "  " * i
                        arrow = "-->" if i == len(grey['path']) else "---->"
                        print(f"{indent}{arrow} {method}")
                    
                    if grey['dbOps']:
                        print(f"\n   DB Operations ({len(grey['dbOps'])}):")
                        for op in grey['dbOps']:
                            print(f"     - {op}")
                    
                    if grey['procCalls']:
                        print(f"\n   Procedure Calls ({len(grey['procCalls'])}):")
                        for proc in grey['procCalls']:
                            print(f"     - {proc}")
                    
                    if grey['shellExecs']:
                        print(f"\n   Shell Executions ({len(grey['shellExecs'])}):")
                        for shell in grey['shellExecs']:
                            print(f"     - {shell}")
                    
                    print(f"\n   {'-'*70}")
            else:
                if not has_grey:
                    print(f"\nLooks Perfect No grey area operations found in call hierarchy!")
        
        print("\n" + "="*80)


def trace_job_operations(job_name, database):
    """Trace operations for all Steps in a Job"""
    print("\n" + "="*80)
    print(f"TRACING OPERATIONS FOR JOB: {job_name}")
    print("="*80)
    
    with driver.session(database=database) as session:
        # Get all Steps for this Job
        query_steps = """
        MATCH (j:Job {name: $jobName})-[:CONTAINS]->(s:Step)
        RETURN s.name as stepName, s.stepKind as stepKind
        ORDER BY s.name
        """
        result = session.run(query_steps, jobName=job_name)
        steps = [dict(record) for record in result]
        
        if not steps:
            print(f"Error Job '{job_name}' not found or has no steps!")
            return
        
        print(f"\nFound {len(steps)} step(s) in job '{job_name}':")
        for step in steps:
            print(f"  - {step['stepName']} ({step['stepKind']})")
        
        # Trace each step
        for step in steps:
            trace_step_operations(step['stepName'], database)


def main():
    parser = argparse.ArgumentParser(
        description='Trace Unknown/Dynamic operations in Step call hierarchy',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python test/trace_unknown_operations.py --step customerProcessingStep
  python test/trace_unknown_operations.py --job CUSTOMER_PROCESSING_JOB
  python test/trace_unknown_operations.py  # Uses jobs from config
        """
    )
    
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('--step', dest='step_name', help='Step name to trace')
    group.add_argument('--job', dest='job_name', help='Job name to trace (traces all steps)')
    
    args = parser.parse_args()
    
    database = config['neo4j']['database_ig']
    
    if args.step_name:
        trace_step_operations(args.step_name, database)
    elif args.job_name:
        trace_job_operations(args.job_name, database)
    elif jobs_to_scan:
        print(f"Scanning predefined jobs from config: {jobs_to_scan}")
        for job in jobs_to_scan:
            trace_job_operations(job, database)
    
    driver.close()


if __name__ == "__main__":
    main()
