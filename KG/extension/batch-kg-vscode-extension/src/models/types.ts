/**
 * Type definitions for the Batch KG Gap Analyzer extension
 */

export interface Job {
    name: string;
    jobId: string;
    gap_count?: number;
}

export interface Step {
    name: string;
    stepId: string;
    stepKind: string;
    gap_count?: number;
}

export interface GapInfo {
    category: 'db' | 'procedure' | 'shell';
    operation: string;
    methodFqn: string;
    furtherAnalysisRequired: boolean;
}

export interface DBGapDetails {
    operation: string;
    tableName?: string;
    schemaName?: string;
    catalogName?: string;
}

export interface ProcedureGapDetails {
    procedureName: string;
    schemaName?: string;
    packageName?: string;
}

export interface ShellGapDetails {
    script: string;
    command?: string;
}

export interface ResolutionEntry {
    type: 'db' | 'procedure' | 'shell';
    step_name: string;
    method_fqn: string;
    original_operation: string;
    resolution: DBResolution | ProcedureResolution | ShellResolution;
}

export interface DBResolution {
    operation_type?: string;
    table_name?: string;
    schema_name?: string;
    confidence?: string;
    bean_id?: string;
    tasklet_fqn?: string;
    reader_fqn?: string;
    writer_fqn?: string;
    processor_fqn?: string;
}

export interface ProcedureResolution {
    procedure_name?: string;
    schema_name?: string;
    package_name?: string;
    database_type?: string;
    is_function?: boolean;
    oracle_type?: string;
    confidence?: string;
    bean_id?: string;
    tasklet_fqn?: string;
}

export interface ShellResolution {
    script_name?: string;
    script_path?: string;
    script_type?: string;
    confidence?: string;
    remote_host?: string;
    remote_user?: string;
    remote_port?: number;
    ssh_key_location?: string;
    description?: string;
    bean_id?: string;
    tasklet_fqn?: string;
}

export interface GreyAreaKeywords {
    core: string[];
    db_operations: string[];
    procedure_calls: string[];
    shell_executions: string[];
    script_quality: string[];
}

/**
 * Parsed from scan_options in information_graph_config.yaml
 * Controls which jobs are visible in the extension's job list
 */
export interface GraphConfig {
    build_all_jobs: boolean;
    jobs_to_build: string[];
    keywords: GreyAreaKeywords;
}

export interface WebviewMessage {
    command: string;
    [key: string]: any;
}

export interface AppState {
    selectedJob: string | null;
    selectedStep: string | null;
    selectedCategory: 'db' | 'procedure' | 'shell' | null;
    selectedGap: GapInfo | null;
    selectedGapIndex: number | null;
    gaps: {
        db: GapInfo[];
        procedure: GapInfo[];
        shell: GapInfo[];
    };
}
