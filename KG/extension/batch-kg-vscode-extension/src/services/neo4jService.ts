import * as vscode from 'vscode';
import neo4j, { Driver, Session } from 'neo4j-driver';
import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import { 
    Job, 
    Step, 
    GapInfo, 
    GreyAreaKeywords,
    GraphConfig,
    DBGapDetails,
    ProcedureGapDetails,
    ShellGapDetails
} from '../models/types';

export class Neo4jService {
    private driver: Driver | null = null;
    private graphConfig: GraphConfig | null = null;

    constructor() {
        // Config is read dynamically in getDriver()
    }

    private getConfig(): vscode.WorkspaceConfiguration {
        return vscode.workspace.getConfiguration('batchKg');
    }

    /**
     * Load and cache the full graph config (keywords + job filtering settings).
     * Reads information_graph_config.yaml once and combines everything.
     */
    private loadGraphConfig(): GraphConfig {
        if (this.graphConfig) {
            return this.graphConfig;
        }

        const defaults = this.getDefaultConfig();

        try {
            const vsConfig = this.getConfig();
            const configPath = vsConfig.get<string>('configPath', '../Batch_KG/config/information_graph_config.yaml');

            const workspaceFolders = vscode.workspace.workspaceFolders;
            if (!workspaceFolders || workspaceFolders.length === 0) {
                console.warn('No workspace folder opened, using config defaults');
                this.graphConfig = defaults;
                return defaults;
            }

            const fullPath = path.resolve(workspaceFolders[0].uri.fsPath, configPath);

            if (!fs.existsSync(fullPath)) {
                console.warn(`Config file not found at ${fullPath}, using defaults`);
                this.graphConfig = defaults;
                return defaults;
            }

            const rawYaml: any = yaml.load(fs.readFileSync(fullPath, 'utf8'));
            const scanOptions = rawYaml?.scan_options || {};

            const cfg: GraphConfig = {
                build_all_jobs: scanOptions.build_all_jobs !== false, // default true
                jobs_to_build: Array.isArray(scanOptions.jobs_to_build) ? scanOptions.jobs_to_build : [],
                keywords: rawYaml?.grey_area_keywords || defaults.keywords
            };

            console.log(
                `Loaded graph config — build_all_jobs: ${cfg.build_all_jobs}`,
                cfg.build_all_jobs ? '' : `jobs: [${cfg.jobs_to_build.join(', ')}]`
            );

            this.graphConfig = cfg;
            return cfg;
        } catch (error) {
            console.error('Error loading graph config, using defaults:', error);
            this.graphConfig = defaults;
            return defaults;
        }
    }

    /** Kept for backward-compat inside getGapsForStep */
    private loadGreyAreaKeywords(): GreyAreaKeywords {
        return this.loadGraphConfig().keywords;
    }

    private getDefaultConfig(): GraphConfig {
        return {
            build_all_jobs: true,
            jobs_to_build: [],
            keywords: this.getDefaultKeywords()
        };
    }

    private getDefaultKeywords(): GreyAreaKeywords {
        return {
            core: ['UNKNOWN', 'DYNAMIC', 'PARAMETERIZED'],
            db_operations: ['DYNAMIC_TABLE', 'DYNAMIC_CATALOG', 'DYNAMIC_SCHEMA'],
            procedure_calls: ['DYNAMIC_PROCEDURE', 'DYNAMIC_PACKAGE'],
            shell_executions: ['DYNAMIC_PATH', 'DYNAMIC_SCRIPT', 'UNKNOWN_SCRIPT', 'REMOTE_EXECUTION'],
            script_quality: ['unknown', 'dynamic', 'parameterized', 'variable', 'placeholder',
                           'error', 'exception', 'unable', 'failed', 'missing', 'not found',
                           'invalid', 'undefined', 'null', 'empty']
        };
    }

    private getDriver(): Driver {
        if (!this.driver) {
            const config = this.getConfig();
            const uri = config.get<string>('neo4jUri', 'bolt://localhost:7687');
            const user = config.get<string>('neo4jUser', 'neo4j');
            const password = config.get<string>('neo4jPassword', '');

            if (!password) {
                throw new Error('Neo4j password not configured. Please set "batchKg.neo4jPassword" in VS Code settings.');
            }

            this.driver = neo4j.driver(uri, neo4j.auth.basic(user, password));
        }
        return this.driver;
    }

    private getSession(): Session {
        const config = this.getConfig();
        const database = config.get<string>('neo4jDatabase', 'information_graph');
        return this.getDriver().session({ database });
    }

    async testConnection(): Promise<boolean> {
        try {
            const session = this.getSession();
            await session.run('RETURN 1');
            await session.close();
            return true;
        } catch (error) {
            console.error('Neo4j connection failed:', error);
            return false;
        }
    }

    async getAllJobs(): Promise<Job[]> {
        const cfg = this.loadGraphConfig();

        // If build_all_jobs is false, return the jobs_to_build list from config directly —
        // no Neo4j query needed. Gap counts are unknown at this stage; they will be
        // resolved per-step when the user drills into a job.
        if (!cfg.build_all_jobs && cfg.jobs_to_build.length > 0) {
            console.log(`getAllJobs — source: config [${cfg.jobs_to_build.join(', ')}]`);
            return cfg.jobs_to_build.map((name: string) => ({
                name,
                jobId: '',
                gap_count: 0
            }));
        }

        // build_all_jobs: true — query the graph for all Job nodes with gap counts
        const session = this.getSession();
        try {
            const allKeywords = [
                ...cfg.keywords.core,
                ...cfg.keywords.db_operations,
                ...cfg.keywords.procedure_calls,
                ...cfg.keywords.shell_executions
            ].map(k => k.toLowerCase());

            const result = await session.run(
                `MATCH (j:Job)
                OPTIONAL MATCH (j)-[:CONTAINS]->(s:Step)-[:CONTAINS]->(m:JavaMethod)
                WHERE toLower(m.operation) IN $keywords 
                   OR m.furtherAnalysisRequired = true
                WITH j, COUNT(DISTINCT m) as gapCount
                RETURN j.name as name, elementId(j) as jobId, gapCount as gap_count
                ORDER BY name`,
                { keywords: allKeywords }
            );

            const jobs = result.records.map(record => ({
                name: record.get('name'),
                jobId: record.get('jobId'),
                gap_count: record.get('gap_count').toInt()
            }));

            console.log(`getAllJobs — source: graph, returned ${jobs.length} job(s)`);
            return jobs;
        } finally {
            await session.close();
        }
    }

    async getStepsForJob(jobName: string): Promise<Step[]> {
        const session = this.getSession();
        try {
            // Load grey area keywords for gap counting
            const keywords = this.loadGreyAreaKeywords();
            const allKeywords = [
                ...keywords.core,
                ...keywords.db_operations,
                ...keywords.procedure_calls,
                ...keywords.shell_executions
            ].map(k => k.toLowerCase());

            const result = await session.run(`
                MATCH (j:Job {name: $jobName})-[:CONTAINS]->(s:Step)
                OPTIONAL MATCH (s)-[:CONTAINS]->(m:JavaMethod)
                WHERE toLower(m.operation) IN $keywords 
                   OR m.furtherAnalysisRequired = true
                WITH s, COUNT(DISTINCT m) as gapCount
                RETURN s.name as name, elementId(s) as stepId, s.stepKind as stepKind, gapCount as gap_count
                ORDER BY name
            `, { jobName, keywords: allKeywords });

            return result.records.map(record => ({
                name: record.get('name'),
                stepId: record.get('stepId'),
                stepKind: record.get('stepKind'),
                gap_count: record.get('gap_count').toInt()
            }));
        } finally {
            await session.close();
        }
    }

    async getGapsForStep(stepName: string): Promise<{ db: GapInfo[], procedure: GapInfo[], shell: GapInfo[] }> {
        const session = this.getSession();
        try {
            // Load grey area keywords from config
            const keywords = this.loadGreyAreaKeywords();
            
            const result = await session.run(`
                MATCH (s:Step {name: $stepName})-[:IMPLEMENTED_BY]->(jc:JavaClass)
                MATCH (jc)-[:HAS_METHOD]->(entry:JavaMethod)
                WHERE entry.methodName IN ['execute', 'read', 'write', 'process']
                
                // BFS to find all methods in call hierarchy
                CALL (entry) {
                    MATCH path = (entry)-[:CALLS*0..10]->(m:JavaMethod)
                    RETURN m
                }
                
                // Return methods with operations or furtherAnalysisRequired flag
                WITH m, m.dbOperations as dbOps, m.procedureCalls as procCalls, 
                     m.shellExecutions as shellExecs, m.furtherAnalysisRequired as needsAnalysis
                WHERE (
                    size(dbOps) > 0 OR size(procCalls) > 0 OR size(shellExecs) > 0
                    OR needsAnalysis = true
                )
                
                RETURN DISTINCT m.fqn as methodFqn,
                       dbOps,
                       procCalls,
                       shellExecs,
                       needsAnalysis
                ORDER BY m.fqn
            `, { stepName });

            const gaps = {
                db: [] as GapInfo[],
                procedure: [] as GapInfo[],
                shell: [] as GapInfo[]
            };

            // Build keyword lists for each category
            const dbKeywords = [...keywords.core, ...keywords.db_operations];
            const procKeywords = [...keywords.core, ...keywords.procedure_calls];
            const shellKeywords = [...keywords.core, ...keywords.shell_executions, ...keywords.script_quality];

            for (const record of result.records) {
                const methodFqn = record.get('methodFqn');
                const dbOps = record.get('dbOps') || [];
                const procCalls = record.get('procCalls') || [];
                const shellExecs = record.get('shellExecs') || [];
                const needsAnalysis = record.get('needsAnalysis') || false;

                // Extract DB gaps: Check for grey area keywords in table name
                // Format: operation_type:table_name:confidence
                for (const op of dbOps) {
                    const parts = op.split(':');
                    if (parts.length >= 2) {
                        const tableName = parts[1];
                        if (dbKeywords.some(kw => tableName.toUpperCase().includes(kw.toUpperCase()))) {
                            gaps.db.push({
                                category: 'db',
                                operation: op,
                                methodFqn,
                                furtherAnalysisRequired: needsAnalysis
                            });
                        }
                    }
                }

                // Extract Procedure gaps: Check for grey area keywords in procedure name
                // Format: schema:package:procedure_name:database_type:proc_type:confidence
                for (const proc of procCalls) {
                    const parts = proc.split(':');
                    if (parts.length >= 3) {
                        const procedureName = parts[2];
                        if (procKeywords.some(kw => procedureName.toUpperCase().includes(kw.toUpperCase()))) {
                            gaps.procedure.push({
                                category: 'procedure',
                                operation: proc,
                                methodFqn,
                                furtherAnalysisRequired: needsAnalysis
                            });
                        }
                    }
                }

                // Extract Shell gaps: Check for grey area keywords in script name
                // Format: execution_method:script_name:confidence
                for (const shell of shellExecs) {
                    const parts = shell.split(':');
                    if (parts.length >= 2) {
                        const scriptName = parts[1];
                        const scriptLower = scriptName.toLowerCase();
                        
                        // Check against shell-specific keywords (case-insensitive)
                        const isShellGap = shellKeywords.some(kw => {
                            const kwLower = kw.toLowerCase();
                            return scriptLower.includes(kwLower) || scriptName.toUpperCase().includes(kw.toUpperCase());
                        });
                        
                        if (isShellGap) {
                            gaps.shell.push({
                                category: 'shell',
                                operation: shell,
                                methodFqn,
                                furtherAnalysisRequired: needsAnalysis
                            });
                        }
                    }
                }
            }

            console.log(`Found gaps for step ${stepName}:`, {
                db: gaps.db.length,
                procedure: gaps.procedure.length,
                shell: gaps.shell.length
            });

            return gaps;
        } finally {
            await session.close();
        }
    }

    async close(): Promise<void> {
        if (this.driver) {
            await this.driver.close();
            this.driver = null;
        }
    }
}
