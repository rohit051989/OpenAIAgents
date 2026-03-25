/**
 * Refactored Gap Analyzer Panel
 * Uses modular ViewBuilder for HTML/CSS/JS generation
 */

import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { Neo4jService } from './services/neo4jService';
import { YamlGenerator } from './services/yamlGenerator';
import { ResolutionEntry } from './models/types';
import { ViewBuilder } from './views/viewBuilder';

export class GapAnalyzerPanel {
    public static currentPanel: GapAnalyzerPanel | undefined;
    public static readonly viewType = 'batchKgGapAnalyzer';

    private readonly _panel: vscode.WebviewPanel;
    private readonly _extensionUri: vscode.Uri;
    private _disposables: vscode.Disposable[] = [];
    private neo4jService: Neo4jService;
    private viewBuilder: ViewBuilder;

    public static createOrShow(extensionUri: vscode.Uri) {
        const column = vscode.window.activeTextEditor
            ? vscode.window.activeTextEditor.viewColumn
            : undefined;

        // If we already have a panel, show it
        if (GapAnalyzerPanel.currentPanel) {
            GapAnalyzerPanel.currentPanel._panel.reveal(column);
            return;
        }

        // Otherwise, create a new panel
        const panel = vscode.window.createWebviewPanel(
            GapAnalyzerPanel.viewType,
            'Batch KG Gap Analyzer',
            column || vscode.ViewColumn.One,
            {
                enableScripts: true,
                localResourceRoots: [
                    extensionUri,
                    vscode.Uri.joinPath(extensionUri, 'out')
                ],
                retainContextWhenHidden: true
            }
        );

        GapAnalyzerPanel.currentPanel = new GapAnalyzerPanel(panel, extensionUri);
    }

    public static revive(panel: vscode.WebviewPanel, extensionUri: vscode.Uri) {
        GapAnalyzerPanel.currentPanel = new GapAnalyzerPanel(panel, extensionUri);
    }

    private constructor(panel: vscode.WebviewPanel, extensionUri: vscode.Uri) {
        this._panel = panel;
        this._extensionUri = extensionUri;
        this.neo4jService = new Neo4jService();
        this.viewBuilder = new ViewBuilder(extensionUri);

        // Set the webview's initial html content
        this._update();

        // Listen for when the panel is disposed
        this._panel.onDidDispose(() => this.dispose(), null, this._disposables);

        // Handle messages from the webview
        this._panel.webview.onDidReceiveMessage(
            message => this.handleMessage(message),
            null,
            this._disposables
        );
    }

    private async handleMessage(message: any) {
        switch (message.command) {
            case 'getJobs':
                await this.handleGetJobs();
                break;
            case 'getSteps':
                await this.handleGetSteps(message.jobName);
                break;
            case 'getGaps':
                await this.handleGetGaps(message.jobName, message.stepName);
                break;
            case 'saveResolution':
                await this.handleSaveResolution(message.gap, message.resolution);
                break;
            case 'testConnection':
                await this.handleTestConnection();
                break;
        }
    }

    private async handleTestConnection() {
        try {
            const connected = await this.neo4jService.testConnection();
            
            this._panel.webview.postMessage({
                command: 'connectionStatus',
                success: connected,
                message: connected 
                    ? ' Neo4j connection successful!' 
                    : ' Neo4j connection failed. Check your settings.'
            });

            if (connected) {
                vscode.window.showInformationMessage(' Neo4j connection successful!');
            } else {
                vscode.window.showErrorMessage(' Neo4j connection failed. Check your settings.', 'Open Settings')
                    .then(selection => {
                        if (selection === 'Open Settings') {
                            vscode.commands.executeCommand('workbench.action.openSettings', 'batchKg');
                        }
                    });
            }
        } catch (error: any) {
            const errorMsg = ` Neo4j error: ${error.message}`;
            
            vscode.window.showErrorMessage(errorMsg, 'Open Settings')
                .then(selection => {
                    if (selection === 'Open Settings') {
                        vscode.commands.executeCommand('workbench.action.openSettings', 'batchKg');
                    }
                });
            
            this._panel.webview.postMessage({
                command: 'connectionStatus',
                success: false,
                message: errorMsg
            });
        }
    }

    private async handleGetJobs() {
        try {
            console.log('Fetching jobs from Neo4j...');
            const jobs = await this.neo4jService.getAllJobs();
            console.log(`Found ${jobs.length} jobs:`, jobs);
            
            this._panel.webview.postMessage({
                command: 'jobsLoaded',
                jobs
            });
        } catch (error: any) {
            console.error('Error loading jobs:', error);
            const isAuthError = error.message.includes('authentication') || 
                               error.message.includes('unauthorized') || 
                               error.message.includes('password');
            
            if (isAuthError) {
                vscode.window.showErrorMessage(`Error loading jobs: ${error.message}`, 'Open Settings')
                    .then(selection => {
                        if (selection === 'Open Settings') {
                            vscode.commands.executeCommand('workbench.action.openSettings', 'batchKg');
                        }
                    });
            } else {
                vscode.window.showErrorMessage(`Error loading jobs: ${error.message}`);
            }
            
            this._panel.webview.postMessage({
                command: 'connectionStatus',
                success: false,
                message: `Error loading jobs: ${error.message}`
            });
        }
    }

    private async handleGetSteps(jobName: string) {
        try {
            console.log(`Fetching steps for job: ${jobName}`);
            const steps = await this.neo4jService.getStepsForJob(jobName);
            console.log(`Found ${steps.length} steps`);
            
            this._panel.webview.postMessage({
                command: 'stepsLoaded',
                steps
            });
        } catch (error: any) {
            console.error('Error loading steps:', error);
            const isAuthError = error.message.includes('authentication') || 
                               error.message.includes('unauthorized') || 
                               error.message.includes('password');
            
            if (isAuthError) {
                vscode.window.showErrorMessage(`Error loading steps: ${error.message}`, 'Open Settings')
                    .then(selection => {
                        if (selection === 'Open Settings') {
                            vscode.commands.executeCommand('workbench.action.openSettings', 'batchKg');
                        }
                    });
            } else {
                vscode.window.showErrorMessage(`Error loading steps: ${error.message}`);
            }
            
            this._panel.webview.postMessage({
                command: 'connectionStatus',
                success: false,
                message: `Error loading steps: ${error.message}`
            });
        }
    }

    private async handleGetGaps(jobName: string, stepName: string) {
        try {
            console.log(`Fetching gaps for step: ${stepName}`);
            const gapData = await this.neo4jService.getGapsForStep(stepName);

            // neo4jService returns: { category, operation (colon-delimited), methodFqn, furtherAnalysisRequired }
            // DB format:        operation_type:table_name:confidence
            // Procedure format: schema:package:procedure_name:database_type:proc_type:confidence
            // Shell format:     execution_method:script_name:confidence
            const gaps = [
                ...gapData.db.map((gap: any) => {
                    const parts = (gap.operation || '').split(':');
                    const confidence = parts[2] || 'MEDIUM';
                    return {
                        category: 'DB_OPERATION',
                        method_fqn: gap.methodFqn,
                        description: gap.operation,
                        confidence,
                        type_specific_info: {
                            operation: parts[0] || '',
                            table_name: parts[1] || '',
                            schema: ''
                        }
                    };
                }),
                ...gapData.procedure.map((gap: any) => {
                    const parts = (gap.operation || '').split(':');
                    const confidence = parts[5] || 'MEDIUM';
                    return {
                        category: 'PROCEDURE_CALL',
                        method_fqn: gap.methodFqn,
                        description: gap.operation,
                        confidence,
                        type_specific_info: {
                            schema: parts[0] || '',
                            package: parts[1] || '',
                            procedure_name: parts[2] || '',
                            database_type: parts[3] || 'ORACLE',
                            oracle_type: parts[4] || 'PROCEDURE'
                        }
                    };
                }),
                ...gapData.shell.map((gap: any) => {
                    const parts = (gap.operation || '').split(':');
                    const confidence = parts[2] || 'MEDIUM';
                    return {
                        category: 'SHELL_EXECUTION',
                        method_fqn: gap.methodFqn,
                        description: gap.operation,
                        confidence,
                        type_specific_info: {
                            script_name: parts[1] || '',
                            script_path: '',
                            script_type: 'BASH',
                            remote_host: '',
                            remote_user: '',
                            remote_port: '22',
                            ssh_key_path: ''
                        }
                    };
                })
            ];

            console.log(`Gaps found:`, {
                db: gapData.db.length,
                procedure: gapData.procedure.length,
                shell: gapData.shell.length,
                total: gaps.length
            });
            
            this._panel.webview.postMessage({
                command: 'gapsLoaded',
                gaps
            });
        } catch (error: any) {
            console.error('Error loading gaps:', error);
            const isAuthError = error.message.includes('authentication') || 
                               error.message.includes('unauthorized') || 
                               error.message.includes('password');
            
            if (isAuthError) {
                vscode.window.showErrorMessage(`Error loading gaps: ${error.message}`, 'Open Settings')
                    .then(selection => {
                        if (selection === 'Open Settings') {
                            vscode.commands.executeCommand('workbench.action.openSettings', 'batchKg');
                        }
                    });
            } else {
                vscode.window.showErrorMessage(`Error loading gaps: ${error.message}`);
            }
            
            this._panel.webview.postMessage({
                command: 'connectionStatus',
                success: false,
                message: `Error loading gaps: ${error.message}`
            });
        }
    }

    private async handleSaveResolution(gap: any, resolution: any) {
        try {
            // Build ResolutionEntry from gap and resolution data
            const resolutionEntry: ResolutionEntry = {
                type: gap.category === 'DB_OPERATION' ? 'db' : 
                      gap.category === 'PROCEDURE_CALL' ? 'procedure' : 'shell',
                step_name: gap.step_name || '',
                method_fqn: gap.method_fqn,
                original_operation: gap.description || gap.method_fqn,
                resolution: {} as any
            };

            // Add category-specific data
            if (gap.category === 'DB_OPERATION' && resolution.db_operation) {
                resolutionEntry.resolution = {
                    operation_type: resolution.db_operation.operation,
                    table_name: resolution.db_operation.table_name,
                    schema_name: resolution.db_operation.schema,
                    confidence: resolution.db_operation.confidence
                };
            } else if (gap.category === 'PROCEDURE_CALL' && resolution.procedure_call) {
                resolutionEntry.resolution = {
                    oracle_type: resolution.procedure_call.oracle_type,
                    procedure_name: resolution.procedure_call.object_name,
                    schema_name: resolution.procedure_call.schema,
                    package_name: resolution.procedure_call.package,
                    database_type: resolution.procedure_call.database_type,
                    is_function: resolution.procedure_call.oracle_type === 'FUNCTION',
                    confidence: resolution.procedure_call.confidence
                };
            } else if (gap.category === 'SHELL_EXECUTION' && resolution.shell_execution) {
                resolutionEntry.resolution = {
                    script_name: resolution.shell_execution.script_name,
                    script_path: resolution.shell_execution.script_path,
                    script_type: resolution.shell_execution.script_type,
                    confidence: resolution.shell_execution.confidence,
                    remote_host: resolution.shell_execution.remote_host,
                    remote_user: resolution.shell_execution.remote_user,
                    remote_port: resolution.shell_execution.remote_port ? 
                        parseInt(resolution.shell_execution.remote_port) : undefined,
                    ssh_key_location: resolution.shell_execution.ssh_key_path,
                    description: resolution.shell_execution.description
                };
            }

            // Add generic info if provided
            if (resolution.is_generic && resolution.generic) {
                if (!resolutionEntry.resolution) {
                    resolutionEntry.resolution = {} as any;
                }
                resolutionEntry.resolution = {
                    ...resolutionEntry.resolution,
                    bean_id: resolution.generic.bean_id,
                    tasklet_fqn: resolution.generic.bean_type === 'Tasklet' ? resolution.generic.bean_fqn : undefined,
                    reader_fqn: resolution.generic.bean_type === 'Reader' ? resolution.generic.bean_fqn : undefined,
                    writer_fqn: resolution.generic.bean_type === 'Writer' ? resolution.generic.bean_fqn : undefined,
                    processor_fqn: resolution.generic.bean_type === 'Processor' ? resolution.generic.bean_fqn : undefined
                };
            }

            // Get output path configuration
            const config = vscode.workspace.getConfiguration('batchKg');
            let outputPath = config.get<string>('yamlOutputPath', 'config/grey_area_resolution.yaml');
            
            // Extract directory from outputPath and use date-based filename
            const outputDir = path.dirname(outputPath);
            const dateBasedFilename = YamlGenerator.getFilenameWithDate();
            outputPath = path.join(outputDir, dateBasedFilename);
            
            // Determine the full path
            // Use the open workspace folder; fall back to the extension's own directory
            // so save works even when no workspace folder is open (e.g. during development)
            const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
            const basePath = workspaceFolder
                ? workspaceFolder.uri.fsPath
                : this._extensionUri.fsPath;

            const fullPath = path.join(basePath, outputPath);
            
            // Read existing YAML if it exists
            let existingYaml = '';
            if (fs.existsSync(fullPath)) {
                existingYaml = fs.readFileSync(fullPath, 'utf8');
            }

            // Generate new YAML (with duplicate checking)
            const newYaml = YamlGenerator.mergeYaml(existingYaml, [resolutionEntry]);

            // Ensure directory exists
            const dir = path.dirname(fullPath);
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
            }

            // Write YAML file
            fs.writeFileSync(fullPath, newYaml, 'utf8');

            // Show success message
            const successMsg = ` Resolution saved to ${outputPath}`;
            vscode.window.showInformationMessage(successMsg);
            
            // Open the file
            const document = await vscode.workspace.openTextDocument(fullPath);
            await vscode.window.showTextDocument(document, { preview: false });
            
            // Send success to webview
            this._panel.webview.postMessage({
                command: 'savingStatus',
                success: true,
                message: successMsg
            });
        } catch (error: any) {
            const errorMsg = ` Error saving resolution: ${error.message}`;
            console.error(errorMsg, error);
            vscode.window.showErrorMessage(errorMsg);
            
            this._panel.webview.postMessage({
                command: 'savingStatus',
                success: false,
                message: errorMsg
            });
        }
    }

    public dispose() {
        GapAnalyzerPanel.currentPanel = undefined;

        // Clean up resources
        this._panel.dispose();

        while (this._disposables.length) {
            const disposable = this._disposables.pop();
            if (disposable) {
                disposable.dispose();
            }
        }
    }

    /**
     * Update webview content using ViewBuilder
     */
    private _update() {
        const webview = this._panel.webview;
        const nonce = this.getNonce();
        
        // Use ViewBuilder to generate HTML
        this._panel.webview.html = this.viewBuilder.buildHtml(webview, nonce);
    }

    /**
     * Generate a nonce for CSP
     */
    private getNonce(): string {
        let text = '';
        const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        for (let i = 0; i < 32; i++) {
            text += possible.charAt(Math.floor(Math.random() * possible.length));
        }
        return text;
    }
}
