/**
 * Refactored Gap Analyzer Panel
 * Uses modular ViewBuilder for HTML/CSS/JS generation
 */

import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { execSync } from 'child_process';
import { ApiService } from './services/apiService';
import { YamlGenerator } from './services/yamlGenerator';
import { ResolutionEntry } from './models/types';
import { ViewBuilder } from './views/viewBuilder';

export class GapAnalyzerPanel {
    public static currentPanel: GapAnalyzerPanel | undefined;
    public static readonly viewType = 'batchIgGapAnalyzer';

    private readonly _panel: vscode.WebviewPanel;
    private readonly _extensionUri: vscode.Uri;
    private _context: vscode.ExtensionContext;
    private _disposables: vscode.Disposable[] = [];
    private neo4jService: ApiService;
    private viewBuilder: ViewBuilder;

    public static createOrShow(extensionUri: vscode.Uri, context: vscode.ExtensionContext) {
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
            'Batch IG Gap Analyzer',
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

        GapAnalyzerPanel.currentPanel = new GapAnalyzerPanel(panel, extensionUri, context);
    }

    public static revive(panel: vscode.WebviewPanel, extensionUri: vscode.Uri, context: vscode.ExtensionContext) {
        GapAnalyzerPanel.currentPanel = new GapAnalyzerPanel(panel, extensionUri, context);
    }

    private constructor(panel: vscode.WebviewPanel, extensionUri: vscode.Uri, context: vscode.ExtensionContext) {
        this._panel = panel;
        this._extensionUri = extensionUri;
        this._context = context;
        this.neo4jService = new ApiService();
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
            case 'openSourceFile':
                await this.handleOpenSourceFile(message.methodFqn);
                break;
            case 'openRepoSetup':
                await this.handleOpenRepoSetup();
                break;
            case 'viewRepoConfig':
                await this.handleOpenRepoSetup();
                break;
            case 'flushRepoCache':
                await this.handleFlushRepoCache();
                break;
            case 'validateRepoPaths':
                await this.handleValidateRepoPaths(message.pathMap);
                break;
            case 'openJavaFile':
                await this.handleOpenJavaFile(message.gitRepoName, message.filePath, message.methodFqn);
                break;
            case 'testConnection':
                await this.handleTestConnection();
                break;
        }
    }

    private async handleOpenSourceFile(methodFqn: string) {
        try {
            const result = await this.neo4jService.getJavaFileForMethod(methodFqn);
            if (!result) {
                vscode.window.showWarningMessage(
                    `Could not find method info for: ${methodFqn}\nThe JavaMethod node may not exist in the graph.`
                );
                return;
            }

            // Truncate source code to first 30 lines if longer
            let displayCode = result.sourceCode ?? '(source code not available)';
            const lines = displayCode.split('\n');
            const truncated = lines.length > 30;
            if (truncated) {
                displayCode = lines.slice(0, 30).join('\n') + '\n// ... (truncated — showing first 30 lines)';
            }

            // Determine whether a validated local path exists for this repo
            const validatedPaths = this._context.globalState.get<Record<string, string>>(
                'batchIg.validatedRepoPaths', {}
            );
            const hasLocalRepo = !!(result.gitRepoName && validatedPaths[result.gitRepoName]);

            this._panel.webview.postMessage({
                command: 'showSourceCodePopup',
                methodFqn,
                methodName: result.methodName ?? methodFqn.split('.').pop(),
                javaLineCount: result.javaLineCount,
                gitBranchName: result.gitBranchName,
                gitRepoName: result.gitRepoName,
                filePath: result.filePath,
                classFqn: result.classFqn,
                sourceCode: displayCode,
                hasLocalRepo,
            });
        } catch (error: any) {
            console.error('Error fetching source code:', error);
            vscode.window.showErrorMessage(`Error fetching source code: ${error.message}`);
        }
    }

    private async handleOpenRepoSetup() {
        try {
            const repos = await this.neo4jService.getRepositories();
            const validatedPaths = this._context.globalState.get<Record<string, string>>(
                'batchIg.validatedRepoPaths', {}
            );
            this._panel.webview.postMessage({
                command: 'reposLoaded',
                repos,
                validatedPaths,
            });
        } catch (error: any) {
            console.error('Error fetching repositories:', error);
            vscode.window.showErrorMessage(`Error fetching repositories: ${error.message}`);
        }
    }

    private async handleFlushRepoCache() {
        const choice = await vscode.window.showWarningMessage(
            'Clear all saved repository paths? You will need to re-enter them in Repo Config.',
            { modal: true },
            'Yes, Clear'
        );
        if (choice !== 'Yes, Clear') { return; }
        await this._context.globalState.update('batchIg.validatedRepoPaths', {});
        vscode.window.showInformationMessage('Repository path cache cleared.');
        this._panel.webview.postMessage({ command: 'repoCacheFlushed' });
    }

    private async handleValidateRepoPaths(        pathMap: Record<string, { localPath: string; expectedBranch: string }>
    ) {
        const results: Record<string, { valid: boolean; message: string }> = {};
        let allValid = true;

        for (const [repoName, { localPath, expectedBranch }] of Object.entries(pathMap)) {
            if (!localPath) {
                results[repoName] = { valid: false, message: 'Path is required.' };
                allValid = false;
                continue;
            }
            if (!fs.existsSync(localPath)) {
                results[repoName] = { valid: false, message: `Path does not exist: ${localPath}` };
                allValid = false;
                continue;
            }
            try {
                const actualBranch = execSync(
                    `git -C "${localPath}" rev-parse --abbrev-ref HEAD`,
                    { timeout: 5000 }
                ).toString().trim();

                if (expectedBranch && actualBranch !== expectedBranch) {
                    results[repoName] = {
                        valid: false,
                        message: `Branch mismatch: expected "${expectedBranch}", current is "${actualBranch}".`,
                    };
                    allValid = false;
                } else {
                    results[repoName] = { valid: true, message: `Validated (branch: ${actualBranch})` };
                }
            } catch (err: any) {
                results[repoName] = {
                    valid: false,
                    message: `Not a valid git repository (${err.message.split('\n')[0]})`,
                };
                allValid = false;
            }
        }

        if (allValid) {
            const pathsToSave: Record<string, string> = {};
            for (const [repoName, { localPath }] of Object.entries(pathMap)) {
                pathsToSave[repoName] = localPath;
            }
            await this._context.globalState.update('batchIg.validatedRepoPaths', pathsToSave);
        }

        this._panel.webview.postMessage({ command: 'repoValidationResult', results, allValid });
    }

    private async handleOpenJavaFile(repoName: string, filePath: string, methodFqn?: string) {
        const validatedPaths = this._context.globalState.get<Record<string, string>>(
            'batchIg.validatedRepoPaths', {}
        );
        const localRepoPath = validatedPaths[repoName];
        if (!localRepoPath) {
            vscode.window.showErrorMessage(
                `No local path configured for repository "${repoName}". Set it up via the source popup first.`
            );
            return;
        }
        if (!filePath) {
            vscode.window.showErrorMessage('No file path available for this Java class.');
            return;
        }

        // JavaClass.path starts with the repo folder name (e.g. "test_code_repo/src/...").
        // The localRepoPath already points inside that folder, so strip the leading segment
        // when it matches the last component of localRepoPath.
        const repoFolderName = path.basename(localRepoPath);
        const normalizedFilePath = filePath.replace(/\\/g, '/');
        const strippedFilePath = normalizedFilePath.startsWith(repoFolderName + '/')
            ? normalizedFilePath.slice(repoFolderName.length + 1)
            : normalizedFilePath;

        const absolutePath = path.join(localRepoPath, strippedFilePath);
        if (!fs.existsSync(absolutePath)) {
            vscode.window.showErrorMessage(`File not found at: ${absolutePath}`);
            return;
        }
        try {
            const document = await vscode.workspace.openTextDocument(absolutePath);
            const editor = await vscode.window.showTextDocument(document, { preview: false });

            // Jump to the specific method, handling overloads by matching parameter types
            if (methodFqn) {
                const sig = this.parseMethodSignature(methodFqn);
                if (sig) {
                    const lines = document.getText().split('\n');
                    const lineIndex = this.findMethodLine(lines, sig.methodName, sig.paramTypes);
                    if (lineIndex >= 0) {
                        const pos = new vscode.Position(lineIndex, 0);
                        editor.selection = new vscode.Selection(pos, pos);
                        editor.revealRange(
                            new vscode.Range(pos, pos),
                            vscode.TextEditorRevealType.InCenter
                        );
                    }
                }
            }
        } catch (err: any) {
            vscode.window.showErrorMessage(`Could not open file: ${err.message}`);
        }
    }

    /** Parse "com.pkg.Class.methodName(Type1,Type2)" → { methodName, paramTypes } */
    private parseMethodSignature(fqn: string): { methodName: string; paramTypes: string[] } | null {
        const parenOpen = fqn.indexOf('(');
        if (parenOpen === -1) { return null; }
        const beforeParen = fqn.substring(0, parenOpen);
        const inside = fqn.substring(parenOpen + 1, fqn.endsWith(')') ? fqn.length - 1 : undefined);
        const methodName = beforeParen.split('.').pop() || '';
        const paramTypes = inside ? inside.split(',').map(p => p.trim()).filter(Boolean) : [];
        return { methodName, paramTypes };
    }

    /**
     * Find the line index of a Java method declaration that matches methodName and all paramTypes.
     * Handles overloads: a line must contain the method name followed by '(' AND all
     * parameter type simple names (e.g. "Map" matches "Map<String,Integer>").
     */
    private findMethodLine(lines: string[], methodName: string, paramTypes: string[]): number {
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            // Must contain: methodName followed (somewhere) by '('
            const nameIdx = line.indexOf(methodName);
            if (nameIdx === -1) { continue; }
            const afterName = line.substring(nameIdx + methodName.length).trimStart();
            if (!afterName.startsWith('(')) { continue; }
            // Must contain each param type (simple name — no FQN prefix)
            if (paramTypes.length > 0) {
                const allMatch = paramTypes.every(pt => {
                    const simpleName = pt.split('.').pop() || pt;
                    return line.includes(simpleName);
                });
                if (!allMatch) { continue; }
            }
            return i;
        }
        return -1;
    }

    private async handleTestConnection() {
        try {
            const connected = await this.neo4jService.testConnection();
            
            this._panel.webview.postMessage({
                command: 'connectionStatus',
                success: connected,
                message: connected 
                    ? ' API connection successful!' 
                    : ' API connection failed. Check your settings.'
            });

            if (connected) {
                vscode.window.showInformationMessage(' API connection successful!');
            } else {
                vscode.window.showErrorMessage(' API connection failed. Check "batchIg.apiUrl" in settings.', 'Open Settings')
                    .then(selection => {
                        if (selection === 'Open Settings') {
                            vscode.commands.executeCommand('workbench.action.openSettings', 'batchIg');
                        }
                    });
            }
        } catch (error: any) {
            const errorMsg = ` API error: ${error.message}`;
            
            vscode.window.showErrorMessage(errorMsg, 'Open Settings')
                .then(selection => {
                    if (selection === 'Open Settings') {
                        vscode.commands.executeCommand('workbench.action.openSettings', 'batchIg');
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
            console.log('Fetching jobs from API...');
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
                            vscode.commands.executeCommand('workbench.action.openSettings', 'batchIg');
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
                            vscode.commands.executeCommand('workbench.action.openSettings', 'batchIg');
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
                            vscode.commands.executeCommand('workbench.action.openSettings', 'batchIg');
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
            const config = vscode.workspace.getConfiguration('batchIg');
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
