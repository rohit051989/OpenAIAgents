import * as vscode from 'vscode';
import { GapAnalyzerPanel } from './gapAnalyzerPanel';

export function activate(context: vscode.ExtensionContext) {
    console.log('Batch KG Gap Analyzer extension is now active');

    // Register command to open Gap Analyzer
    const openGapAnalyzer = vscode.commands.registerCommand('batchKg.openGapAnalyzer', () => {
        GapAnalyzerPanel.createOrShow(context.extensionUri);
    });

    context.subscriptions.push(openGapAnalyzer);

    // Register serializer for webview persistence
    if (vscode.window.registerWebviewPanelSerializer) {
        vscode.window.registerWebviewPanelSerializer(GapAnalyzerPanel.viewType, {
            async deserializeWebviewPanel(webviewPanel: vscode.WebviewPanel, state: any) {
                GapAnalyzerPanel.revive(webviewPanel, context.extensionUri);
            }
        });
    }
}

export function deactivate() {
    console.log('Batch KG Gap Analyzer extension is now deactivated');
}
