/**
 * View Builder for Webview
 * Assembles HTML templates, CSS styles, and JavaScript modules
 */

import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';

export class ViewBuilder {
    private extensionUri: vscode.Uri;
    private templateCache: Map<string, string> = new Map();
    private cssCache: Map<string, string> = new Map();

    constructor(extensionUri: vscode.Uri) {
        this.extensionUri = extensionUri;
    }

    /**
     * Build complete HTML for webview
     */
    public buildHtml(webview: vscode.Webview, nonce: string): string {
        // Read all templates
        const mainTemplate = this.readTemplate('main.html');
        const headerTemplate = this.readTemplate('header.html');
        const leftPanelTemplate = this.readTemplate('leftPanel.html');
        const rightPanelTemplate = this.readTemplate('rightPanel.html');
        
        // Read form templates
        const dbFieldsTemplate = this.readTemplate('forms/dbFields.html');
        const procedureFieldsTemplate = this.readTemplate('forms/procedureFields.html');
        const shellFieldsTemplate = this.readTemplate('forms/shellFields.html');

        // Assemble right panel with form templates
        const rightPanel = rightPanelTemplate
            .replace('{{dbFields}}', dbFieldsTemplate)
            .replace('{{procedureFields}}', procedureFieldsTemplate)
            .replace('{{shellFields}}', shellFieldsTemplate);

        // Read and combine CSS
        const styles = this.buildStyles(nonce);

        // Read and combine JavaScript
        const script = this.buildScript(webview, nonce);

        // Assemble main template
        const cspSource = webview.cspSource;
        const html = mainTemplate
            .replace(/\{\{cspSource\}\}/g, cspSource)
            .replace(/\{\{nonce\}\}/g, nonce)
            .replace('{{styles}}', styles)
            .replace('{{header}}', headerTemplate)
            .replace('{{leftPanel}}', leftPanelTemplate)
            .replace('{{rightPanel}}', rightPanel)
            .replace('{{script}}', script);

        return html;
    }

    /**
     * Read a template file from views/templates/
     */
    private readTemplate(filename: string): string {
        if (this.templateCache.has(filename)) {
            return this.templateCache.get(filename)!;
        }

        const templatePath = path.join(
            this.extensionUri.fsPath,
            'src',
            'views',
            'templates',
            filename
        );

        try {
            const content = fs.readFileSync(templatePath, 'utf8');
            this.templateCache.set(filename, content);
            return content;
        } catch (error) {
            console.error(`Failed to read template ${filename}:`, error);
            return `<!-- Template ${filename} not found -->`;
        }
    }

    /**
     * Read a CSS file from views/styles/
     */
    private readCss(filename: string): string {
        if (this.cssCache.has(filename)) {
            return this.cssCache.get(filename)!;
        }

        const cssPath = path.join(
            this.extensionUri.fsPath,
            'src',
            'views',
            'styles',
            filename
        );

        try {
            const content = fs.readFileSync(cssPath, 'utf8');
            this.cssCache.set(filename, content);
            return content;
        } catch (error) {
            console.error(`Failed to read CSS ${filename}:`, error);
            return `/* CSS ${filename} not found */`;
        }
    }

    /**
     * Build combined CSS styles
     */
    private buildStyles(nonce: string): string {
        const cssFiles = [
            'base.css',
            'layout.css',
            'forms.css',
            'components.css'
        ];

        const combinedCss = cssFiles
            .map(file => this.readCss(file))
            .join('\n\n');

        // Return only CSS content (template has the <style> tag)
        return combinedCss;
    }

    /**
     * Build JavaScript bundle for webview
     */
    private buildScript(webview: vscode.Webview, nonce: string): string {
        // Read and inline all scripts in correct order to avoid async loading issues
        const scriptFiles = [
            'stateManager.js',
            'formManager.js',
            'messageHandler.js',
            'eventHandlers.js',
            'app.js'
        ];

        let combinedScript = '';
        
        for (const file of scriptFiles) {
            const scriptPath = path.join(
                this.extensionUri.fsPath,
                'out',
                'views',
                'scripts',
                file
            );
            
            try {
                const scriptContent = fs.readFileSync(scriptPath, 'utf8');
                // Remove source map reference as it causes CSP issues
                const cleanedContent = scriptContent.replace(/\/\/# sourceMappingURL=.*$/gm, '');
                combinedScript += `\n// === ${file} ===\n${cleanedContent}\n`;
            } catch (error) {
                console.error(`Failed to read script ${file}:`, error);
                combinedScript += `\n// ERROR: Failed to load ${file}\n`;
            }
        }

        // Return only script content (template has the <script> tag)
        return combinedScript;
    }

    /**
     * Clear template and CSS caches (useful for development)
     */
    public clearCache(): void {
        this.templateCache.clear();
        this.cssCache.clear();
    }
}
