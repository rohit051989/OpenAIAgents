/**
 * Type declarations for VS Code Webview API
 */

declare function acquireVsCodeApi(): {
    postMessage(message: any): void;
    getState(): any;
    setState(state: any): void;
};
