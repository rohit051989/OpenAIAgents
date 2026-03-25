/**
 * Application Entry Point for Webview
 * Initializes all modules and starts the application
 */

(function() {
    // Get VS Code API
    const vscode = acquireVsCodeApi();

    // Initialize managers
    const stateManager = new (window as any).StateManager(vscode);
    const formManager = new (window as any).FormManager();
    const messageHandler = new (window as any).MessageHandler(stateManager, formManager);
    const eventHandlers = new (window as any).EventHandlers(stateManager, formManager);

    // Initialize all modules
    function initializeApp() {
        messageHandler.initialize();
        eventHandlers.initialize();
        
        console.log('Application initialized successfully');
    }

    // Start application when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initializeApp);
    } else {
        initializeApp();
    }
})();
