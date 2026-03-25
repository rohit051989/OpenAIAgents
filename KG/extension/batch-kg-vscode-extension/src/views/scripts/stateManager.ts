/**
 * State Manager for Webview Application
 * Manages the application state including jobs, steps, gaps, and resolution data
 */

interface AppState {
    jobs: Job[];
    selectedJob: string;
    steps: Step[];
    selectedStep: string;
    gaps: GapInfo[];
    selectedGap: GapInfo | null;
    categories: string[];
    selectedCategory: string;
    vscode: any;
}

interface Job {
    name: string;
    gap_count: number;
}

interface Step {
    name: string;
    gap_count: number;
}

interface GapInfo {
    category: string;
    method_fqn: string;
    description: string;
    type_specific_info: any;
    confidence: string;
}

class StateManager {
    private state: AppState;
    private listeners: Set<(state: AppState) => void>;

    constructor(vscode: any) {
        this.state = {
            jobs: [],
            selectedJob: '',
            steps: [],
            selectedStep: '',
            gaps: [],
            selectedGap: null,
            categories: [],
            selectedCategory: '',
            vscode: vscode
        };
        this.listeners = new Set();
    }

    getState(): AppState {
        return { ...this.state };
    }

    setState(partial: Partial<AppState>): void {
        this.state = { ...this.state, ...partial };
        this.notifyListeners();
    }

    subscribe(listener: (state: AppState) => void): () => void {
        this.listeners.add(listener);
        return () => this.listeners.delete(listener);
    }

    private notifyListeners(): void {
        this.listeners.forEach(listener => listener(this.getState()));
    }

    // Job operations
    setJobs(jobs: Job[]): void {
        this.setState({ jobs });
    }

    selectJob(jobName: string): void {
        this.setState({ 
            selectedJob: jobName,
            steps: [],
            selectedStep: '',
            gaps: [],
            selectedGap: null,
            categories: [],
            selectedCategory: ''
        });
    }

    // Step operations
    setSteps(steps: Step[]): void {
        this.setState({ steps });
    }

    selectStep(stepName: string): void {
        this.setState({ 
            selectedStep: stepName,
            gaps: [],
            selectedGap: null,
            categories: [],
            selectedCategory: ''
        });
    }

    // Category operations
    setCategories(categories: string[]): void {
        this.setState({ categories });
    }

    selectCategory(category: string): void {
        this.setState({ 
            selectedCategory: category,
            selectedGap: null
        });
    }

    // Gap operations
    setGaps(gaps: GapInfo[]): void {
        this.setState({ gaps });
    }

    selectGap(gap: GapInfo): void {
        this.setState({ selectedGap: gap });
    }

    clearSelection(): void {
        this.setState({
            selectedJob: '',
            selectedStep: '',
            selectedCategory: '',
            selectedGap: null,
            steps: [],
            gaps: [],
            categories: []
        });
    }

    // Message sending helper
    sendMessage(command: string, data?: any): void {
        this.state.vscode.postMessage({ command, ...data });
    }
}

// Export for use in webview
if (typeof window !== 'undefined') {
    (window as any).StateManager = StateManager;
}
