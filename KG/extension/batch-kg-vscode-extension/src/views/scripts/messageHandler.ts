/**
 * Message Handler for Webview Communication
 * Handles messages between webview and extension host
 */

class MessageHandler {
    private stateManager: any; // StateManager
    private formManager: any; // FormManager

    constructor(stateManager: any, formManager: any) {
        this.stateManager = stateManager;
        this.formManager = formManager;
    }

    initialize(): void {
        window.addEventListener('message', (event) => {
            this.handleMessage(event.data);
        });
    }

    private handleMessage(message: any): void {
        console.log('Received message:', message.command, message);
        switch (message.command) {
            case 'jobsLoaded':
                this.handleJobsLoaded(message.jobs);
                break;
            case 'stepsLoaded':
                this.handleStepsLoaded(message.steps);
                break;
            case 'gapsLoaded':
                this.handleGapsLoaded(message.gaps);
                break;
            case 'connectionStatus':
                this.handleConnectionStatus(message.success, message.message);
                break;
            case 'savingStatus':
                this.handleSavingStatus(message.success, message.message);
                break;
            default:
                console.warn('Unknown message command:', message.command);
        }
    }

    private handleJobsLoaded(jobs: any[]): void {
        this.stateManager.setJobs(jobs);
        this.populateJobDatalist(jobs);
    }

    private handleStepsLoaded(steps: any[]): void {
        this.stateManager.setSteps(steps);
        this.populateStepDatalist(steps);
    }

    private handleGapsLoaded(gaps: any[]): void {
        this.stateManager.setGaps(gaps);
        this.populateCategories(gaps);
    }

    private handleConnectionStatus(success: boolean, message: string): void {
        this.showStatusMessage(message, success ? 'success' : 'error');
    }

    private handleSavingStatus(success: boolean, message: string): void {
        this.showStatusMessage(message, success ? 'success' : 'error');

        // Also update the inline save status in the right panel
        const saveStatusEl = document.getElementById('saveStatus');
        if (saveStatusEl) {
            saveStatusEl.textContent = message;
            saveStatusEl.className = `save-status ${success ? 'success' : 'error'}`;
            saveStatusEl.style.display = 'block';
            if (success) {
                setTimeout(() => { saveStatusEl.style.display = 'none'; }, 4000);
            }
        }
        
        if (success) {
            // Keep form visible after save — user can make another selection or edit
            // (do NOT call resetForm here; resetting hides everything)
        }
    }

    private populateJobDatalist(jobs: any[]): void {
        console.log('Populating job datalist with', jobs.length, 'jobs');
        const jobDatalist = document.getElementById('jobList');
        if (!jobDatalist) {
            console.error('jobList element not found!');
            return;
        }

        jobDatalist.innerHTML = '';
        jobs.forEach((job) => {
            const option = document.createElement('option');
            option.value = job.name;
            option.textContent = `${job.name} (${job.gap_count || 0} gaps)`;
            jobDatalist.appendChild(option);
        });

        // Enable job input
        const jobInput = document.getElementById('jobSelect') as HTMLInputElement;
        if (jobInput) {
            jobInput.disabled = false;
            jobInput.placeholder = `Search from ${jobs.length} jobs...`;
        }
        console.log('Job datalist populated successfully');
    }

    private populateStepDatalist(steps: any[]): void {
        const stepDatalist = document.getElementById('stepList');
        if (!stepDatalist) return;

        stepDatalist.innerHTML = '';
        steps.forEach((step) => {
            const option = document.createElement('option');
            option.value = step.name;
            option.textContent = `${step.name} (${step.gap_count || 0} gaps)`;
            stepDatalist.appendChild(option);
        });

        // Enable step input
        const stepInput = document.getElementById('stepSelect') as HTMLInputElement;
        if (stepInput) {
            stepInput.disabled = false;
            stepInput.placeholder = `Search from ${steps.length} steps...`;
        }
    }

    private populateCategories(gaps: any[]): void {
        const categorySelect = document.getElementById('categorySelect') as HTMLSelectElement;
        if (!categorySelect) return;

        // Count gaps by category
        const categoryCounts: { [key: string]: number } = {};
        gaps.forEach((gap) => {
            categoryCounts[gap.category] = (categoryCounts[gap.category] || 0) + 1;
        });

        const categories = Object.keys(categoryCounts);
        this.stateManager.setCategories(categories);

        // Populate dropdown
        categorySelect.innerHTML = '<option value="">All Categories</option>';
        categories.forEach((category) => {
            const option = document.createElement('option');
            option.value = category;
            option.textContent = `${category} (${categoryCounts[category]})`;
            categorySelect.appendChild(option);
        });

        categorySelect.disabled = false;

        // Auto-populate gap dropdown with all gaps
        this.populateGapDropdown(gaps, '');
    }

    private populateGapDropdown(gaps: any[], category: string): void {
        const gapSelect = document.getElementById('gapSelect') as HTMLSelectElement;
        if (!gapSelect) return;

        const filteredGaps = category ? 
            gaps.filter((gap: any) => gap.category === category) : 
            gaps;

        gapSelect.innerHTML = '<option value="">Select a gap...</option>';
        filteredGaps.forEach((gap: any, index: number) => {
            const option = document.createElement('option');
            const gapIndex = gaps.indexOf(gap);
            option.value = gapIndex.toString();
            option.textContent = `${gap.method_fqn} (${gap.confidence})`;
            gapSelect.appendChild(option);
        });

        gapSelect.disabled = filteredGaps.length === 0;
    }

    private showStatusMessage(message: string, type: 'success' | 'error'): void {
        // Remove existing status messages
        const existing = document.querySelector('.status-message');
        if (existing) {
            existing.remove();
        }

        // Create new status message
        const statusDiv = document.createElement('div');
        statusDiv.className = `status-message ${type}`;
        statusDiv.textContent = message;
        document.body.appendChild(statusDiv);

        // Auto-remove after 3 seconds
        setTimeout(() => {
            statusDiv.remove();
        }, 3000);
    }
}

// Export for use in webview
if (typeof window !== 'undefined') {
    (window as any).MessageHandler = MessageHandler;
}
