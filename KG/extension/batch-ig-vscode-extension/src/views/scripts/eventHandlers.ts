/**
 * Event Handlers for Webview UI
 * Manages all user interactions and UI events
 */

class EventHandlers {
    private stateManager: any; // StateManager
    private formManager: any; // FormManager

    constructor(stateManager: any, formManager: any) {
        this.stateManager = stateManager;
        this.formManager = formManager;
    }

    initialize(): void {
        this.setupConnectionTest();
        this.setupRepoCacheButtons();
        this.setupJobSelection();
        this.setupStepSelection();
        this.setupCategorySelection();
        this.setupGapSelection();
        this.setupFormEvents();
        this.setupPanelToggles();
    }

    private setupConnectionTest(): void {
        const testBtn = document.getElementById('testConnectionBtn');
        if (testBtn) {
            testBtn.addEventListener('click', () => {
                this.stateManager.sendMessage('testConnection');
            });
        }
    }

    private setupRepoCacheButtons(): void {
        const viewBtn = document.getElementById('viewRepoConfigBtn');
        if (viewBtn) {
            viewBtn.addEventListener('click', () => {
                this.stateManager.sendMessage('viewRepoConfig');
            });
        }

        const flushBtn = document.getElementById('flushRepoCacheBtn');
        if (flushBtn) {
            flushBtn.addEventListener('click', () => {
                // Confirmation is done in the extension host via VS Code's showWarningMessage
                // (window.confirm is blocked in VS Code webviews)
                this.stateManager.sendMessage('flushRepoCache');
            });
        }
    }

    private setupJobSelection(): void {
        const jobInput = document.getElementById('jobSelect') as HTMLInputElement;
        if (jobInput) {
            jobInput.addEventListener('input', (e) => {
                const target = e.target as HTMLInputElement;
                const selectedJob = target.value;
                const jobList = document.getElementById('jobList') as HTMLDataListElement;

                if (!selectedJob || !jobList) { return; }

                // Only trigger when the value exactly matches a datalist option
                const isValidJob = Array.from(jobList.options).some(o => o.value === selectedJob);
                if (!isValidJob) { return; }

                this.stateManager.selectJob(selectedJob);
                this.stateManager.sendMessage('getSteps', { jobName: selectedJob });

                // Reset step and gap dropdowns when job changes
                const stepInput = document.getElementById('stepSelect') as HTMLInputElement;
                if (stepInput) { stepInput.value = ''; stepInput.disabled = true; }
                const categorySelect = document.getElementById('categorySelect') as HTMLSelectElement;
                if (categorySelect) { categorySelect.innerHTML = '<option value="">-- Select a Category --</option>'; categorySelect.disabled = true; }
                const gapSelect = document.getElementById('gapSelect') as HTMLSelectElement;
                if (gapSelect) { gapSelect.innerHTML = '<option value="">-- Select a Gap --</option>'; gapSelect.disabled = true; }
            });

            // Load jobs on first focus
            jobInput.addEventListener('focus', () => {
                const state = this.stateManager.getState();
                if (state.jobs.length === 0) {
                    this.stateManager.sendMessage('getJobs');
                }
            });
        }
    }

    private setupStepSelection(): void {
        const stepInput = document.getElementById('stepSelect') as HTMLInputElement;
        if (stepInput) {
            stepInput.addEventListener('input', (e) => {
                const target = e.target as HTMLInputElement;
                const selectedStep = target.value;
                const stepList = document.getElementById('stepList') as HTMLDataListElement;
                const state = this.stateManager.getState();

                if (!selectedStep || !stepList || !state.selectedJob) { return; }

                // Only trigger when the value exactly matches a datalist option
                const isValidStep = Array.from(stepList.options).some(o => o.value === selectedStep);
                if (!isValidStep) { return; }

                this.stateManager.selectStep(selectedStep);
                this.stateManager.sendMessage('getGaps', {
                    jobName: state.selectedJob,
                    stepName: selectedStep
                });

                // Reset category and gap dropdowns when step changes
                const categorySelect = document.getElementById('categorySelect') as HTMLSelectElement;
                if (categorySelect) { categorySelect.innerHTML = '<option value="">-- Select a Category --</option>'; categorySelect.disabled = true; }
                const gapSelect = document.getElementById('gapSelect') as HTMLSelectElement;
                if (gapSelect) { gapSelect.innerHTML = '<option value="">-- Select a Gap --</option>'; gapSelect.disabled = true; }
            });
        }
    }

    private setupCategorySelection(): void {
        const categorySelect = document.getElementById('categorySelect');
        if (categorySelect) {
            categorySelect.addEventListener('change', (e) => {
                const target = e.target as HTMLSelectElement;
                const category = target.value;
                
                this.stateManager.selectCategory(category);
                this.populateGapDropdown(category);
            });
        }
    }

    private setupGapSelection(): void {
        const gapSelect = document.getElementById('gapSelect');
        if (gapSelect) {
            gapSelect.addEventListener('change', (e) => {
                const target = e.target as HTMLSelectElement;
                const gapIndex = parseInt(target.value);
                const state = this.stateManager.getState();
                
                if (!isNaN(gapIndex) && state.gaps[gapIndex]) {
                    const gap = state.gaps[gapIndex];
                    this.stateManager.selectGap(gap);
                    this.formManager.populateForm(gap);
                    this.showGapInfo(gap);
                }
            });
        }
    }

    private setupFormEvents(): void {
        // Generic checkbox
        const genericCheckbox = document.getElementById('genericCheckbox') as HTMLInputElement;
        if (genericCheckbox) {
            genericCheckbox.addEventListener('change', (e) => {
                const target = e.target as HTMLInputElement;
                this.formManager.toggleGenericSection(target.checked);
            });
        }

        // Save button
        const saveBtn = document.getElementById('saveBtn');
        if (saveBtn) {
            saveBtn.addEventListener('click', () => {
                try {
                    const state = this.stateManager.getState();
                    if (!state.selectedGap) {
                        console.warn('[Save] No gap selected in state');
                        this.showSaveStatus('Please select a gap before saving.', 'error');
                        return;
                    }
                    const formData = this.formManager.collectFormData();
                    console.log('[Save] Sending saveResolution', { gap: state.selectedGap, resolution: formData });
                    this.stateManager.sendMessage('saveResolution', {
                        gap: state.selectedGap,
                        resolution: formData
                    });
                    this.showSaveStatus('Saving…', 'info');
                } catch (err) {
                    console.error('[Save] Unexpected error:', err);
                    this.showSaveStatus('Unexpected error — check Developer Console.', 'error');
                }
            });
        }

        // Cancel button — restores the form to the values from the currently selected gap
        const cancelBtn = document.getElementById('cancelBtn');
        if (cancelBtn) {
            cancelBtn.addEventListener('click', () => {
                const state = this.stateManager.getState();
                if (state.selectedGap) {
                    // Re-populate the form with the original gap values (discards user edits)
                    this.formManager.populateForm(state.selectedGap);
                }
            });
        }
    }

    private setupPanelToggles(): void {
        // Left panel toggle
        const leftToggle = document.getElementById('leftPanelToggle');
        const leftPanel = document.querySelector('.left-panel');
        if (leftToggle && leftPanel) {
            leftToggle.addEventListener('click', () => {
                leftPanel.classList.toggle('collapsed');
                leftToggle.textContent = leftPanel.classList.contains('collapsed') ? '→' : '←';
            });
        }

        // Right panel toggle
        const rightToggle = document.getElementById('rightPanelToggle');
        const rightPanel = document.querySelector('.right-panel');
        if (rightToggle && rightPanel) {
            rightToggle.addEventListener('click', () => {
                rightPanel.classList.toggle('collapsed');
                rightToggle.textContent = rightPanel.classList.contains('collapsed') ? '←' : '→';
            });
        }
    }

    private populateGapDropdown(category: string): void {
        const state = this.stateManager.getState();
        const gapSelect = document.getElementById('gapSelect') as HTMLSelectElement;
        
        if (!gapSelect) return;

        const filteredGaps = state.gaps.filter((gap: GapInfo) => 
            !category || gap.category === category
        );

        gapSelect.innerHTML = '<option value="">Select a gap...</option>';
        filteredGaps.forEach((gap: GapInfo, index: number) => {
            const option = document.createElement('option');
            const gapIndex = state.gaps.indexOf(gap);
            option.value = gapIndex.toString();
            option.textContent = `${gap.method_fqn} (${gap.confidence})`;
            gapSelect.appendChild(option);
        });

        gapSelect.disabled = filteredGaps.length === 0;
    }

    private showGapInfo(gap: GapInfo): void {
        const gapInfoDiv = document.getElementById('gapInfo');
        if (!gapInfoDiv) return;

        const typeSpecific = gap.type_specific_info ? 
            `<p><strong>Details:</strong> ${JSON.stringify(gap.type_specific_info, null, 2)}</p>` : '';

        // Sanitise method_fqn for use as a data attribute (no quotes needed — stored in JS closure)
        gapInfoDiv.innerHTML = `
            <h3>Gap Information</h3>
            <p><strong>Category:</strong> ${gap.category}</p>
            <p><strong>Method:</strong> ${gap.method_fqn}</p>
            <p><strong>Confidence:</strong> ${gap.confidence}</p>
            <p><strong>Description:</strong> ${gap.description || 'N/A'}</p>
            ${typeSpecific}
            <p><a id="viewCodeLink" class="view-code-link" href="#">🔍 Click to view code</a></p>
        `;
        gapInfoDiv.style.display = 'block';

        // Wire click after innerHTML is set (setTimeout 0 ensures DOM is ready)
        const link = document.getElementById('viewCodeLink');
        if (link) {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                this.stateManager.sendMessage('openSourceFile', { methodFqn: gap.method_fqn });
            });
        }
    }

    showSaveStatus(message: string, type: 'success' | 'error' | 'info'): void {
        const el = document.getElementById('saveStatus');
        if (!el) { return; }
        el.textContent = message;
        el.className = `save-status ${type}`;
        el.style.display = 'block';
        if (type === 'success') {
            setTimeout(() => { el.style.display = 'none'; }, 4000);
        }
    }
}

// Export for use in webview
if (typeof window !== 'undefined') {
    (window as any).EventHandlers = EventHandlers;
}
