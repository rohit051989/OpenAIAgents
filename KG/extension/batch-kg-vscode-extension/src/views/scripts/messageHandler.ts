/**
 * Message Handler for Webview Communication
 * Handles messages between webview and extension host
 */

class MessageHandler {
    private stateManager: any; // StateManager
    private formManager: any; // FormManager
    private repos: any[] = [];

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
            case 'showSourceCodePopup':
                this.handleShowSourceCodePopup(message);
                break;
            case 'reposLoaded':
                this.handleReposLoaded(message.repos, message.validatedPaths || {});
                break;
            case 'repoValidationResult':
                this.handleRepoValidationResult(message.results, message.allValid);
                break;
            case 'repoCacheFlushed':
                // After flush the popup footer should show setup link, not view-file button.
                // Nothing visible changes immediately unless the popup is open — safe to no-op.
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

    private handleShowSourceCodePopup(msg: any): void {
        const overlay = document.getElementById('sourceCodePopupOverlay');
        if (!overlay) { return; }

        // Populate title
        const title = document.getElementById('popupMethodTitle');
        if (title) { title.textContent = msg.methodName || msg.methodFqn || ''; }

        // Populate source code (textContent escapes all HTML automatically)
        const codeEl = document.getElementById('popupSourceCode');
        if (codeEl) { codeEl.textContent = msg.sourceCode || '(no source code available)'; }

        // Populate each meta item — show the wrapper only when a value is present
        const setMeta = (wrapperId: string, valueId: string, value: string | number | null | undefined) => {
            const wrapper = document.getElementById(wrapperId);
            const valueEl = document.getElementById(valueId);
            if (!wrapper || !valueEl) { return; }
            if (value != null && value !== '') {
                valueEl.textContent = String(value);
                wrapper.style.display = 'inline';
            } else {
                wrapper.style.display = 'none';
            }
        };

        setMeta('popupMetaRepo',   'popupMetaRepoValue',   msg.gitRepoName);
        setMeta('popupMetaBranch', 'popupMetaBranchValue', msg.gitBranchName);
        setMeta('popupMetaPath',   'popupMetaPathValue',   msg.filePath);
        setMeta('popupMetaLines',  'popupMetaLinesValue',  msg.javaLineCount);

        // Hide the meta bar entirely if no values are available
        const metaBar = document.getElementById('popupMeta');
        if (metaBar) {
            const hasAny = [msg.gitRepoName, msg.gitBranchName, msg.filePath, msg.javaLineCount]
                .some(v => v != null && v !== '');
            metaBar.style.display = hasAny ? 'block' : 'none';
        }

        const hide = () => { overlay.classList.add('popup-overlay--hidden'); };

        // Show overlay by removing the hidden class
        overlay.classList.remove('popup-overlay--hidden');

        // Wire close button — replace node to avoid stacking duplicate listeners
        const closeBtn = document.getElementById('closeSourcePopup');
        if (closeBtn) {
            const freshBtn = closeBtn.cloneNode(true) as HTMLElement;
            closeBtn.parentNode!.replaceChild(freshBtn, closeBtn);
            freshBtn.addEventListener('click', hide);
        }

        // Close on backdrop click
        overlay.onclick = (e) => { if (e.target === overlay) { hide(); } };

        // Action footer: toggle between setup link and view-file button based on hasLocalRepo
        const setupLink = document.getElementById('popupSetupRepoLink');
        const viewFileBtn = document.getElementById('popupViewFileBtn');

        if (setupLink && viewFileBtn) {
            if (msg.hasLocalRepo) {
                setupLink.classList.add('popup-overlay--hidden');
                viewFileBtn.classList.remove('popup-overlay--hidden');
            } else {
                setupLink.classList.remove('popup-overlay--hidden');
                viewFileBtn.classList.add('popup-overlay--hidden');
            }

            // Wire "Setup Local Repos" link — capture repo/file from current message
            const freshLink = setupLink.cloneNode(true) as HTMLElement;
            setupLink.parentNode!.replaceChild(freshLink, setupLink);
            freshLink.addEventListener('click', (e) => {
                e.preventDefault();
                hide();
                this.stateManager.sendMessage('openRepoSetup');
            });

            // Wire "View Full File" button — capture repo name and file path in closure
            const capturedRepo = msg.gitRepoName as string;
            const capturedFile = msg.filePath as string;
            const capturedFqn  = msg.methodFqn as string;
            const freshViewBtn = viewFileBtn.cloneNode(true) as HTMLElement;
            viewFileBtn.parentNode!.replaceChild(freshViewBtn, viewFileBtn);
            freshViewBtn.addEventListener('click', () => {
                hide();
                this.stateManager.sendMessage('openJavaFile', {
                    gitRepoName: capturedRepo,
                    filePath: capturedFile,
                    methodFqn: capturedFqn,
                });
            });
        }
    }

    private handleReposLoaded(repos: any[], validatedPaths: Record<string, string>): void {
        this.repos = repos;

        const overlay = document.getElementById('repoSetupOverlay');
        if (!overlay) { return; }
        overlay.classList.remove('popup-overlay--hidden');

        const loading = document.getElementById('repoSetupLoading');
        const content = document.getElementById('repoSetupContent');
        if (loading) { loading.classList.add('popup-overlay--hidden'); }
        if (content) { content.classList.remove('popup-overlay--hidden'); }

        const cardsList = document.getElementById('repoCardsList');
        if (!cardsList) { return; }
        cardsList.innerHTML = '';

        if (repos.length === 0) {
            cardsList.innerHTML = '<p class="repo-empty-msg">No Repository nodes found in the graph.</p>';
        } else {
            repos.forEach((repo) => {
                const repoName = repo.repoName || repo.name || '';
                const existingPath = validatedPaths[repoName] || '';
                const card = document.createElement('div');
                card.className = 'repo-card';
                card.innerHTML = `
                    <div class="repo-card-info">
                        <div class="repo-card-name">${this.escapeHtml(repoName)}</div>
                        <div class="repo-card-detail">
                            <span class="repo-detail-label">Clone URL:</span>
                            ${this.escapeHtml(repo.repoUrl || '—')}
                        </div>
                        <div class="repo-card-detail">
                            <span class="repo-detail-label">Branch:</span>
                            <code>${this.escapeHtml(repo.branchName || '—')}</code>
                        </div>
                        ${repo.repoUrl ? `<div class="repo-card-detail repo-clone-cmd">
                            <span class="repo-detail-label">Clone command:</span>
                            <code>git clone -b ${this.escapeHtml(repo.branchName || 'main')} ${this.escapeHtml(repo.repoUrl)}</code>
                        </div>` : ''}
                    </div>
                    <div class="repo-path-group">
                        <label class="repo-path-label">Local path (where you cloned this repo):</label>
                        <input type="text" class="repo-path-input"
                            data-repo-name="${this.escapeHtml(repoName)}"
                            data-branch="${this.escapeHtml(repo.branchName || '')}"
                            placeholder="e.g. C:\\projects\\${this.escapeHtml(repoName)}"
                            value="${this.escapeHtml(existingPath)}" />
                        <div class="repo-validation-badge" id="badge-${this.escapeHtml(repoName)}"></div>
                    </div>`;
                cardsList.appendChild(card);
            });
        }

        // Wire Validate button
        const validateBtn = document.getElementById('validateRepoPathsBtn');
        if (validateBtn) {
            const fresh = validateBtn.cloneNode(true) as HTMLElement;
            validateBtn.parentNode!.replaceChild(fresh, validateBtn);
            fresh.addEventListener('click', () => this.submitValidation());
        }

        // Wire Back button
        const backBtn = document.getElementById('repoSetupBackBtn');
        if (backBtn) {
            const fresh = backBtn.cloneNode(true) as HTMLElement;
            backBtn.parentNode!.replaceChild(fresh, backBtn);
            fresh.addEventListener('click', () => this.closeRepoSetup());
        }

        // Hide validation summary
        const summary = document.getElementById('repoValidationSummary');
        if (summary) { summary.classList.add('popup-overlay--hidden'); }
    }

    private closeRepoSetup(): void {
        const overlay = document.getElementById('repoSetupOverlay');
        if (overlay) { overlay.classList.add('popup-overlay--hidden'); }
        // Reset loading/content for next visit
        const loading = document.getElementById('repoSetupLoading');
        const content = document.getElementById('repoSetupContent');
        if (loading) { loading.classList.remove('popup-overlay--hidden'); }
        if (content) { content.classList.add('popup-overlay--hidden'); }
    }

    private submitValidation(): void {
        const inputs = document.querySelectorAll('.repo-path-input') as NodeListOf<HTMLInputElement>;
        const pathMap: Record<string, { localPath: string; expectedBranch: string }> = {};

        inputs.forEach((input) => {
            const name = input.getAttribute('data-repo-name') || '';
            const branch = input.getAttribute('data-branch') || '';
            if (name) {
                pathMap[name] = { localPath: input.value.trim(), expectedBranch: branch };
            }
        });

        if (Object.keys(pathMap).length === 0) { return; }

        const btn = document.getElementById('validateRepoPathsBtn') as HTMLButtonElement | null;
        if (btn) { btn.textContent = 'Validating\u2026'; btn.disabled = true; }

        this.stateManager.sendMessage('validateRepoPaths', { pathMap });
    }

    private handleRepoValidationResult(
        results: Record<string, { valid: boolean; message: string }>,
        allValid: boolean
    ): void {
        for (const [repoName, result] of Object.entries(results)) {
            const badge = document.getElementById(`badge-${repoName}`);
            if (badge) {
                badge.textContent = (result.valid ? '\u2713 ' : '\u2717 ') + result.message;
                badge.className = `repo-validation-badge ${result.valid ? 'badge-valid' : 'badge-invalid'}`;
            }
        }

        const btn = document.getElementById('validateRepoPathsBtn') as HTMLButtonElement | null;
        if (btn) { btn.textContent = 'Validate Paths'; btn.disabled = false; }

        const summary = document.getElementById('repoValidationSummary');
        if (summary) {
            summary.classList.remove('popup-overlay--hidden');
            if (allValid) {
                summary.textContent = '\u2713 All repositories validated! Click \u201cView Full File in Editor\u201d in the source popup to open Java files.';
                summary.className = 'repo-validation-summary validation-success';
            } else {
                summary.textContent = '\u2717 Some paths could not be validated. Check the details above and try again.';
                summary.className = 'repo-validation-summary validation-error';
            }
        }
    }

    private escapeHtml(text: string): string {
        return text
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
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
            option.textContent = job.name;
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
