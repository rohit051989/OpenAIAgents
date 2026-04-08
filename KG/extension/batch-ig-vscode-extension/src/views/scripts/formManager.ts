/**
 * Form Manager for Resolution Form
 * Handles form population, validation, and data collection
 */

class FormManager {
    constructor() {}

    populateForm(gap: any): void {
        // Hide placeholder, show the resolution section
        const placeholder = document.getElementById('resolutionPlaceholder');
        if (placeholder) { placeholder.style.display = 'none'; }

        // 1. Show the resolution section
        const resolutionSection = document.getElementById('resolutionSection');
        if (resolutionSection) {
            resolutionSection.style.display = 'block';
        }

        // 2. Reset form fields (scoped to resolution section only)
        this.resetFormFields();

        // 3. Set method FQN
        const methodFqnInput = document.getElementById('methodFqn') as HTMLInputElement;
        if (methodFqnInput) {
            methodFqnInput.value = gap.method_fqn || '';
        }

        // 4. Show only the relevant category section
        this.toggleSectionsByCategory(gap.category);

        // 5. Populate category-specific fields
        if (gap.category === 'DB_OPERATION') {
            this.populateDBFields(gap);
        } else if (gap.category === 'PROCEDURE_CALL') {
            this.populateProcedureFields(gap);
        } else if (gap.category === 'SHELL_EXECUTION') {
            this.populateShellFields(gap);
        }
    }

    private toggleSectionsByCategory(category: string): void {
        // IDs match the actual template IDs: dbFields, procFields, shellFields
        const dbSection = document.getElementById('dbFields');
        const procSection = document.getElementById('procFields');
        const shellSection = document.getElementById('shellFields');

        if (dbSection) { dbSection.style.display = category === 'DB_OPERATION' ? 'block' : 'none'; }
        if (procSection) { procSection.style.display = category === 'PROCEDURE_CALL' ? 'block' : 'none'; }
        if (shellSection) { shellSection.style.display = category === 'SHELL_EXECUTION' ? 'block' : 'none'; }
    }

    private populateDBFields(gap: any): void {
        const info = gap.type_specific_info || {};
        this.setInputValue('dbOperation', info.operation || '');
        this.setInputValue('dbTable', info.table_name || '');
        this.setInputValue('dbSchema', info.schema || '');
        this.setInputValue('dbConfidence', gap.confidence || 'MEDIUM');
    }

    private populateProcedureFields(gap: any): void {
        const info = gap.type_specific_info || {};
        this.setInputValue('procOracleType', info.oracle_type || 'PROCEDURE');
        this.setInputValue('procName', info.procedure_name || '');
        this.setInputValue('procSchema', info.schema || '');
        this.setInputValue('procPackage', info.package || '');
        this.setInputValue('procDatabaseType', info.database_type || 'ORACLE');
        this.setInputValue('procConfidence', gap.confidence || 'MEDIUM');
    }

    private populateShellFields(gap: any): void {
        const info = gap.type_specific_info || {};
        this.setInputValue('shellScript', info.script_name || '');
        this.setInputValue('shellPath', info.script_path || '');
        this.setInputValue('shellType', info.script_type || 'BASH');
        this.setInputValue('shellConfidence', gap.confidence || 'MEDIUM');
        this.setInputValue('shellRemoteHost', info.remote_host || '');
        this.setInputValue('shellRemoteUser', info.remote_user || '');
        this.setInputValue('shellRemotePort', info.remote_port ? String(info.remote_port) : '22');
        this.setInputValue('shellSshKey', info.ssh_key_path || '');
        this.setInputValue('shellDescription', info.description || '');
    }

    toggleGenericSection(enabled: boolean): void {
        const genericFields = document.getElementById('genericFields');
        // Show/hide extra generic fields only — never hide the category fields
        if (genericFields) { genericFields.style.display = enabled ? 'block' : 'none'; }
    }

    collectFormData(): any {
        const methodFqn = this.getInputValue('methodFqn');
        const isGeneric = (document.getElementById('genericCheckbox') as HTMLInputElement)?.checked;

        const data: any = { method_fqn: methodFqn, is_generic: isGeneric };

        if (isGeneric) {
            data.generic = {
                bean_id: this.getInputValue('beanId'),
                bean_type: this.getInputValue('beanType'),
                bean_fqn: this.getInputValue('beanFqn')
            };
        }

        // Collect from whichever section is currently visible
        const dbSection = document.getElementById('dbFields');
        const procSection = document.getElementById('procFields');
        const shellSection = document.getElementById('shellFields');

        if (dbSection && dbSection.style.display !== 'none') {
            data.db_operation = {
                operation: this.getInputValue('dbOperation'),
                table_name: this.getInputValue('dbTable'),
                schema: this.getInputValue('dbSchema'),
                confidence: this.getInputValue('dbConfidence')
            };
        } else if (procSection && procSection.style.display !== 'none') {
            data.procedure_call = {
                oracle_type: this.getInputValue('procOracleType'),
                object_name: this.getInputValue('procName'),
                schema: this.getInputValue('procSchema'),
                package: this.getInputValue('procPackage'),
                database_type: this.getInputValue('procDatabaseType'),
                confidence: this.getInputValue('procConfidence')
            };
        } else if (shellSection && shellSection.style.display !== 'none') {
            data.shell_execution = {
                script_name: this.getInputValue('shellScript'),
                script_path: this.getInputValue('shellPath'),
                script_type: this.getInputValue('shellType'),
                confidence: this.getInputValue('shellConfidence'),
                remote_host: this.getInputValue('shellRemoteHost'),
                remote_user: this.getInputValue('shellRemoteUser'),
                remote_port: this.getInputValue('shellRemotePort'),
                ssh_key_path: this.getInputValue('shellSshKey'),
                description: this.getInputValue('shellDescription')
            };
        }

        return data;
    }

    // Resets only inputs inside the resolution section (never touches left panel)
    private resetFormFields(): void {
        const resolutionSection = document.getElementById('resolutionSection');
        if (!resolutionSection) { return; }

        resolutionSection.querySelectorAll<HTMLInputElement>('input[type="text"], input[type="number"]')
            .forEach(input => {
                if (input.id !== 'methodFqn') { input.value = ''; }
            });

        resolutionSection.querySelectorAll<HTMLInputElement>('input[type="checkbox"]')
            .forEach(cb => { cb.checked = false; });

        // Always hide generic fields when resetting (checkbox is now unchecked)
        const genericFields = document.getElementById('genericFields');
        if (genericFields) { genericFields.style.display = 'none'; }
    }

    // Full reset called from Cancel button
    resetForm(): void {
        // Hide resolution section
        const resolutionSection = document.getElementById('resolutionSection');
        if (resolutionSection) { resolutionSection.style.display = 'none'; }

        // Clear methodFqn
        const methodFqn = document.getElementById('methodFqn') as HTMLInputElement;
        if (methodFqn) { methodFqn.value = ''; }

        // Reset all form fields inside resolution section
        this.resetFormFields();

        // Reset select defaults
        this.setInputValue('dbConfidence', 'MEDIUM');
        this.setInputValue('procOracleType', 'PROCEDURE');
        this.setInputValue('procDatabaseType', 'ORACLE');
        this.setInputValue('procConfidence', 'MEDIUM');
        this.setInputValue('shellType', 'BASH');
        this.setInputValue('shellConfidence', 'MEDIUM');
        this.setInputValue('shellRemotePort', '22');

        // Hide all category sections
        ['dbFields', 'procFields', 'shellFields', 'genericFields'].forEach(id => {
            const el = document.getElementById(id);
            if (el) { el.style.display = 'none'; }
        });

        // Show non-generic fields container
        const nonGenericFields = document.getElementById('nonGenericFields');
        if (nonGenericFields) { nonGenericFields.style.display = 'block'; }

        // Hide gap info
        const gapInfo = document.getElementById('gapInfo');
        if (gapInfo) { gapInfo.style.display = 'none'; }
    }

    private setInputValue(id: string, value: string): void {
        const el = document.getElementById(id) as HTMLInputElement | HTMLSelectElement | null;
        if (el) { el.value = value; }
    }

    private getInputValue(id: string): string {
        const el = document.getElementById(id) as HTMLInputElement | HTMLSelectElement | null;
        return el ? el.value : '';
    }
}

// Export for use in webview
if (typeof window !== 'undefined') {
    (window as any).FormManager = FormManager;
}
if (typeof window !== 'undefined') {
    (window as any).FormManager = FormManager;
}
