# Batch KG Gap Analyzer - Setup & Usage Guide

## 📋 Overview

This VS Code extension streamlines the process of identifying and resolving gaps in Spring Batch Knowledge Graph. It replaces the manual process of running Python scripts, analyzing logs, and manually writing YAML files.

## 🏗️ Project Structure

```
batch-kg-vscode-extension/
├── src/
│   ├── extension.ts              # Extension entry point
│   ├── gapAnalyzerPanel.ts       # Main webview UI controller
│   ├── neo4jService.ts           # Neo4j database queries
│   └── yamlGenerator.ts          # YAML file generation
├── package.json                  # Extension manifest & dependencies
├── tsconfig.json                 # TypeScript configuration
├── README.md                     # Documentation
└── .gitignore                    # Git ignore rules
```

## 🚀 Installation Steps

### 1. Install Dependencies

```bash
cd batch-kg-vscode-extension
npm install
```

### 2. Compile TypeScript

```bash
npm run compile
```

### 3. Run Extension in Development Mode

1. Open the `batch-kg-vscode-extension` folder in VS Code
2. Press `F5` to launch Extension Development Host
3. A new VS Code window will open with the extension loaded

### 4. Configure Settings

In VS Code settings (File → Preferences → Settings), search for "Batch KG" and configure:

- **Neo4j URI**: `bolt://localhost:7687` (or your Neo4j server)
- **Neo4j User**: `neo4j`
- **Neo4j Password**: Your Neo4j password
- **Neo4j Database**: `information_graph` (or your database name)
- **YAML Output Path**: `config/grey_area_resolution.yaml` (relative to workspace)

Alternatively, add to `.vscode/settings.json`:

```json
{
  "batchKg.neo4jUri": "bolt://localhost:7687",
  "batchKg.neo4jUser": "neo4j",
  "batchKg.neo4jPassword": "your-password",
  "batchKg.neo4jDatabase": "information_graph",
  "batchKg.yamlOutputPath": "config/grey_area_resolution.yaml"
}
```

## 📖 Usage

### Step 1: Open Gap Analyzer

1. Open Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`)
2. Type: "Batch KG: Open Gap Analyzer"
3. Press Enter

### Step 2: Test Connection

1. Click **Test Connection** button in the top-right
2. Verify you see "✅ Connected to Neo4j"

### Step 3: Browse Gaps

1. **Select Job**: Choose from dropdown (e.g., `customerProcessingJob`)
2. **Select Step**: Choose a step (e.g., `customerProcessingStep`)
3. **Select Category**: Choose gap category:
   - Database Operations
   - Procedure Calls
   - Shell Executions
4. **Select Gap**: Choose a specific gap to resolve

### Step 4: Fill Resolution Form

The form adapts based on gap category:

#### For Database Operations:

**Non-Generic:**
- Operation: SELECT, INSERT, UPDATE, DELETE, MERGE
- Table Name: e.g., `CUSTOMER_TABLE`
- Schema Name: e.g., `CUSTOMER_SCHEMA`
- Catalog Name (optional): e.g., `DB_CATALOG`

**Generic (Dynamic):**
- Check "Generic Resolution"
- Bean ID: e.g., `customerItemReader`
- Tasklet FQN (optional): e.g., `com.example.CustomerTasklet`
- Reader/Writer/Processor FQNs (optional)

#### For Procedure Calls:

**Non-Generic:**
- Procedure Name: e.g., `UPDATE_CUSTOMER_PROC`
- Schema Name: e.g., `CUSTOMER_SCHEMA`
- Package Name (optional): e.g., `PKG_CUSTOMER`
- Catalog Name (optional)

**Generic:**
- Bean ID
- Tasklet FQN (optional)

#### For Shell Executions:

**Non-Generic:**
- Script Name: e.g., `process_files.sh`
- Script Path: e.g., `/opt/scripts/`
- Command (optional): e.g., `process_files.sh --input data`
- Execution Type: Runtime.exec, ProcessBuilder, SSH, etc.

**Generic:**
- Bean ID
- Tasklet FQN (optional)

### Step 5: Save Resolution

1. Click **💾 Save Resolution**
2. YAML file is automatically generated/updated
3. File opens in editor for review

## 📝 Generated YAML Format

Example output:

```yaml
grey_area_resolutions:
  description: Manual resolutions for UNKNOWN/DYNAMIC/PARAMETERIZED operations
  generated_by: Batch KG Gap Analyzer VS Code Extension
  generated_at: '2026-03-24T12:00:00.000Z'
  steps:
    customerProcessingStep:
      db_operations:
        - method_fqn: com.example.dao.CustomerDAO.updateCustomer
          original: 'UPDATE: DYNAMIC_TABLE'
          resolution:
            generic: false
            operation: UPDATE
            table_name: CUSTOMER_TABLE
            schema_name: CUSTOMER_SCHEMA
      shell_executions:
        - method_fqn: com.example.tasklet.FileProcessorTasklet.execute
          original: 'Runtime.exec: UNKNOWN_SCRIPT'
          resolution:
            generic: false
            script_name: process_files.sh
            script_path: /opt/scripts/
            execution_type: Runtime.exec
```

## 🔧 Development

### Watch Mode (Auto-Compile)

```bash
npm run watch
```

### Debugging

1. Set breakpoints in TypeScript files
2. Press `F5` to start debugging
3. Breakpoints will hit in Extension Development Host

### Building VSIX Package

```bash
npm install -g vsce
vsce package
```

This creates a `.vsix` file that can be installed in VS Code.

## 📊 Features

### ✅ Implemented

- [x] Gap visualization with cascading dropdowns
- [x] Category-specific resolution forms
- [x] Generic vs. non-generic resolution support
- [x] Neo4j integration with connection testing
- [x] YAML generation with merge support
- [x] Auto-open generated files

### 🚧 Future Enhancements

- [ ] Bulk gap resolution (resolve multiple gaps at once)
- [ ] Gap statistics dashboard
- [ ] Validation rules for form fields
- [ ] Import existing YAML for editing
- [ ] Search/filter gaps by method or operation
- [ ] Export gap reports (CSV, JSON)

## 🐛 Troubleshooting

### Extension not activating

- Check that you compiled TypeScript: `npm run compile`
- Check for errors in VS Code Output panel (View → Output → Extension Host)

### Connection to Neo4j fails

- Verify Neo4j is running: `bolt://localhost:7687`
- Check credentials in VS Code settings
- Ensure database name is correct

### YAML file not created

- Check workspace folder is open
- Verify output path in settings
- Check file permissions
- Look for errors in VS Code Developer Tools (Help → Toggle Developer Tools)

## 📚 Related Files

This extension works with:

- **Python Scripts**: `trace_unknown_operations.py`, `quick_trace.py`, `list_unknown_steps.py`
- **Config Files**: `config/information_graph_config.yaml`
- **Enrichers**: `db_operation_enricher.py`, `procedure_call_enricher.py`, `shell_execution_enricher.py`

## 🤝 Contributing

1. Make changes in `src/` directory
2. Run `npm run compile` to build
3. Test with `F5` (Extension Development Host)
4. Submit pull request

## 📄 License

Internal use only - Batch KG project
