# Quick Start Commands

## Initial Setup

```powershell
# Navigate to extension directory
cd d:\Iris\practice\GenAI\code\batch-kg-vscode-extension

# Install dependencies
npm install

# Compile TypeScript
npm run compile
```

## Development

```powershell
# Watch mode (auto-compile on save)
npm run watch

# In VS Code: Press F5 to launch Extension Development Host
```

## Configuration (First Time)

### Option 1: Extension Development Workspace Settings
Add to the **extension project** settings (`.vscode/settings.json`):

```json
{
  "batchKg.neo4jUri": "bolt://localhost:7687",
  "batchKg.neo4jUser": "neo4j",
  "batchKg.neo4jPassword": "your-password-here",
  "batchKg.neo4jDatabase": "informationgraph",
  "batchKg.yamlOutputPath": "config/grey_area_resolution.yaml"
}
```

### Option 2: Target Workspace Settings (Recommended)
Add to the **Batch_KG project** settings (`Batch_KG/.vscode/settings.json`):
- This is where you'll actually use the extension
- Settings are already configured with your Neo4j credentials
- Open the Batch_KG folder in the Extension Development Host window

## Usage in VS Code

1. **Ctrl+Shift+P** → "Batch KG: Open Gap Analyzer"
2. Click "Test Connection"
3. Select: Job → Step → Category → Gap
4. Fill form and click "Save Resolution"

## Building for Distribution

```powershell
# Install VSCE (first time only)
npm install -g vsce

# Package extension
vsce package

# This creates: batch-kg-gap-analyzer-0.1.0.vsix
```

## Install Packaged Extension

```powershell
# In VS Code:
# Extensions → ... → Install from VSIX
# Select the .vsix file
```
