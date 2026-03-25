# Settings Files Explanation

## Which Settings Files Do You Need?

You need **2 settings files** (not 3):

### 1. Extension Development Workspace
**File**: `batch-kg-vscode-extension/.vscode/settings.json`
**Purpose**: Optional - for testing the extension in its own development workspace
**When**: If you want to test the extension without opening the Batch_KG project

### 2. Target Workspace (Batch_KG)
**File**: `Batch_KG/.vscode/settings.json` ✅ **MAIN ONE TO USE**
**Purpose**: Configuration for using the extension in your actual work environment
**When**: This is where you'll actually use the extension daily

## ❌ Deleted Files
- `Batch_KG/.vscode/batch-kg-extension-settings.json` - REMOVED (was redundant)

## How Settings Work

When you run the extension:
1. Press **F5** in `batch-kg-vscode-extension` → Opens Extension Development Host
2. In the new window, open the **Batch_KG** folder (`File → Open Folder`)
3. Extension reads settings from **Batch_KG/.vscode/settings.json**
4. Run: **Ctrl+Shift+P** → "Batch KG: Open Gap Analyzer"

## Current Configuration (Batch_KG/.vscode/settings.json)

```json
{
  "batchKg.neo4jUri": "bolt://localhost:7687",
  "batchKg.neo4jUser": "neo4j",
  "batchKg.neo4jPassword": "Rohit@123",
  "batchKg.neo4jDatabase": "informationgraph",
  "batchKg.yamlOutputPath": "config/grey_area_resolution.yaml"
}
```

## To Change Settings

### Option 1: Edit File Directly
Edit `Batch_KG/.vscode/settings.json`

### Option 2: Via VS Code UI
1. File → Preferences → Settings
2. Search: "Batch KG"
3. Update values in the UI

### Option 3: Via Extension Error Message
1. If you see authentication error
2. Click "Open Settings" button
3. VS Code opens settings filtered to "batchKg"
