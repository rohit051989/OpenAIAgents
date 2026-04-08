# Settings Files Explanation

## Which Settings Files Do You Need?

You need **2 settings files** (not 3):

### 1. Extension Development Workspace
**File**: `batch-ig-vscode-extension/.vscode/settings.json`
**Purpose**: Optional - for testing the extension in its own development workspace
**When**: If you want to test the extension without opening the Batch_IG project

### 2. Target Workspace (Batch_IG)
**File**: `Batch_IG/.vscode/settings.json` ✅ **MAIN ONE TO USE**
**Purpose**: Configuration for using the extension in your actual work environment
**When**: This is where you'll actually use the extension daily

## ❌ Deleted Files
- `Batch_IG/.vscode/batch-ig-extension-settings.json` - REMOVED (was redundant)

## How Settings Work

When you run the extension:
1. Press **F5** in `batch-ig-vscode-extension` → Opens Extension Development Host
2. In the new window, open the **Batch_IG** folder (`File → Open Folder`)
3. Extension reads settings from **Batch_IG/.vscode/settings.json**
4. Run: **Ctrl+Shift+P** → "Batch IG: Open Gap Analyzer"

## Current Configuration (Batch_IG/.vscode/settings.json)

```json
{
  "batchIg.neo4jUri": "bolt://localhost:7687",
  "batchIg.neo4jUser": "neo4j",
  "batchIg.neo4jPassword": "Rohit@123",
  "batchIg.neo4jDatabase": "informationgraph",
  "batchIg.yamlOutputPath": "config/grey_area_resolution.yaml"
}
```

## To Change Settings

### Option 1: Edit File Directly
Edit `Batch_IG/.vscode/settings.json`

### Option 2: Via VS Code UI
1. File → Preferences → Settings
2. Search: "Batch IG"
3. Update values in the UI

### Option 3: Via Extension Error Message
1. If you see authentication error
2. Click "Open Settings" button
3. VS Code opens settings filtered to "batchIg"
