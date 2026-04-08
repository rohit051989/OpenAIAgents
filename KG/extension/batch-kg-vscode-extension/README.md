# Batch IG Gap Analyzer - VS Code Extension

A Visual Studio Code extension for analyzing and resolving gaps in Spring Batch Information Graph.

## Features

- **Gap Visualization**: Browse Jobs → Steps → Categories → Specific Gaps
- **Gap Resolution**: Fill in missing information with category-specific forms
- **YAML Generation**: Automatically generate YAML configuration files

## Installation

1. Clone this repository
2. Run `npm install`
3. Run `npm run compile`
4. Press F5 to open Extension Development Host

## Configuration

Set the following in VS Code settings:

- `batchIg.neo4jUri`: Neo4j database URI (default: bolt://localhost:7687)
- `batchIg.neo4jUser`: Neo4j username
- `batchIg.neo4jPassword`: Neo4j password
- `batchIg.neo4jDatabase`: Database name (default: information_graph)
- `batchIg.yamlOutputPath`: Output path for YAML files

## Usage

1. Open Command Palette (Ctrl+Shift+P / Cmd+Shift+P)
2. Run command: "Batch IG: Open Gap Analyzer"
3. Select Job → Step → Category → Gap
4. Fill in resolution details
5. Click Save to generate YAML

## Development

```bash
npm install
npm run compile
npm run watch  # For continuous compilation
```

## Building

```bash
npm run vscode:prepublish
vsce package
```
