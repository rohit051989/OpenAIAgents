# Batch KG Gap Analyzer - Installation Script
# Run this script from PowerShell to set up the extension

Write-Host "================================" -ForegroundColor Cyan
Write-Host "Batch KG Gap Analyzer Setup" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

# Check if Node.js is installed
Write-Host "Checking Node.js installation..." -ForegroundColor Yellow
$nodeVersion = node --version 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Node.js is not installed!" -ForegroundColor Red
    Write-Host "Please install Node.js 18.x or higher from: https://nodejs.org/" -ForegroundColor Red
    exit 1
}
Write-Host "✅ Node.js version: $nodeVersion" -ForegroundColor Green
Write-Host ""

# Check if npm is installed
Write-Host "Checking npm installation..." -ForegroundColor Yellow
$npmVersion = npm --version 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ npm is not installed!" -ForegroundColor Red
    exit 1
}
Write-Host "✅ npm version: $npmVersion" -ForegroundColor Green
Write-Host ""

# Navigate to extension directory
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptPath

Write-Host "Installing dependencies..." -ForegroundColor Yellow
npm install
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ npm install failed!" -ForegroundColor Red
    exit 1
}
Write-Host "✅ Dependencies installed" -ForegroundColor Green
Write-Host ""

Write-Host "Compiling TypeScript..." -ForegroundColor Yellow
npm run compile
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Compilation failed!" -ForegroundColor Red
    exit 1
}
Write-Host "✅ TypeScript compiled" -ForegroundColor Green
Write-Host ""

# Create settings file if it doesn't exist
$settingsPath = ".vscode\settings.json"
if (-not (Test-Path $settingsPath)) {
    Write-Host "Creating settings file..." -ForegroundColor Yellow
    Copy-Item ".vscode\settings.json.example" $settingsPath
    Write-Host "✅ Settings file created: $settingsPath" -ForegroundColor Green
    Write-Host "⚠️  Please update Neo4j credentials in $settingsPath" -ForegroundColor Yellow
} else {
    Write-Host "ℹ️  Settings file already exists: $settingsPath" -ForegroundColor Cyan
}
Write-Host ""

Write-Host "================================" -ForegroundColor Cyan
Write-Host "✅ Setup Complete!" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Open this folder in VS Code" -ForegroundColor White
Write-Host "2. Update Neo4j credentials in .vscode\settings.json" -ForegroundColor White
Write-Host "3. Press F5 to launch Extension Development Host" -ForegroundColor White
Write-Host "4. In the new window, press Ctrl+Shift+P" -ForegroundColor White
Write-Host "5. Type 'Batch KG: Open Gap Analyzer'" -ForegroundColor White
Write-Host ""
Write-Host "For more details, see QUICK_START.md" -ForegroundColor Cyan
Write-Host ""
