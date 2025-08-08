# OpenAI Agents Learning Project

Welcome to the OpenAI Agents Learning Project! This repository is designed for anyone who wants to learn about OpenAI Agents, starting from the basics and progressing to advanced topics.

## Project Overview
This project provides hands-on examples and code to help you understand and implement OpenAI Agents. It is suitable for beginners as well as those looking to deepen their knowledge.

## Getting Started

### 1. Obtain an OpenAI API Key
To use OpenAI Agents, you need an OpenAI API key. If you don't have one:
- Sign up at [OpenAI](https://platform.openai.com/signup)
- Go to your [API Keys page](https://platform.openai.com/api-keys) and create a new key

### 2. Set the OpenAI API Key as an Environment Variable

#### Windows (PowerShell)
```powershell
$env:OPENAI_API_KEY="your-api-key-here"
```
Or to set it permanently (for your user):
```powershell
[System.Environment]::SetEnvironmentVariable("OPENAI_API_KEY", "your-api-key-here", "User")
```

#### Linux / macOS (bash/zsh)
```bash
export OPENAI_API_KEY="your-api-key-here"
```
To make it permanent, add the above line to your `~/.bashrc`, `~/.zshrc`, or equivalent shell profile file.

### 3. Set Up a Python Virtual Environment

#### Windows
```powershell
python -m venv venv
.\venv\Scripts\Activate
```

#### Linux / macOS
```bash
python3 -m venv venv
source venv/bin/activate
```

### 4. Install Dependencies
Install the required Python packages using `requirements.txt`:
```bash
pip install -r requirements.txt
```

### 5. Run the Example
Navigate to the `basic` directory and run the HelloWorld example:
```bash
python HelloWorld.py
```

## Project Structure
- `basic/HelloWorld.py`: A simple example to get started with OpenAI Agents.
- `requirements.txt`: List of required Python packages.

## Contributing
Feel free to contribute by submitting issues or pull requests!

## License
This project is for educational purposes.
