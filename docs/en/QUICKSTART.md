# NexusAI Quick Start Guide

Get up and running with NexusAI in 5 minutes! 🚀

## 📦 Quick Installation

### Option 1: Automated Installation (Recommended)
```bash
# Download and run the installer
git clone https://github.com/your-repo/NexusAI.git
cd NexusAI
python install.py
```

### Option 2: Manual Installation
```bash
# Install dependencies
pip install openai>=1.0.0 markdown>=3.4.0

# Copy plugin files to IDA Pro plugins directory:
# 1. Copy NexusAI.py to plugins directory
# 2. Copy entire NexusAI/ folder to plugins directory
# Windows: %IDADIR%\plugins\
# macOS: $IDADIR/plugins/
# Linux: $IDADIR/plugins/
```

## ⚡ First Time Setup

### 1. Get Your API Key
- **OpenAI**: Visit [platform.openai.com](https://platform.openai.com/api-keys)
- **Claude**: Visit [console.anthropic.com](https://console.anthropic.com/)

### 2. Configure NexusAI
1. **Start IDA Pro** and open any binary file
2. **Open Settings**: `Edit → NexusAI → Settings`
3. **Enter API Key**: Paste your API key
4. **Test Connection**: Click "Test Model" button
5. **Save Settings**: Click "OK"

### 3. Open Output Window
Press `Ctrl+Shift+K` to open the NexusAI output window

## 🎯 Basic Usage

### Analyze a Function
1. **Navigate** to any function in IDA Pro
2. **Right-click** → "Analyze Function (AI)" or press `Ctrl+Shift+A`
3. **View Results** in the NexusAI output window

### Ask Questions
1. **Type** your question in the input field at the bottom
2. **Press Enter** to send
3. **Get AI responses** in real-time

### Add Smart Comments
1. **Position cursor** on any line
2. **Press `Ctrl+Shift+S`** for line comments
3. **Press `Ctrl+Shift+A`** for function comments

## 🔥 Essential Hotkeys

| Hotkey | Action |
|--------|--------|
| `Ctrl+Shift+K` | Toggle NexusAI window |
| `Ctrl+Shift+A` | Analyze current function |
| `Ctrl+Shift+S` | Add AI comment to line |
| `Ctrl+Shift+D` | Add repeatable comment |
| `Ctrl+Shift+W` | Add anterior comment |

## 💡 Pro Tips

### 1. Adjust Analysis Depth
- **Settings → Analysis → Depth**: Set to 2-3 for detailed analysis
- Higher depth = more context but slower analysis

### 2. Use Custom Prompts
- **Settings → Prompts**: Customize AI behavior
- Example: "Focus on security vulnerabilities"

### 3. Interactive Analysis
- Ask follow-up questions about functions
- Request specific analysis types
- Get explanations for complex algorithms

### 4. Export Analysis
- **Right-click** in output window → "Export"
- Save analysis results for documentation

## 🛠️ Common Use Cases

### Malware Analysis
```
Analyze this function for malicious behavior and potential indicators of compromise
```

### Vulnerability Research
```
Check this function for buffer overflows, integer overflows, and other security issues
```

### Algorithm Identification
```
What algorithm is implemented in this function? Explain the logic flow.
```

### Code Understanding
```
Explain what this function does in simple terms and identify its purpose
```

## 🚨 Troubleshooting

### Plugin Not Loading
1. Check IDA Pro's Python console for errors
2. Verify all dependencies are installed
3. Ensure files are in correct directory

### API Errors
1. Verify API key is correct
2. Check internet connection
3. Configure proxy if needed

### No AI Response
1. Check API key has credits
2. Verify model name is correct
3. Try a different AI model

### UI Issues
1. Restart IDA Pro
2. Check PyQt5 installation
3. Reset configuration file

## 📚 Next Steps

### Learn More
- Read the full [README.md](README.md)
- Check [CONFIGURATION.md](CONFIGURATION.md) for advanced settings
- Browse [CONTRIBUTING.md](CONTRIBUTING.md) to contribute

### Advanced Features
- **AIMCP**: Enable for multi-turn conversations
- **Extensions**: Try graph export and flattening detection
- **Custom Providers**: Configure local AI models

### Community
- **Issues**: [GitHub Issues](https://github.com/fenda1-1/IDA-NexusAI/issues)
- **Discussions**: [GitHub Discussions](https://github.com/fenda1-1/IDA-NexusAI/discussions)
- **Wiki**: [Project Wiki](https://github.com/fenda1-1/IDA-NexusAI/wiki)

## 🎉 Example Workflow

### Analyzing a Suspicious Function
1. **Open** malware sample in IDA Pro
2. **Navigate** to suspicious function
3. **Press `Ctrl+Shift+A`** to analyze
4. **Ask**: "Is this function malicious? What does it do?"
5. **Follow up**: "What are the key indicators?"
6. **Add comment**: Press `Ctrl+Shift+S` to save analysis

### Understanding Complex Algorithm
1. **Select** algorithm code block
2. **Right-click** → "Analyze Selection (AI)"
3. **Ask**: "What algorithm is this? Explain step by step."
4. **Request**: "Show me the mathematical formula"
5. **Document**: Export analysis for team review

---

**Happy Reverse Engineering! 🔍✨**

Need help? Check the [full documentation](README.md) or [open an issue](https://github.com/fenda1-1/IDA-NexusAI/issues).
