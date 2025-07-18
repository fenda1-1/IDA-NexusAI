# NexusAI - AI-Powered IDA Pro Plugin

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/fenda1-1/IDA-NexusAI)
[![IDA Pro](https://img.shields.io/badge/IDA%20Pro-7.x%2F8.x%2F9.x-green.svg)](https://www.hex-rays.com/products/ida/)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

NexusAI is a powerful IDA Pro plugin that integrates artificial intelligence to enhance reverse engineering workflows. It provides intelligent code analysis, automatic commenting, and interactive AI assistant capabilities directly within the IDA Pro environment.

## 🌐 Language / 语言

- **English**: You are reading the English documentation
- **中文**: [中文文档请点击这里](docs/zh-CN/README.md)

## 🚀 Quick Start

**New to NexusAI?** Check out our [Quick Start Guide](docs/en/QUICKSTART.md) to get up and running in 5 minutes!

## 🖥️ Installation

### Windows - Single-File Installer (Recommended)
Download and run the standalone installer - **no Python installation required!**

1. **Download** `NexusAI-Installer-GUI.exe` from [Releases](https://github.com/fenda1-1/IDA-NexusAI/releases)
2. **Double-click** to run (no console window will appear)
3. **Select language** (English/中文)
4. **Auto-detect or browse** for IDA Pro installation
5. **Choose Python** from detected installations (shows full paths)
6. **Complete installation** with real-time progress



### Linux/macOS - Python Script Installation
For Linux and macOS users, use the Python script installer:

```bash
# Clone the repository
git clone https://github.com/fenda1-1/IDA-NexusAI.git
cd IDA-NexusAI

# Run installer script
python install.py              # GUI mode (if tkinter available)
python install.py --cli        # CLI mode (recommended for Linux/macOS)
python install.py --lang zh    # Chinese interface
```

**Requirements for Linux/macOS:**
- Python 3.8+
- IDA Pro installation
- For GUI mode: tkinter (usually included with Python)

## ✨ Features

### 🤖 AI-Powered Analysis
- **Function Analysis**: Intelligent assembly function analysis with AI-generated explanations
- **Code Selection Analysis**: Analyze specific code segments with contextual understanding
- **Cross-Reference Analysis**: Automatic analysis of function call chains and data dependencies
- **Decompiler Integration**: Seamless integration with Hex-Rays decompiler for enhanced analysis

### 💬 Interactive AI Assistant
- **AIMCP (AI Model Control Protocol)**: Advanced conversational AI for complex reverse engineering tasks
- **Multi-Provider Support**: Compatible with OpenAI, Claude, and other AI providers
- **Streaming Responses**: Real-time AI responses with live text streaming
- **Session Management**: Persistent chat history and session management

### 🎯 Smart Commenting
- **Automatic Function Comments**: AI-generated function comments with hotkey support
- **Line Comments**: Intelligent comments for specific assembly lines
- **Repeatable Comments**: Consistent commenting across similar code patterns
- **Anterior Comments**: Context-aware pre-function comments

### 🔧 Advanced Features
- **Extension System**: Modular architecture supporting custom extensions
- **Graph Export**: Export call graphs and data flow diagrams for visualization
- **Multi-Language Support**: Chinese and English interface support
- **Configurable Hotkeys**: Customizable keyboard shortcuts for all functions

## 📋 System Requirements

### System Requirements
- **IDA Pro**: Version 7.x, 8.x, or 9.x
- **Python**: 3.8 or higher (bundled with IDA Pro)
- **Operating System**: Windows, macOS, or Linux

### Python Dependencies
The plugin requires several Python packages. Install using pip:

```bash
# Core dependencies
pip install openai>=1.0.0
pip install markdown>=3.4.0

# Optional dependencies for enhanced features
pip install httpx>=0.24.0  # For proxy support
```

**Important**: Ensure you're using the same Python environment that IDA Pro uses. You can check this by running the following in IDA Pro's Python console:
```python
import sys
print(sys.executable)
```

### Manual Installation (Advanced Users)
For developers or users who prefer manual installation:

```bash
# Clone the repository
git clone https://github.com/fenda1-1/IDA-NexusAI.git
cd IDA-NexusAI

# Manual installation steps
# 1. Copy NexusAI.py and NexusAI/ folder to IDA Pro plugins directory
# 2. Install Python dependencies
# 3. Configure settings
# See INSTALLATION_GUIDE.md for detailed steps
```

## 🎯 Usage

After installation:

1. **Start IDA Pro** and open any binary file
2. **Open Settings**: `Edit → NexusAI → Settings`
3. **Enter API Key**: Paste your API key
4. **Test Connection**: Click "Test Model" button
5. **Save Settings**: Click "OK"

### Basic Operations

#### Open NexusAI Window
Press `Ctrl+Shift+K` to open the NexusAI output window

#### Analyze a Function
1. **Navigate** to any function in IDA Pro
2. **Right-click** → "Analyze Function (AI)" or press `Ctrl+Shift+A`
3. **View Results** in the NexusAI output window

#### Ask Questions
1. **Type** your question in the input field at the bottom
2. **Press Enter** to send
3. **Get AI responses** in real-time

## ⚙️ Configuration

### Initial Setup

1. **Get API Key**:
   - **OpenAI**: Visit [platform.openai.com](https://platform.openai.com/api-keys)
   - **Claude**: Visit [console.anthropic.com](https://console.anthropic.com/)

2. **Configure NexusAI**:
   - Open IDA Pro and load any binary
   - Go to `Edit → NexusAI → Settings`
   - Enter your API key and select model
   - Test the connection and save

### Advanced Configuration

The plugin supports extensive customization through the settings dialog:
- **AI Provider**: Choose between OpenAI, Claude, or custom providers
- **Model Selection**: Select specific models (GPT-4, Claude-3, etc.)
- **Analysis Depth**: Configure how deep the AI analysis should go
- **Custom Prompts**: Modify AI behavior with custom prompts
- **Hotkeys**: Customize keyboard shortcuts
- **Language**: Switch between English and Chinese interface

## 🔥 Essential Hotkeys

| Hotkey | Action |
|--------|--------|
| `Ctrl+Shift+K` | Toggle NexusAI window |
| `Ctrl+Shift+A` | Analyze current function |
| `Ctrl+Shift+S` | Add AI comment to line |
| `Ctrl+Shift+D` | Add repeatable comment |
| `Ctrl+Shift+W` | Add anterior comment |

## 🛠️ Building from Source

To build the installer:

```bash
# Build GUI installer
python build_gui.py
```

## 📞 Support

- **Documentation**: Complete guides in `docs/` directory
- **Issues**: [GitHub Issues](https://github.com/fenda1-1/IDA-NexusAI/issues)
- **Discussions**: [GitHub Discussions](https://github.com/fenda1-1/IDA-NexusAI/discussions)

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

**Transform your reverse engineering workflow with AI-powered analysis! 🚀**
