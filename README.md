# NexusAI - AI-Powered IDA Pro Plugin

🚀 **Advanced AI assistant for reverse engineering with IDA Pro**

## ✨ Features

- **AI-Powered Analysis**: Leverage OpenAI's GPT models for code analysis
- **Multi-Language Support**: Full English and Chinese interface
- **Smart Integration**: Seamless integration with IDA Pro workflow
- **Advanced Capabilities**: Function analysis, code explanation, vulnerability detection

## 🌐 Language / 语言

- **English**: You are reading the English documentation
- **中文**: [中文文档请点击这里](docs/zh-CN/README.md)

## 🖥️ Installation

### Windows - Single-File Installer (Recommended)
Download and run the standalone installer - **no Python installation required!**

1. **Download** `NexusAI-Installer-GUI.exe` from [Releases](https://github.com/fenda1-1/IDA-NexusAI/releases)
2. **Double-click** to run (no console window will appear)
3. **Select language** (English/中文)
4. **Auto-detect or browse** for IDA Pro installation
5. **Choose Python** from detected installations (shows full paths)
6. **Complete installation** with real-time progress

**✨ Key Features:**
- **Single file** - Everything embedded, no additional files needed
- **No console window** - Clean GUI-only experience
- **Smart detection** - Automatically finds IDA Pro and Python installations
- **Multi-language** - Full English and Chinese support
- **Zero dependencies** - No Python or other software required

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

### Smart Detection Features:

#### IDA Pro Detection
- **Multi-drive scanning**: Automatically searches C:, D:, E:, F: drives
- **Deep search**: Up to 2 directory levels for comprehensive coverage
- **Pattern recognition**: Identifies IDA Pro by executable files and directory structure
- **Validation**: Verifies installations before presenting options

#### Python Detection
- **IDA Pro Python**: Automatically detects Python in selected IDA Pro directory (python/, python312/, etc.)
- **System Python**: Detects current Python installation
- **Anaconda/Miniconda**: Locates conda environments and base installations
- **Registry search**: Windows registry-based detection for official Python installers
- **Path scanning**: Searches common installation directories across all drives
- **Full path display**: Shows complete paths for informed selection
- **Priority ordering**: IDA Pro Python shown first as the recommended option

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

1. **Start IDA Pro**
2. **Open any binary file**
3. **Access NexusAI**:
   - Menu: `Edit → NexusAI`
   - Hotkey: `Ctrl+Shift+K`
4. **Configure API key** in settings
5. **Start analyzing** with AI assistance

## 🔧 Configuration

### API Setup
1. Get OpenAI API key from [OpenAI Platform](https://platform.openai.com/)
2. In IDA Pro: `Edit → NexusAI → Settings`
3. Enter your API key
4. Select preferred model (GPT-4 recommended)

### Features Overview
- **Function Analysis**: AI-powered function understanding
- **Code Explanation**: Natural language code descriptions
- **Vulnerability Detection**: Security issue identification
- **Pattern Recognition**: Malware and exploit pattern detection
- **Documentation**: Automatic code documentation generation

## 📋 System Requirements

- **IDA Pro**: Version 7.x, 8.x, or 9.x
- **Operating System**: Windows 10/11 (64-bit)
- **Python**: 3.8+ (automatically detected and configured)
- **Internet**: Required for AI model access
- **API Key**: OpenAI API access

## 🚀 Advanced Features

### Multi-Python Support
The installer detects and displays multiple Python installations:
- System Python installations
- IDA Pro bundled Python
- Anaconda/Miniconda environments
- Custom Python installations

### Smart Path Display
Python options show full paths for informed selection, with IDA Pro Python prioritized:
```
IDA Pro Python 3.12.5 (python312)
    Path: E:\Program\IDApro9.1\python312\python.exe

Current System Python 3.12.3
    Path: D:\Python\python.exe

Python 3.12.7 (anaconda3)
    Path: D:\ProgramData\anaconda3\python.exe

Python 3.12.7 (anaconda3)
    Path: E:\ProgramData\anaconda3\python.exe
```

### Development Mode
For plugin developers:
- Symbolic link installation
- Real-time updates without reinstalling
- Debug-friendly setup

## 🛠️ Building from Source

To build the installer:

```bash
# Build GUI installer
python build_gui.py

# This creates:
# - NexusAI-Installer-GUI.exe (single file, no console)
```

## 📞 Support

- **Documentation**: Complete guides in `docs/` directory
- **Issues**: [GitHub Issues](https://github.com/fenda1-1/IDA-NexusAI/issues)
- **Discussions**: [GitHub Discussions](https://github.com/fenda1-1/IDA-NexusAI/discussions)

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

**Transform your reverse engineering workflow with AI-powered analysis! 🚀**
