# NexusAI Project Overview

This document provides a comprehensive overview of the NexusAI project structure and documentation.

## 📁 Project Structure

```
NexusAI/
├── 📄 Core Plugin Files
│   ├── NexusAI.py                    # Main plugin entry point
│   └── NexusAI/                      # Plugin package directory
│       ├── __init__.py               # Package initialization
│       ├── Core/                     # Core functionality
│       ├── AIService/                # AI service providers
│       ├── UI/                       # User interface components
│       ├── Utils/                    # Utility modules
│       ├── Config/                   # Configuration management
│       └── extensions/               # Plugin extensions
│
├── 📋 Dependencies & Installation
│   ├── requirements.txt              # Python dependencies
│   ├── install.py                    # Unified cross-platform installer with language selection
│   ├── install.bat                   # Windows batch wrapper
│   └── install.sh                    # Linux/macOS shell wrapper
│
├── 📚 Documentation (docs/)
│   ├── en/                           # English Documentation
│   │   ├── QUICKSTART.md            # Quick start guide
│   │   ├── CONFIGURATION.md         # Configuration guide
│   │   ├── CONTRIBUTING.md          # Contributing guidelines
│   │   └── CHANGELOG.md             # Version history
│   └── zh-CN/                       # Chinese Documentation (中文文档)
│       ├── README.md                # 主要项目文档
│       ├── QUICKSTART.md            # 快速开始指南
│       ├── CONFIGURATION.md         # 配置指南
│       ├── CONTRIBUTING.md          # 贡献指南
│       └── CHANGELOG.md             # 版本历史
│
└── 📄 Project Meta Files
    ├── LICENSE                       # MIT license
    └── PROJECT_OVERVIEW.md          # This file
```

## 📖 Documentation Guide

### For Users

#### Getting Started
1. **[README.md](README.md)** / **[中文README](docs/zh-CN/README.md)** - Start here for project overview
2. **[Quick Start](docs/en/QUICKSTART.md)** / **[快速开始](docs/zh-CN/QUICKSTART.md)** - 5-minute setup guide
3. **[Configuration](docs/en/CONFIGURATION.md)** / **[配置指南](docs/zh-CN/CONFIGURATION.md)** - Detailed configuration

#### Installation Options
- **Interactive**: Run `install.py` for language selection and guided installation
- **Command Line**: Use `install.py --lang en` or `install.py --lang zh` for direct language selection
- **Platform Scripts**: Use `install.bat` (Windows) or `./install.sh` (Linux/macOS)
- **Development**: Use `--dev` flag for symbolic links

### For Developers

#### Contributing
1. **[Contributing Guide](docs/en/CONTRIBUTING.md)** / **[贡献指南](docs/zh-CN/CONTRIBUTING.md)** - Development guidelines
2. **[Changelog](docs/en/CHANGELOG.md)** / **[更新日志](docs/zh-CN/CHANGELOG.md)** - Version history
3. **[LICENSE](LICENSE)** - MIT license terms

#### Code Structure
- **Core/**: Main plugin logic and controllers
- **AIService/**: AI provider implementations
- **UI/**: PyQt5 user interface components
- **Utils/**: Helper functions and utilities
- **Config/**: Configuration management
- **extensions/**: Modular extension system

## 🚀 Quick Installation

### English Users
```bash
git clone https://github.com/your-repo/NexusAI.git
cd NexusAI
python install.py
```

### 中文用户
```bash
git clone https://github.com/your-repo/NexusAI.git
cd NexusAI
python install.py --lang zh
# 或使用交互式安装
python install.py
# 或使用平台脚本
# Windows: install.bat
# Linux/macOS: ./install.sh
```

## 🔧 Key Features

### AI-Powered Analysis
- Function analysis with streaming responses
- Code selection analysis
- Interactive AI assistant (AIMCP)
- Smart commenting system

### Multi-Provider Support
- OpenAI (GPT-4, GPT-3.5-turbo, etc.)
- Claude (Anthropic)
- Custom API endpoints
- Local AI models

### User Interface
- Modern Qt5-based output window
- Real-time streaming text display
- Markdown rendering support
- Multi-language interface (EN/CN)

### Extension System
- Graph export extension
- Flattening detection extension
- Modular architecture for custom extensions

## 📋 System Requirements

- **IDA Pro**: 7.x, 8.x, or 9.x
- **Python**: 3.8+ (bundled with IDA Pro)
- **OS**: Windows, macOS, Linux
- **Dependencies**: OpenAI SDK, PyQt5, Markdown

## 🔑 Configuration

### Required Setup
1. Obtain API key from AI provider (OpenAI, Claude, etc.)
2. Configure in NexusAI settings dialog
3. Test connection and adjust parameters

### Optional Configuration
- Proxy settings for enterprise environments
- Custom prompts and templates
- Hotkey customization
- Analysis depth and parameters

## 🤝 Contributing

### Ways to Contribute
- **Bug Reports**: Use GitHub Issues
- **Feature Requests**: Use GitHub Discussions
- **Code Contributions**: Submit Pull Requests
- **Documentation**: Improve guides and examples
- **Translations**: Help with localization

### Development Workflow
1. Fork the repository
2. Create feature branch
3. Make changes and test
4. Submit pull request
5. Code review and merge

## 📞 Support

### Getting Help
- **Documentation**: Check relevant guide files
- **Issues**: [GitHub Issues](https://github.com/your-repo/NexusAI/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-repo/NexusAI/discussions)
- **Wiki**: [Project Wiki](https://github.com/your-repo/NexusAI/wiki)

### Common Issues
- **Installation**: Check Python version and dependencies
- **API Errors**: Verify API keys and network connectivity
- **UI Problems**: Ensure PyQt5 compatibility
- **Performance**: Adjust timeout and analysis depth settings

## 🌟 Project Goals

### Current Version (1.0.0)
- ✅ Core AI analysis functionality
- ✅ Multi-provider support
- ✅ Modern user interface
- ✅ Extension system
- ✅ Comprehensive documentation

### Future Roadmap
- 🔄 Additional AI providers
- 🔄 Enhanced extension ecosystem
- 🔄 Advanced analysis features
- 🔄 Performance optimizations
- 🔄 Community contributions

## 📈 Project Statistics

- **Language**: Python
- **Framework**: IDA Pro SDK, PyQt5
- **AI Integration**: OpenAI, Claude, Custom APIs
- **Platforms**: Cross-platform (Windows, macOS, Linux)
- **License**: MIT (Open Source)
- **Documentation**: Bilingual (English/Chinese)

---

**Thank you for your interest in NexusAI! / 感谢您对NexusAI的关注！**

For the latest updates and information, please visit our [GitHub repository](https://github.com/your-repo/NexusAI).
