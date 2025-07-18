# NexusAI - 基于AI的IDA Pro逆向工程插件

[![版本](https://img.shields.io/badge/版本-1.0.0-blue.svg)](https://github.com/fenda1-1/IDA-NexusAI)
[![IDA Pro](https://img.shields.io/badge/IDA%20Pro-7.x%2F8.x%2F9.x-green.svg)](https://www.hex-rays.com/products/ida/)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![许可证](https://img.shields.io/badge/许可证-MIT-green.svg)](LICENSE)

NexusAI 是一个强大的 IDA Pro 插件，集成了人工智能来增强逆向工程工作流程。它在 IDA Pro 环境中直接提供智能代码分析、自动注释和交互式AI助手功能。

## 🌐 Language / 语言

- **English**: [English Documentation](../../README.md)
- **中文**: 您正在阅读中文文档

## 🚀 快速开始

**初次使用 NexusAI？** 查看我们的 [快速开始指南](QUICKSTART.md) 在5分钟内开始使用！

## 🖥️ 安装方法

### Windows - 单文件安装程序（推荐）
下载并运行预构建的安装程序 - **无需安装Python！**

1. **下载** `NexusAI-Installer-GUI.exe` 从 [Releases](https://github.com/fenda1-1/IDA-NexusAI/releases)
2. **双击运行**（不会显示控制台窗口）
3. **选择语言**（中文/English）
4. **自动检测或浏览** IDA Pro 安装目录
5. **选择Python** 从检测到的安装中（显示完整路径）
6. **完成安装** 实时进度显示

**✨ 主要特性：**
- **单文件** - 所有文件已内嵌，无需其他文件
- **无控制台窗口** - 纯图形界面体验
- **智能检测** - 自动查找IDA Pro和Python安装
- **多语言** - 完整的中文和英文支持
- **零依赖** - 无需Python或其他软件

### Linux/macOS - Python脚本安装
对于Linux和macOS用户，使用Python脚本安装程序：

```bash
# 克隆仓库
git clone https://github.com/fenda1-1/IDA-NexusAI.git
cd IDA-NexusAI

# 运行安装脚本
python install.py              # GUI模式（如果tkinter可用）
python install.py --cli        # CLI模式（推荐用于Linux/macOS）
python install.py --lang zh    # 中文界面
```

**Linux/macOS 要求：**
- Python 3.8+
- IDA Pro 安装
- GUI模式需要：tkinter（通常包含在Python中）

### 安装程序功能特性：
- **交互式语言选择**（中文/英文）
- **可视化IDA Pro目录选择**，支持自动检测
- **Python安装检测**，包括IDA Pro自带的Python
- **实时安装进度**，详细日志记录
- **逐步指导**完成整个安装过程
- **无外部依赖**（Windows独立可执行文件）

## ✨ 功能特性

### 🤖 AI驱动的分析
- **函数分析**：使用AI生成解释的智能汇编函数分析
- **代码选择分析**：分析特定代码段并提供上下文理解
- **交叉引用分析**：自动分析函数调用链和数据依赖关系
- **反编译器集成**：与Hex-Rays反编译器无缝集成以增强分析

### 💬 交互式AI助手
- **AIMCP（AI模型控制协议）**：用于复杂逆向工程任务的高级对话AI
- **多提供商支持**：兼容OpenAI、Claude和其他AI提供商
- **流式响应**：实时AI响应与实时文本流
- **会话管理**：持久化聊天历史和会话管理

### 🎯 智能注释
- **自动函数注释**：支持热键的AI生成函数注释
- **行注释**：针对特定汇编行的智能注释
- **可重复注释**：在相似代码模式中保持一致的注释
- **前置注释**：上下文感知的函数前注释

### 🔧 高级功能
- **扩展系统**：支持自定义扩展的模块化架构
- **图形导出**：导出调用图和数据流图进行可视化
- **多语言支持**：中文和英文界面支持
- **可配置热键**：所有功能的可自定义键盘快捷键

## 📋 系统要求

### 系统需求
- **IDA Pro**：版本 7.x、8.x 或 9.x
- **Python**：3.8 或更高版本（IDA Pro 自带）
- **操作系统**：Windows、macOS 或 Linux

### Python依赖
插件需要几个Python包。使用pip安装：

```bash
# 核心依赖
pip install openai>=1.0.0
pip install markdown>=3.4.0

# 增强功能的可选依赖
pip install httpx>=0.24.0  # 用于代理支持
```

**重要**：确保您使用的是IDA Pro使用的相同Python环境。您可以在IDA Pro的Python控制台中运行以下命令来检查：
```python
import sys
print(sys.executable)
```

## 🚀 安装

### 方法1：自动安装（推荐）

1. **下载插件**
   ```bash
   git clone https://github.com/fenda1-1/IDA-NexusAI.git
   cd IDA-NexusAI
   ```

2. **运行安装脚本**
   ```bash
   # Windows - 使用GUI安装程序
   NexusAI-Installer-GUI.exe

   # Linux/macOS - 使用Python脚本
   python install.py --cli

   # 或者图形界面（如果支持）
   python install.py
   ```

### 方法2：手动安装

1. **安装依赖**
   ```bash
   # 使用IDA Pro使用的Python版本
   python -m pip install -r requirements.txt
   ```

2. **复制插件文件**
   - 将 `NexusAI.py` 复制到您的IDA Pro插件目录：
     - **Windows**：`%IDADIR%\plugins\`
     - **macOS**：`$IDADIR/plugins/`
     - **Linux**：`$IDADIR/plugins/`
   
   - 将整个 `NexusAI/` 文件夹复制到同一插件目录

3. **重启IDA Pro**

## ⚙️ 配置

### 初始设置

1. **启动IDA Pro** 并打开任何二进制文件
2. **访问设置**：转到 `编辑 → NexusAI → 设置` 或使用 `Ctrl+Shift+K` 打开输出窗口
3. **配置API设置**：
   - **API密钥**：输入您的OpenAI API密钥
   - **基础URL**：设置API端点（默认：`https://api.openai.com/v1`）
   - **模型**：选择您首选的AI模型（例如：`gpt-4`、`gpt-3.5-turbo`）
   - **代理**：如果需要，配置代理设置

### 配置文件

插件在 `NexusAI/Config/NexusAI.json` 创建配置文件。主要设置包括：

```json
{
  "openai": {
    "api_key": "your-api-key-here",
    "base_url": "https://api.openai.com/v1",
    "model": "gpt-4"
  },
  "language": "zh_CN",
  "analysis_depth": 2,
  "auto_open": true,
  "shortcuts": {
    "toggle_output": "Ctrl+Shift+K",
    "comment_function": "Ctrl+Shift+A",
    "comment_line": "Ctrl+Shift+S"
  }
}
```

## 🎮 使用方法

### 基本操作

#### 函数分析
1. **导航** 到IDA Pro中的任何函数
2. **右键单击** 并选择"分析函数（AI）"或按 `Ctrl+Shift+A`
3. **查看结果** 在NexusAI输出窗口中

#### 代码选择分析  
1. **选择** 一段汇编代码
2. **右键单击** 并选择"分析选择（AI）"
3. **查看** AI生成的分析

#### 交互式聊天（AIMCP）
1. **打开** NexusAI输出窗口（`Ctrl+Shift+K`）
2. **输入** 您的问题在输入框中
3. **按回车** 将查询发送给AI
4. **进行** 关于二进制文件的交互式对话

### 高级功能

#### 自定义提示词
- 在设置对话框中修改系统提示词
- 创建自定义分析模板
- 调整AI模型参数（温度、最大令牌数）

#### 扩展开发
插件支持自定义扩展。查看 `extensions/` 文件夹中的示例：
- **图形导出扩展**：导出调用图和数据流图
- **平坦化检测扩展**：检测控制流平坦化

### 热键参考

| 热键 | 功能 |
|------|------|
| `Ctrl+Shift+K` | 切换NexusAI输出窗口 |
| `Ctrl+Shift+A` | 分析当前函数 |
| `Ctrl+Shift+S` | 为当前行添加AI注释 |
| `Ctrl+Shift+D` | 添加可重复注释 |
| `Ctrl+Shift+W` | 添加前置注释 |

## 🔧 故障排除

### 常见问题

#### "未找到markdown库"
```bash
pip install markdown>=3.4.0
```

#### "未配置OpenAI API密钥"
1. 打开NexusAI设置
2. 输入您的有效OpenAI API密钥
3. 使用"测试模型"按钮测试连接

#### 插件未加载
1. 检查IDA Pro的Python控制台中的错误消息
2. 验证所有依赖项已安装
3. 确保插件文件在正确的目录中
4. 重启IDA Pro

#### 代理问题
如果您在企业防火墙后：
1. 在NexusAI设置对话框中配置代理设置
2. 或设置环境变量：
   ```bash
   set HTTP_PROXY=http://proxy.company.com:8080
   set HTTPS_PROXY=http://proxy.company.com:8080
   ```

### 调试模式
通过在配置文件中设置 `log_chain_of_thought: true` 启用调试日志记录。

## 🤝 贡献

我们欢迎贡献！请查看我们的 [贡献指南](CONTRIBUTING_CN.md) 了解详情。

### 开发设置
1. Fork 仓库
2. 创建开发分支
3. 安装开发依赖
4. 进行更改
5. 彻底测试
6. 提交拉取请求

## 📄 许可证

本项目根据MIT许可证授权 - 有关详细信息，请参阅 [LICENSE](LICENSE) 文件。

## 🙏 致谢

- **Hex-Rays** 提供优秀的IDA Pro平台
- **OpenAI** 提供强大的AI模型
- **逆向工程社区** 的灵感和反馈

## 📚 文档

- **[快速开始指南](QUICKSTART.md)** - 5分钟内开始使用
- **[配置指南](CONFIGURATION.md)** - 详细配置选项
- **[贡献指南](CONTRIBUTING.md)** - 如何为项目做贡献
- **[更新日志](CHANGELOG.md)** - 版本历史和更新

## 📞 支持

- **问题反馈**：[GitHub Issues](https://github.com/fenda1-1/IDA-NexusAI/issues)
- **讨论**：[GitHub Discussions](https://github.com/fenda1-1/IDA-NexusAI/discussions)
- **文档**：[项目Wiki](https://github.com/fenda1-1/IDA-NexusAI/wiki)

## 🌟 Star历史

如果您觉得NexusAI有用，请考虑给它一个star！⭐

## 📈 项目统计

- **语言**：Python
- **框架**：IDA Pro SDK、PyQt5
- **AI集成**：OpenAI、Claude、自定义API
- **平台**：Windows、macOS、Linux
- **许可证**：MIT

---

**用AI愉快地进行逆向工程！🚀**
