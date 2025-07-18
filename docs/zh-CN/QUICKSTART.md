# NexusAI 快速开始指南

5分钟内开始使用NexusAI！🚀

## 📦 快速安装

### 选项1：自动安装（推荐）
```bash
# 下载并运行安装程序
git clone https://github.com/your-repo/NexusAI.git
cd NexusAI
python install.py
```

### 选项2：手动安装
```bash
# 安装依赖
pip install openai>=1.0.0 markdown>=3.4.0

# 复制文件到IDA Pro插件目录
# Windows: %IDADIR%\plugins\
# macOS: $IDADIR/plugins/
# Linux: $IDADIR/plugins/
```

## ⚡ 首次设置

### 1. 获取您的API密钥
- **OpenAI**：访问 [platform.openai.com](https://platform.openai.com/api-keys)
- **Claude**：访问 [console.anthropic.com](https://console.anthropic.com/)

### 2. 配置NexusAI
1. **启动IDA Pro** 并打开任何二进制文件
2. **打开设置**：`编辑 → NexusAI → 设置`
3. **输入API密钥**：粘贴您的API密钥
4. **测试连接**：点击"测试模型"按钮
5. **保存设置**：点击"确定"

### 3. 打开输出窗口
按 `Ctrl+Shift+K` 打开NexusAI输出窗口

## 🎯 基本使用

### 分析函数
1. **导航** 到IDA Pro中的任何函数
2. **右键单击** → "分析函数（AI）"或按 `Ctrl+Shift+A`
3. **查看结果** 在NexusAI输出窗口中

### 提问
1. **输入** 您的问题在底部的输入框中
2. **按回车** 发送
3. **获取AI响应** 实时显示

### 添加智能注释
1. **定位光标** 在任何行上
2. **按 `Ctrl+Shift+S`** 添加行注释
3. **按 `Ctrl+Shift+A`** 添加函数注释

## 🔥 基本热键

| 热键 | 操作 |
|------|------|
| `Ctrl+Shift+K` | 切换NexusAI窗口 |
| `Ctrl+Shift+A` | 分析当前函数 |
| `Ctrl+Shift+S` | 为行添加AI注释 |
| `Ctrl+Shift+D` | 添加可重复注释 |
| `Ctrl+Shift+W` | 添加前置注释 |

## 💡 专业技巧

### 1. 调整分析深度
- **设置 → 分析 → 深度**：设置为2-3进行详细分析
- 更高深度 = 更多上下文但分析更慢

### 2. 使用自定义提示词
- **设置 → 提示词**：自定义AI行为
- 示例："专注于安全漏洞"

### 3. 交互式分析
- 询问关于函数的后续问题
- 请求特定类型的分析
- 获取复杂算法的解释

### 4. 导出分析
- **右键单击** 输出窗口 → "导出"
- 保存分析结果用于文档

## 🛠️ 常见用例

### 恶意软件分析
```
分析此函数的恶意行为和潜在的威胁指标
```

### 漏洞研究
```
检查此函数是否存在缓冲区溢出、整数溢出和其他安全问题
```

### 算法识别
```
此函数实现了什么算法？解释逻辑流程。
```

### 代码理解
```
用简单的术语解释此函数的作用并识别其目的
```

## 🚨 故障排除

### 插件未加载
1. 检查IDA Pro的Python控制台中的错误
2. 验证所有依赖项已安装
3. 确保文件在正确的目录中

### API错误
1. 验证API密钥正确
2. 检查网络连接
3. 如果需要配置代理

### 无AI响应
1. 检查API密钥是否有余额
2. 验证模型名称正确
3. 尝试不同的AI模型

### UI问题
1. 重启IDA Pro
2. 检查PyQt5安装
3. 重置配置文件

## 📚 下一步

### 了解更多
- 阅读完整的 [README.md](README.md)
- 查看 [CONFIGURATION.md](CONFIGURATION.md) 了解高级设置
- 浏览 [CONTRIBUTING.md](CONTRIBUTING.md) 参与贡献

### 高级功能
- **AIMCP**：启用多轮对话
- **扩展**：尝试图形导出和平坦化检测
- **自定义提供商**：配置本地AI模型

### 社区
- **问题**：[GitHub Issues](https://github.com/your-repo/NexusAI/issues)
- **讨论**：[GitHub Discussions](https://github.com/your-repo/NexusAI/discussions)
- **Wiki**：[项目Wiki](https://github.com/your-repo/NexusAI/wiki)

## 🎉 示例工作流程

### 分析可疑函数
1. **打开** 恶意软件样本在IDA Pro中
2. **导航** 到可疑函数
3. **按 `Ctrl+Shift+A`** 进行分析
4. **询问**："此函数是恶意的吗？它做什么？"
5. **跟进**："关键指标是什么？"
6. **添加注释**：按 `Ctrl+Shift+S` 保存分析

### 理解复杂算法
1. **选择** 算法代码块
2. **右键单击** → "分析选择（AI）"
3. **询问**："这是什么算法？逐步解释。"
4. **请求**："显示数学公式"
5. **文档化**：导出分析供团队审查

---

**愉快的逆向工程！🔍✨**

需要帮助？查看 [完整文档](README.md) 或 [提交问题](https://github.com/your-repo/NexusAI/issues)。
