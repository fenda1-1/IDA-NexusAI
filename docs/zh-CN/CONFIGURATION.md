# NexusAI 配置指南

本指南提供了配置NexusAI以获得最佳性能的详细信息。

## 📁 配置文件位置

主配置文件位于：
```
<IDA_PLUGINS_DIR>/NexusAI/Config/NexusAI.json
```

## 🔧 配置部分

### API设置

#### OpenAI配置
```json
{
  "openai": {
    "api_key": "your-openai-api-key",
    "base_url": "https://api.openai.com/v1",
    "proxy": "",
    "models": [
      "gpt-4",
      "gpt-4-turbo",
      "gpt-3.5-turbo"
    ],
    "model": "gpt-4"
  }
}
```

#### 多AI提供商
NexusAI通过 `api_profiles` 系统支持多个AI提供商：

```json
{
  "api_profiles": {
    "OpenAI": {
      "api_key": "your-openai-key",
      "base_url": "https://api.openai.com/v1",
      "model": "gpt-4"
    },
    "Claude": {
      "api_key": "your-claude-key", 
      "base_url": "https://api.anthropic.com/v1",
      "model": "claude-3-opus-20240229"
    },
    "自定义": {
      "api_key": "your-custom-key",
      "base_url": "https://your-custom-endpoint.com/v1",
      "model": "your-model"
    }
  },
  "current_profile": "OpenAI"
}
```

### 分析设置

```json
{
  "analysis_depth": 2,
  "analysis_options": {
    "include_type_definitions": true,
    "include_xrefs": true
  },
  "temperature": 0.7,
  "max_tokens": 2000
}
```

- **analysis_depth**：分析函数调用链的深度（1-5）
- **include_type_definitions**：在分析中包含类型信息
- **include_xrefs**：在分析中包含交叉引用
- **temperature**：AI创造性水平（0.0-1.0）
- **max_tokens**：最大响应长度

### UI设置

```json
{
  "language": "zh_CN",
  "auto_open": true,
  "shortcuts": {
    "toggle_output": "Ctrl+Shift+K",
    "comment_function": "Ctrl+Shift+A",
    "comment_line": "Ctrl+Shift+S",
    "comment_repeatable": "Ctrl+Shift+D",
    "comment_anterior": "Ctrl+Shift+W"
  },
  "shortcuts_window_only": false
}
```

- **language**：界面语言（"en_US"或"zh_CN"）
- **auto_open**：启动时自动打开输出窗口
- **shortcuts_window_only**：仅在NexusAI窗口中限制快捷键

### AIMCP设置

```json
{
  "aimcp_enabled": true,
  "aimcp_auto_enabled": false,
  "aimcp_limit_iters_enabled": true,
  "aimcp_max_iterations": 10,
  "log_chain_of_thought": false
}
```

- **aimcp_enabled**：启用AI模型控制协议
- **aimcp_auto_enabled**：自动为查询启动AIMCP
- **aimcp_limit_iters_enabled**：限制最大迭代次数
- **aimcp_max_iterations**：最大对话轮数
- **log_chain_of_thought**：启用调试日志记录

## 🔑 API密钥设置

### OpenAI API密钥
1. 访问 [OpenAI平台](https://platform.openai.com/api-keys)
2. 创建新的API密钥
3. 将密钥复制到配置文件
4. 确保您有足够的余额

### Claude API密钥
1. 访问 [Anthropic控制台](https://console.anthropic.com/)
2. 生成API密钥
3. 添加到配置中的Claude配置文件
4. 将 `current_profile` 设置为"Claude"

### 自定义端点
对于自定义或本地AI模型：
1. 将 `base_url` 设置为您的端点
2. 配置适当的 `model` 名称
3. 如果需要，添加身份验证

## 🌐 代理配置

### HTTP代理
```json
{
  "openai": {
    "proxy": "http://proxy.company.com:8080"
  }
}
```

### 环境变量
或者，设置环境变量：
```bash
# Windows
set HTTP_PROXY=http://proxy.company.com:8080
set HTTPS_PROXY=http://proxy.company.com:8080

# Linux/macOS
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080
```

## 🎨 自定义提示词

### 系统提示词
通过修改系统提示词自定义AI行为：

```json
{
  "prompts": {
    "system": "您是一位专业的逆向工程师...",
    "function_analysis": "分析此函数并解释...",
    "code_explanation": "解释此代码的作用..."
  }
}
```

### 提示词模板
创建可重用的提示词模板：

```json
{
  "prompt_templates": {
    "vulnerability_analysis": "分析此代码的安全漏洞...",
    "algorithm_identification": "识别此函数中实现的算法...",
    "malware_analysis": "分析此代码的恶意行为..."
  }
}
```

## 🔧 高级设置

### 性能调优
```json
{
  "performance": {
    "max_concurrent_requests": 1,
    "request_timeout": 120,
    "retry_attempts": 2,
    "retry_delay": 5
  }
}
```

### 调试设置
```json
{
  "debug": {
    "log_level": "INFO",
    "log_api_requests": false,
    "log_responses": false,
    "save_prompts": false
  }
}
```

### 扩展设置
```json
{
  "extensions": {
    "graph_export": {
      "enabled": true,
      "output_format": "json",
      "include_data_refs": true
    },
    "flattening_detection": {
      "enabled": true,
      "threshold": 0.8
    }
  }
}
```

## 🔄 配置管理

### 备份配置
```bash
# 创建备份
cp NexusAI/Config/NexusAI.json NexusAI/Config/NexusAI.json.backup

# 恢复备份
cp NexusAI/Config/NexusAI.json.backup NexusAI/Config/NexusAI.json
```

### 重置为默认值
删除配置文件并重启IDA Pro以重新生成默认值：
```bash
rm NexusAI/Config/NexusAI.json
```

### 验证配置
使用设置对话框中的内置验证：
1. 打开NexusAI设置
2. 点击"测试模型"验证API设置
3. 检查输出窗口中的错误消息

## 🚨 故障排除

### 常见配置问题

#### 无效的API密钥
```
错误：提供的API密钥无效
```
**解决方案**：验证您的API密钥正确且有足够余额

#### 网络问题
```
错误：连接超时
```
**解决方案**：检查代理设置和网络连接

#### 模型不可用
```
错误：未找到模型
```
**解决方案**：验证模型名称正确且在您的计划中可用

#### 权限问题
```
错误：无法写入配置文件
```
**解决方案**：确保IDA Pro对插件目录有写权限

### 配置验证
插件在启动时验证配置。检查IDA Pro输出窗口中的验证消息。

## 📝 配置示例

### 最小配置
```json
{
  "openai": {
    "api_key": "sk-...",
    "model": "gpt-3.5-turbo"
  },
  "language": "zh_CN"
}
```

### 企业配置
```json
{
  "openai": {
    "api_key": "sk-...",
    "base_url": "https://api.openai.com/v1",
    "proxy": "http://proxy.company.com:8080",
    "model": "gpt-4"
  },
  "analysis_depth": 3,
  "temperature": 0.3,
  "max_tokens": 4000,
  "aimcp_enabled": true,
  "aimcp_max_iterations": 15,
  "shortcuts_window_only": true,
  "debug": {
    "log_level": "DEBUG",
    "log_api_requests": true
  }
}
```

### 多提供商配置
```json
{
  "api_profiles": {
    "OpenAI-GPT4": {
      "api_key": "sk-...",
      "base_url": "https://api.openai.com/v1",
      "model": "gpt-4"
    },
    "OpenAI-GPT3": {
      "api_key": "sk-...",
      "base_url": "https://api.openai.com/v1", 
      "model": "gpt-3.5-turbo"
    },
    "本地LLM": {
      "api_key": "not-needed",
      "base_url": "http://localhost:8000/v1",
      "model": "llama-2-70b"
    }
  },
  "current_profile": "OpenAI-GPT4"
}
```

---

如需更多帮助，请参阅主要的 [README.md](README.md) 或在GitHub上提交问题。
