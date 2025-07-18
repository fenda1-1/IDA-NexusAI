# NexusAI Configuration Guide

This guide provides detailed information about configuring NexusAI for optimal performance.

## 📁 Configuration File Location

The main configuration file is located at:
```
<IDA_PLUGINS_DIR>/NexusAI/Config/NexusAI.json
```

## 🔧 Configuration Sections

### API Settings

#### OpenAI Configuration
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

#### Multiple AI Providers
NexusAI supports multiple AI providers through the `api_profiles` system:

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
    "Custom": {
      "api_key": "your-custom-key",
      "base_url": "https://your-custom-endpoint.com/v1",
      "model": "your-model"
    }
  },
  "current_profile": "OpenAI"
}
```

### Analysis Settings

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

- **analysis_depth**: How deep to analyze function call chains (1-5)
- **include_type_definitions**: Include type information in analysis
- **include_xrefs**: Include cross-references in analysis
- **temperature**: AI creativity level (0.0-1.0)
- **max_tokens**: Maximum response length

### UI Settings

```json
{
  "language": "en_US",
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

- **language**: Interface language ("en_US" or "zh_CN")
- **auto_open**: Automatically open output window on startup
- **shortcuts_window_only**: Limit shortcuts to NexusAI window only

### AIMCP Settings

```json
{
  "aimcp_enabled": true,
  "aimcp_auto_enabled": false,
  "aimcp_limit_iters_enabled": true,
  "aimcp_max_iterations": 10,
  "log_chain_of_thought": false
}
```

- **aimcp_enabled**: Enable AI Model Control Protocol
- **aimcp_auto_enabled**: Automatically start AIMCP for queries
- **aimcp_limit_iters_enabled**: Limit maximum iterations
- **aimcp_max_iterations**: Maximum conversation rounds
- **log_chain_of_thought**: Enable debug logging

## 🔑 API Key Setup

### OpenAI API Key
1. Visit [OpenAI Platform](https://platform.openai.com/api-keys)
2. Create a new API key
3. Copy the key to the configuration file
4. Ensure you have sufficient credits

### Claude API Key
1. Visit [Anthropic Console](https://console.anthropic.com/)
2. Generate an API key
3. Add to the Claude profile in configuration
4. Set `current_profile` to "Claude"

### Custom Endpoints
For custom or local AI models:
1. Set the `base_url` to your endpoint
2. Configure the appropriate `model` name
3. Add authentication if required

## 🌐 Proxy Configuration

### HTTP Proxy
```json
{
  "openai": {
    "proxy": "http://proxy.company.com:8080"
  }
}
```

### Environment Variables
Alternatively, set environment variables:
```bash
# Windows
set HTTP_PROXY=http://proxy.company.com:8080
set HTTPS_PROXY=http://proxy.company.com:8080

# Linux/macOS
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080
```

## 🎨 Custom Prompts

### System Prompts
Customize the AI behavior by modifying system prompts:

```json
{
  "prompts": {
    "system": "You are an expert reverse engineer...",
    "function_analysis": "Analyze this function and explain...",
    "code_explanation": "Explain what this code does..."
  }
}
```

### Prompt Templates
Create reusable prompt templates:

```json
{
  "prompt_templates": {
    "vulnerability_analysis": "Analyze this code for security vulnerabilities...",
    "algorithm_identification": "Identify the algorithm implemented in this function...",
    "malware_analysis": "Analyze this code for malicious behavior..."
  }
}
```

## 🔧 Advanced Settings

### Performance Tuning
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

### Debug Settings
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

### Extension Settings
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

## 🔄 Configuration Management

### Backup Configuration
```bash
# Create backup
cp NexusAI/Config/NexusAI.json NexusAI/Config/NexusAI.json.backup

# Restore backup
cp NexusAI/Config/NexusAI.json.backup NexusAI/Config/NexusAI.json
```

### Reset to Defaults
Delete the configuration file and restart IDA Pro to regenerate defaults:
```bash
rm NexusAI/Config/NexusAI.json
```

### Validate Configuration
Use the built-in validation in the settings dialog:
1. Open NexusAI Settings
2. Click "Test Model" to validate API settings
3. Check for error messages in the output window

## 🚨 Troubleshooting

### Common Configuration Issues

#### Invalid API Key
```
Error: Invalid API key provided
```
**Solution**: Verify your API key is correct and has sufficient credits

#### Network Issues
```
Error: Connection timeout
```
**Solution**: Check proxy settings and network connectivity

#### Model Not Available
```
Error: Model not found
```
**Solution**: Verify the model name is correct and available in your plan

#### Permission Issues
```
Error: Cannot write to configuration file
```
**Solution**: Ensure IDA Pro has write permissions to the plugins directory

### Configuration Validation
The plugin validates configuration on startup. Check the IDA Pro output window for validation messages.

## 📝 Configuration Examples

### Minimal Configuration
```json
{
  "openai": {
    "api_key": "sk-...",
    "model": "gpt-3.5-turbo"
  },
  "language": "en_US"
}
```

### Enterprise Configuration
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

### Multi-Provider Configuration
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
    "Local-LLM": {
      "api_key": "not-needed",
      "base_url": "http://localhost:8000/v1",
      "model": "llama-2-70b"
    }
  },
  "current_profile": "OpenAI-GPT4"
}
```

---

For more help, see the main [README.md](README.md) or open an issue on GitHub.
