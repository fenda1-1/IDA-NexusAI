"""
Configuration management module.

This module is responsible for loading, saving, and managing plugin configurations.
It ensures that the plugin has access to necessary settings like API keys,
language preferences, and predefined prompts.
"""
# -*- coding: utf-8 -*-
"""
配置管理模块

该模块负责加载、保存和管理插件的配置。
它确保插件能够访问必要的设置，如API密钥、语言偏好和预定义的提示词。
"""

import os
import json
import sys
import threading
from idaapi import msg
import idaapi
from openai import OpenAI

from ..Core.event_bus import get_event_bus
# 新增：持久化历史管理
from ..Utils.history_manager import HistoryManager
from pathlib import Path

# ----------------------------------------------------------------------------
# 配置管理器
# ----------------------------------------------------------------------------


event_bus = get_event_bus()


class ConfigManager:
    """
    Manages plugin configurations loaded from a JSON file.

    This class implements the Singleton pattern to ensure a single instance
    manages the configuration throughout the plugin's lifecycle. It handles
    loading, saving, and providing access to various configuration settings.

    Attributes:
        _instance (ConfigManager): The singleton instance of the class.
        _lock (threading.Lock): A lock for thread-safe singleton instantiation.
        DEFAULT_CONFIG (dict): A dictionary holding the default configuration.
        config (dict): The currently loaded configuration.
        config_path (str): The file path to the configuration file.
        client (openai.OpenAI): The OpenAI client instance.
        output_view (object): The view object for displaying output.
    """
    """
    管理从JSON文件加载的插件配置。

    该类采用单例模式，确保在插件的整个生命周期中只有一个实例来管理配置。
    它处理加载、保存和提供对各种配置设置的访问。

    属性:
        _instance (ConfigManager): 类的单例实例。
        _lock (threading.Lock): 用于线程安全单例实例化的锁。
        DEFAULT_CONFIG (dict): 包含默认配置的字典。
        config (dict): 当前加载的配置。
        config_path (str): 配置文件的路径。
        client (openai.OpenAI): OpenAI 客户端实例。
        output_view (object): 用于显示输出的视图对象。
    """
    _instance = None
    _lock = threading.Lock()
    DEFAULT_CONFIG = {
        # ----------------------- 多平台预设 -----------------------
        "api_profiles": {
            "OpenAI": {
                "api_key": "",
                "base_url": "https://api.openai.com/v1",
                "proxy": "",
                "models": [
                    "gpt-4.1", "gpt-4o", "gpt-4o-mini", "o4-mini", "o3-mini",
                    "o1-mini", "o3", "o1"
                ],
                "model": "gpt-4o"
            },
            "Claude": {
                "api_key": "",
                "base_url": "https://api.anthropic.com/v1",
                "proxy": "",
                "models": [
                    "claude-opus-4-0", "claude-sonnet-4-0", "claude-3-7-sonnet-latest",
                    "claude-3-5-sonnet-latest", "claude-3-5-haiku-latest", "claude-3-opus-latest"
                ],
                "model": "claude-opus-4-0"
            },
            "Gemini": {
                "api_key": "",
                "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
                "proxy": "",
                "models": [
                    "gemini-2.5-flash-preview-05-20", "gemini-2.5-pro-preview-06-05", "gemini-2.0-flash-exp",
                    "gemini-2.0-flash-thinking-exp", "gemini-2.0-flash-thinking-exp-1219", "gemini-1.5-pro-latest",
                    "gemini-1.5-flash-latest", "gemini-1.5-pro-exp-0827", "gemini-1.5-flash-exp-0827",
                    "gemini-1.5-flash-8b-exp-0924", "gemini-pro"
                ],
                "model": "gemini-1.5-pro-latest"
            },
            "Ollama": {
                "api_key": "",
                "base_url": "http://127.0.0.1:11434",
                "proxy": "",
                "model": "llama3"
            },
            "LM Studio": {
                "api_key": "",
                "base_url": "http://127.0.0.1:1234",
                "proxy": "",
                "model": "llama3:8b-instruct-q4_K_M"
            },
            "DeepSeek": {
                "api_key": "",
                "base_url": "https://api.deepseek.com/v1",
                "proxy": "",
                "models": ["deepseek-chat", "deepseek-coder", "deepseek-reasoner"],
                "model": "deepseek-chat"
            },
            "Azure": {
                "api_key": "",
                "base_url": "https://<resource_name>.openai.azure.com/openai/deployments",
                "proxy": "",
                "model": "gpt-4o",
                "api_version": "2024-05-01-preview"
            },
            "xAI": {
                "api_key": "",
                "base_url": "https://api.x.ai/v1",
                "proxy": "",
                "models": [
                    "grok-3-beta", "grok-3-mini-beta", "grok-2-vision-1212",
                    "grok-2-image-1212", "grok-2-1212", "grok-vision-beta", "grok-beta"
                ],
                "model": "grok-3-beta"
            }
        },
        # 兼容旧逻辑的 openai 字段（始终与当前选定分组同步）
        "openai": {
            "api_key": "YOUR_API_KEY",  # 请替换为您的API密钥
            "base_url": "https://api.openai.com/v1",
            "proxy": "",
            "model": "gpt-4o"
        },
        "language": "zh_CN", # 默认使用中文
        "prompt": "你是一名逆向工程专家，请分析我提供的代码。请用中文回复。", # 默认分析指令
        "analysis_depth": 2, # 默认分析深度
        # 默认快捷键配置，可在设置界面中修改
        "shortcuts": {
            "toggle_output": "Ctrl+Shift+K",      # 切换输出窗口
            "comment_function": "Ctrl+Shift+A",   # 函数注释
            "comment_line": "Ctrl+Shift+S",       # 行注释
            "comment_repeatable": "Ctrl+Shift+D", # 可重复注释
            "comment_anterior": "Ctrl+Shift+W"    # 前置注释
        },
        "prompts": {
            "zh_CN": {
                "system": "你是一名逆向工程专家，请分析我提供的代码。请用中文回复。",
                "comment_function": "我将提供一个函数及其调用链代码用于分析。请为名为 {func_name} 的主函数生成详细的注释。\n\n注释要求：\n1. 使用C语言风格的注释格式，以/*开头，以*/结尾\n2. 清晰描述函数的主要功能和目的\n3. 说明函数的参数及其用途\n4. 描述返回值的含义\n5. 如有特殊的算法或技术，请指出\n6. 只生成注释内容，不要包含任何代码或其他解释\n7. 不要添加无关内容，注释只用于描述这个函数\n\n注释格式示例：\n/*\n➀功能：\n  ⑴描述函数的功能1\n  ⑵描述函数的功能2\n\n➁参数：\n  ⑴参数1: 参数1的说明\n  ⑵参数2: 参数2的说明\n\n➂返回值：\n  ⑴描述返回值的含义\n\n➃特殊算法/技术：\n  ⑴描述使用的特殊算法或技术（如果有）\n*/\n\n主函数代码 ({func_name}):\n{target_func_code}\n\n调用链上下文代码 (用于辅助分析，无需为这部分生成注释):\n{context_code}",
                "generate_line_comment": "请为以下代码行(标记为'>')生成简洁、准确的注释，只提供注释内容，不要包含额外解释：\n\n{context}",
                "custom_query_with_code": "以下是相关代码：\n{code_snippet}",
                "analyze_function": "请分析以下函数及其调用链：\n{code_snippet}",
                "analyze_selection": "请分析以下代码片段：\n{code_snippet}",
            },
            "en_US": {
                "system": "You are a reverse engineering expert. Please analyze the code I provide and respond in English.",
                "comment_function": "I will provide a function and its call chain code for analysis. Please generate detailed comments for the main function named {func_name}.\n\nComment requirements:\n1. Use C-style comment format, starting with /* and ending with */\n2. Clearly describe the main function and purpose\n3. Explain the function's parameters and their uses\n4. Describe the meaning of the return value\n5. If there are special algorithms or techniques, please indicate them\n6. Only generate comment content, do not include any code or other explanations\n7. Do not add irrelevant content; the comment is only for describing this function\n\nComment format example:\n/*\n➀ Function:\n  ⑴ Describe function function 1\n  ⑵ Describe function function 2\n\n➁ Parameters:\n  ⑴ Parameter 1: Description of parameter 1\n  ⑵ Parameter 2: Description of parameter 2\n\n➂ Return value:\n  ⑴ Describe the meaning of the return value\n\n➃ Special algorithm/technology:\n  ⑴ Describe the special algorithm or technology used (if any)\n*/\n\nMain function code ({func_name}):\n{target_func_code}\n\nCall chain context code (for assisting analysis, no need to generate comments for this part):\n{context_code}",
                "generate_line_comment": "Please generate a concise and accurate comment for the following line of code (marked with '>'), providing only the comment content without extra explanations:\n\n{context}",
                "custom_query_with_code": "Here is the relevant code:\n{code_snippet}",
                "analyze_function": "Please analyze the following function and its call chain:\n{code_snippet}",
                "analyze_selection": "Please analyze the following code snippet:\n{code_snippet}"
            },
        },
        "analysis_options": {
            "include_type_definitions": True,
            "include_xrefs": True
        },
        "aimcp_enabled": False,
        "messages": {
            "zh_CN": {
                "markdown_not_found": "<div style=\"background-color: #5A2D2D; border: 1px solid #C53333; color: #F0DADA; padding: 10px; margin: 5px; border-radius: 4px;\"><strong>[NexusAI] 错误: 缺少依赖库</strong><br>未安装 'markdown' 库，富文本渲染将被禁用。<br>请从命令行安装 (<b>确保 python 命令与 IDA Pro 使用的版本一致</b>):<br><code style=\"background-color: #444; padding: 3px 6px; border-radius: 3px; color: #D4D4D4;\">python -m pip install markdown</code><br>然后，重启 IDA Pro。</div>",
                "config_load_success": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #2ECC71;\">✅ <b>NexusAI: 配置文件加载成功: {0}</b> ✅</span></div>",
                "config_not_found": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI: 未找到配置文件: {0}。正在创建默认配置...</b> ℹ️</span></div>",
                "config_format_error": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: 配置文件格式错误: {0}</b> ❌</span></div>",
                "config_load_error": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: 配置文件加载失败: {0}</b> ❌</span></div>",
                "config_updated": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI: 配置已更新，默认项目已添加</b> ℹ️</span></div>",
                "create_dir": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI: 正在创建配置目录: {0}</b> ℹ️</span></div>",
                "config_save_success": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #2ECC71;\">✅ <b>NexusAI: 配置文件保存成功: {0}</b> ✅</span></div>",
                "config_save_error": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: 配置文件保存失败: {0}</b> ❌</span></div>",
                "reload_config": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI: 正在重新加载配置...</b> ℹ️</span></div>",
                "reload_complete": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #2ECC71;\">✅ <b>NexusAI: 重载完成。语言: {0}, 深度: {1}, 模型: {2}</b> ✅</span></div>",
                "api_key_not_set": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: API密钥未设置或为默认值，请修改API设置</b> ❌</span></div>",
                "client_create_success": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #2ECC71;\">✅ <b>NexusAI: OpenAI 客户端创建成功</b> ✅</span></div>",
                "client_create_error": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: OpenAI 客户端创建失败: {0}</b> ❌</span></div>",
                "prompt_empty": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: 分析指令不能为空</b> ❌</span></div>",
                "depth_invalid": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: 分析深度 '{0}' 无效，已使用默认值 {1}</b> ❌</span></div>",
                "depth_negative": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI: 分析深度必须为非负整数</b> ℹ️</span></div>",
                "depth_not_int": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI: 分析深度必须为有效整数</b> ℹ️</span></div>",
                "language_changed": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #2ECC71;\">✅ <b>NexusAI: 语言已切换为 {0}</b> ✅</span></div>",
                "language_not_supported": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: 不支持的语言 '{0}'</b> ❌</span></div>",
                "prompt_updated": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #2ECC71;\">✅ <b>NexusAI: 指令已更新为当前语言 ({0}) 的系统指令</b> ✅</span></div>",
                "plugin_load_success": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI 插件加载成功</b> ℹ️</span></div>",
                "current_depth": "当前分析深度: {0}",
                "current_model": "当前模型: {0}",
                "task_in_progress": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI: AI 正在处理任务，请稍后再试或停止当前任务</b> ℹ️</span></div>",
                "prepare_analyze_function": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI: 准备分析当前函数...</b> ℹ️</span></div>",
                "code_extract_failed": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: 代码提取失败: {0}</b> ❌</span></div>",
                "code_extract_error": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: 代码提取时发生未知错误: {0}</b> ❌</span></div>",
                "prepare_analyze_selection": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI: 准备分析选中代码...</b> ℹ️</span></div>",
                "custom_query_empty": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: 自定义提问内容不能为空</b> ❌</span></div>",
                "prepare_extract_code": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI: 准备提取当前函数代码用于提问...</b> ℹ️</span></div>",
                "task_start_error": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: 启动任务时发生错误: {0}</b> ❌</span></div>",
                "task_execution_error": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: 任务执行过程中发生未捕获的错误: {0}</b> ❌</span></div>",
                "stop_task": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI: 尝试停止AI任务...</b> ℹ️</span></div>",
                "no_task_running": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI: 没有正在运行的AI任务</b> ℹ️</span></div>",
                "client_not_initialized": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: OpenAI 客户端未初始化，无法执行此操作</b> ❌</span></div>",
                "query_error": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: 查询AI时出错: {0}</b> ❌</span></div>",
                "sending_request": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: red;\">💡 <b>NexusAI: 正在向AI发送请求...</b> 💡</span></div>",
                "client_not_initialized_check": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: OpenAI 客户端未初始化。请检查配置文件和API密钥</b> ❌</span></div>",
                "ai_response_header": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: red;\">💡 <b>NexusAI: 回复开始</b> 💡</span></div>",
                "analysis_paused": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: red;\">💡 <b>NexusAI: 分析已暂停.</b> 💡</span></div>",
                "analysis_complete": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: red;\">💡 <b>NexusAI: 分析完成！</b> 💡</span></div>",
                "aimcp_max_iters_reached": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI: 当前 AIMCP 已达到最大迭代次数 ({0})，已停止工作。如需提高上限，请在设置中调整 AIMCP 迭代限制。</b> ℹ️</span></div>",
                "aimcp_cancelled": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI: AIMCP 过程已被用户终止。</b> ℹ️</span></div>",
                "openai_request_error": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: 请求 OpenAI 时发生错误: {0}</b> ❌</span></div>",
                "create_prompt_error": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: 创建提示词时出错: {0}</b> ❌</span></div>",
                "horizontal_rule": "<hr/>",
                "register_action_failed": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: 注册动作失败: {0}</b> ❌</span></div>",
                "menu_added": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI: 已在主菜单 Edit/{0} 中添加菜单项</b> ℹ️</span></div>",
                "menu_removed": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI: 已删除主菜单项 {0}</b> ℹ️</span></div>",
                "plugin_load_limited": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI 插件加载完成 (功能受限)</b> ℹ️</span></div>",
                "client_init_failed": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: OpenAI 客户端初始化失败，插件功能受限</b> ❌</span></div>",
                "depth_input": "请输入分析深度 (0-10):",
                "depth_set": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #2ECC71;\">✅ <b>NexusAI: 分析深度已设置为 {0}</b> ✅</span></div>",
                "prompt_input": "请输入分析指令:",
                "prompt_set": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #2ECC71;\">✅ <b>NexusAI: 分析指令已更新</b> ✅</span></div>",
                "custom_query_input": "请输入您的问题:",
                "language_input": "请选择语言 (1:zh_CN/2:en_US):",
                "language_set": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #2ECC71;\">✅ <b>NexusAI: 语言已切换为 {0}</b> ✅</span></div>",
                "no_selection": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: 请先选中代码范围</b> ❌</span></div>",
                "welcome_message": "### 欢迎使用 NexusAI！\n\n- 使用 `Ctrl+Shift+K` 切换此窗口的显示/隐藏。\n- 在反汇编或伪代码视图中右键单击以访问分析选项。\n- 在下面的输入框中提问以开始。\n<br><br>\n",
                "chat_input_placeholder": "输入对当前光标位置的代码提问（\"附加上下文\"以添加附带内容，\"查看提示词\"可查看具体附加内容）...",
                "menu_texts": {
                    "menu_title": "NexusAI",
                    "analyze_func": "分析当前函数 (AI)",
                    "analyze_selection": "分析选中代码 (AI)",
                    "custom_query": "自定义提问...",
                    "set_depth": "设置分析深度...",
                    "set_prompt": "设置分析指令...",
                    "reload_config": "重新加载配置",
                    "stop_task": "停止当前分析",
                    "switch_language": "切换语言...",
                    "toggle_output_view": "切换输出窗口",
                    "reload_extensions": "重新加载扩展",
                    "extensions_reloaded": "扩展已重新加载。",
                    "plugin_unloaded": "插件已卸载。"
                },
                "tooltip": {
                    "analyze_func": "对当前函数及其调用链执行非阻塞式AI分析",
                    "analyze_selection": "对当前选定的代码范围执行非阻塞式AI分析",
                    "custom_query": "不附带任何代码上下文进行提问",
                    "set_depth": "设置代码递归分析的深度",
                    "set_prompt": "自定义用于函数分析的提示",
                    "reload_config": "从文件重新加载插件配置",
                    "stop_task": "强制停止当前的AI分析任务",
                    "switch_language": "切换界面和AI回复的语言",
                    "toggle_output_view": "切换 NexusAI 输出窗口 (Ctrl+Shift+K)",
                    "reload_extensions": "重新加载扩展"
                }
            },
            "en_US": {
                "markdown_not_found": "<div style=\"background-color: #5A2D2D; border: 1px solid #C53333; color: #F0DADA; padding: 10px; margin: 5px; border-radius: 4px;\"><strong>[NexusAI] Error: Missing Dependency</strong><br>The 'markdown' library is not installed. Rich text rendering will be disabled.<br>Please install it from your command line (<b>ensure this python command corresponds to the version used by IDA Pro</b>):<br><code style=\"background-color: #444; padding: 3px 6px; border-radius: 3px; color: #D4D4D4;\">python -m pip install markdown</code><br>Then, restart IDA Pro.</div>",
                "config_load_success": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #2ECC71;\">✅ <b>NexusAI: Configuration file loaded successfully: {0}</b> ✅</span></div>",
                "config_not_found": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI: Configuration file not found: {0}. Creating default configuration.</b> ℹ️</span></div>",
                "config_format_error": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: Configuration file format error: {0}</b> ❌</span></div>",
                "config_load_error": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: Configuration file load failed: {0}</b> ❌</span></div>",
                "config_updated": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI: Configuration updated, default items added</b> ℹ️</span></div>",
                "create_dir": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI: Creating configuration directory: {0}</b> ℹ️</span></div>",
                "config_save_success": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #2ECC71;\">✅ <b>NexusAI: Configuration file saved successfully: {0}</b> ✅</span></div>",
                "config_save_error": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: Configuration file save failed: {0}</b> ❌</span></div>",
                "reload_config": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI: Reloading configuration...</b> ℹ️</span></div>",
                "reload_complete": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #2ECC71;\">✅ <b>NexusAI: Reload complete. Language: {0}, Depth: {1}, Model: {2}</b> ✅</span></div>",
                "api_key_not_set": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: API key not set or is default value, please edit api settings</b> ❌</span></div>",
                "client_create_success": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #2ECC71;\">✅ <b>NexusAI: OpenAI client created successfully</b> ✅</span></div>",
                "client_create_error": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: OpenAI client creation failed: {0}</b> ❌</span></div>",
                "prompt_empty": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: Analysis prompt cannot be empty</b> ❌</span></div>",
                "depth_invalid": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: Analysis depth '{0}' is invalid, using default {1}</b> ❌</span></div>",
                "depth_negative": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI: Analysis depth must be a non-negative integer</b> ℹ️</span></div>",
                "depth_not_int": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI: Analysis depth must be a valid integer</b> ℹ️</span></div>",
                "language_changed": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #2ECC71;\">✅ <b>NexusAI: Language switched to {0}</b> ✅</span></div>",
                "language_not_supported": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: Unsupported language '{0}'</b> ❌</span></div>",
                "prompt_updated": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #2ECC71;\">✅ <b>NexusAI: Prompt updated to current language ({0}) system prompt</b> ✅</span></div>",
                "plugin_load_success": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI Plugin Loaded Successfully</b> ℹ️</span></div>",
                "current_depth": "Current analysis depth: {0}",
                "current_model": "Current model: {0}",
                "task_in_progress": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI: AI is currently processing a task, please try again later or stop it</b> ℹ️</span></div>",
                "prepare_analyze_function": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI: Preparing to analyze current function...</b> ℹ️</span></div>",
                "code_extract_failed": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: Code extraction failed: {0}</b> ❌</span></div>",
                "code_extract_error": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: Unknown error during code extraction: {0}</b> ❌</span></div>",
                "prepare_analyze_selection": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI: Preparing to analyze selected code...</b> ℹ️</span></div>",
                "custom_query_empty": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: Custom query content cannot be empty</b> ❌</span></div>",
                "prepare_extract_code": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI: Preparing to extract current function code for query...</b> ℹ️</span></div>",
                "task_start_error": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: Error starting task: {0}</b> ❌</span></div>",
                "task_execution_error": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: Uncaught error during task execution: {0}</b> ❌</span></div>",
                "stop_task": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI: Attempting to stop AI task...</b> ℹ️</span></div>",
                "no_task_running": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI: No AI task is currently running</b> ℹ️</span></div>",
                "client_not_initialized": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: OpenAI client not initialized, cannot perform this operation</b> ❌</span></div>",
                "query_error": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: Error querying AI: {0}</b> ❌</span></div>",
                "sending_request": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: red;\">💡 <b>NexusAI: Sending request to AI...</b> 💡</span></div>",
                "client_not_initialized_check": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: OpenAI client not initialized. Please check configuration file and API key</b> ❌</span></div>",
                "ai_response_header": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: red;\">💡 <b>NexusAI: AI Response Start</b> 💡</span></div>",
                "analysis_paused": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: red;\">💡 <b>NexusAI: Analysis paused.</b> 💡</span></div>",
                "analysis_complete": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: red;\">💡 <b>NexusAI: Analysis complete!</b> 💡</span></div>",
                "aimcp_max_iters_reached": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI: AIMCP has reached the maximum iteration limit ({0}) and stopped. To increase the limit, please adjust it in Settings.</b> ℹ️</span></div>",
                "aimcp_cancelled": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI: AIMCP process has been terminated by the user.</b> ℹ️</span></div>",
                "openai_request_error": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: Error occurred when requesting OpenAI: {0}</b> ❌</span></div>",
                "create_prompt_error": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: Error creating prompt: {0}</b> ❌</span></div>",
                "horizontal_rule": "<hr/>",
                "register_action_failed": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: Failed to register action: {0}</b> ❌</span></div>",
                "menu_added": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI: Menu items added to main menu Edit/{0}</b> ℹ️</span></div>",
                "menu_removed": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI: Main menu item removed: {0}</b> ℹ️</span></div>",
                "plugin_load_limited": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #1E90FF;\">ℹ️ <b>NexusAI Plugin Loaded (Limited Functionality)</b> ℹ️</span></div>",
                "client_init_failed": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: OpenAI client initialization failed, plugin functionality is limited</b> ❌</span></div>",
                "depth_input": "Enter analysis depth (0-10):",
                "depth_set": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #2ECC71;\">✅ <b>NexusAI: Analysis depth set to {0}</b> ✅</span></div>",
                "prompt_input": "Enter analysis prompt:",
                "prompt_set": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #2ECC71;\">✅ <b>NexusAI: Analysis prompt updated</b> ✅</span></div>",
                "custom_query_input": "Enter your question:",
                "language_input": "Select language (1:zh_CN/2:en_US):",
                "language_set": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #2ECC71;\">✅ <b>NexusAI: Language switched to {0}</b> ✅</span></div>",
                "no_selection": "<div style=\"display: flex; align-items: center; justify-content: center;\"><span style=\"white-space: nowrap; color: #FF4500;\">❌ <b>NexusAI: Please select a code range first</b> ❌</span></div>",
                "welcome_message": "### Welcome to NexusAI!\n\n- Use `Ctrl+Shift+K` to toggle this window.\n- Right-click in the Disassembly or Pseudocode view to access analysis options.\n- Ask a question in the input box below to start.\n<br><br>\n",
                "chat_input_placeholder": "Ask questions about the code at the current cursor position (\"Attach context\" to add additional content, \"View prompt\" to see specific attached content)...",
                "menu_texts": {
                    "menu_title": "NexusAI",
                    "analyze_func": "Analyze Current Function (AI)",
                    "analyze_selection": "Analyze Selected Code (AI)",
                    "custom_query": "Custom Question...",
                    "set_depth": "Set Analysis Depth...",
                    "set_prompt": "Set Analysis Prompt...",
                    "reload_config": "Reload Configuration",
                    "stop_task": "Stop Current Analysis",
                    "switch_language": "Switch Language...",
                    "toggle_output_view": "Toggle Output Window",
                    "reload_extensions": "Reload Extensions",
                    "extensions_reloaded": "Extensions reloaded.",
                    "plugin_unloaded": "Plugin unloaded."
                },
                "tooltip": {
                    "analyze_func": "Perform non-blocking AI analysis of the current function and its call chain",
                    "analyze_selection": "Perform non-blocking AI analysis of the currently selected code range",
                    "custom_query": "Ask a question without any code context",
                    "set_depth": "Set the depth of recursive code analysis",
                    "set_prompt": "Customize the prompt used for function analysis",
                    "reload_config": "Reload plugin configuration from file",
                    "stop_task": "Force stop the current AI analysis task",
                    "switch_language": "Switch interface and AI reply language",
                    "toggle_output_view": "Toggle the NexusAI output window (Ctrl+Shift+K)",
                    "reload_extensions": "Reload Extensions"
                }
            }
        },
        "aimcp_max_iterations": 10
    }

    def __new__(cls):
        """
        Ensures that only one instance of ConfigManager is created.

        Returns:
            ConfigManager: The singleton instance of the ConfigManager.
        """
        """
        确保只创建一个 ConfigManager 实例。

        返回:
            ConfigManager: ConfigManager 的单例实例。
        """
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(ConfigManager, cls).__new__(cls)
                cls._instance._initialize()
            return cls._instance

    def _initialize(self):
        """
        Initializes the ConfigManager instance.

        Sets up the configuration path, loads the configuration,
        and initializes the OpenAI client.
        """
        """
        初始化 ConfigManager 实例。

        设置配置路径，加载配置，并初始化 OpenAI 客户端。
        """
        self.script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.config_path = os.path.join(self.script_dir, 'Config', 'NexusAI.json')
        self.config = {}  # 初始化空配置
        self.output_view = None  # 持有UI视图的引用
        self.openai_client = None  # 初始化空客户端

        # --------------------------------------------------------------
        # 历史管理：在插件根目录创建 History 文件夹
        # --------------------------------------------------------------
        self.history_manager = HistoryManager(Path(self.script_dir))

        # 占位，确保 load_config 期间 show_message 可安全使用
        self.history: list = []

        # 读取配置（可能包含 last_session_name）
        self.load_config()

        last_session_name = self.config.get("last_session_name")
        try:
            if last_session_name:
                self.history_manager.load_session(last_session_name, create_if_missing=True)
            else:
                self.history_manager.create_new_session()
        except Exception:
            # 回退：创建新会话
            self.history_manager.create_new_session()

        # 将初始化阶段暂存的消息合并到持久化历史中
        temp_history = getattr(self, "history", [])
        self.history = self.history_manager.current  # type: ignore
        if temp_history:
            self.history.extend(temp_history)

        self.welcome_shown = False
        
        # 确保提示词与当前语言匹配
        current_lang = self.language
        if "prompts" in self.config and current_lang in self.config["prompts"] and "system" in self.config["prompts"][current_lang]:
            # 如果提示词与语言不匹配，更新提示词
            if self.config.get("prompt") != self.config["prompts"][current_lang]["system"]:
                self.config["prompt"] = self.config["prompts"][current_lang]["system"]
                self.save_config()
                self.show_message("prompt_updated", current_lang)
                
        self._create_openai_client() # 创建客户端

    def set_output_view(self, view):
        """
        Sets the output view for displaying messages.

        Args:
            view (object): The view object to be used for output.
                         This object must have a `print_message` method.
        """
        """
        设置用于显示消息的输出视图。

        参数:
            view (object): 用于输出的视图对象。
                         该对象必须具有 `print_message` 方法。
        """
        self.output_view = view
        if view:
            self.replay_history()

    def replay_history(self):
        """
        Replays the message history to the newly attached output view.
        """
        """
        将消息历史记录重播到新附加的输出视图。
        """
        if not self.output_view:
            return
        
        for method, txt in self.history:
            if method == "markdown":
                self.output_view.append_markdown(txt)
            else:
                self.output_view.append_text(txt)

    def get_message(self, key, *args):
        """
        Retrieves a formatted message string from the configuration.
        
        Args:
            key (str): The key of the message template in the config.
                       Can be a dot-separated path for nested keys (e.g., "menu_texts.menu_title").
            *args: Arguments to format the message string.
            
        Returns:
            str: The formatted message string or a key-not-found error message.
        """
        """
        从配置中检索格式化后的消息字符串。

        参数:
            key (str): 配置中消息模板的键。
                       可以是点分隔的路径以访问嵌套键 (例如 "menu_texts.menu_title")。
            *args: 用于格式化消息字符串的参数。

        返回:
            str: 格式化后的消息字符串或键未找到的错误消息。
        """
        current_lang = self.language
        
        try:
            messages = self.config.get("messages", {}).get(current_lang, {})
            
            # support nested key like "menu_texts.menu_title"
            # 支持像 "menu_texts.menu_title" 这样的嵌套键
            keys = key.split('.')
            value = messages
            for k in keys:
                value = value[k]

            message_template = value
            return message_template.format(*args) if args else message_template
        except KeyError:
            return f"[Message not found for key: {key}]"
        except Exception as e:
            return f"[Error retrieving message for key: {key}]: {e}"
            
    def show_message(self, key, *args):
        """
        Displays a message in the output view.

        If the output view is not set, the message is printed to the IDA console.
        
        Args:
            key (str): The key of the message template in the config.
            *args: Arguments to format the message string.
        """
        """
        在输出视图中显示一条消息。

        如果未设置输出视图，消息将被打印到 IDA 控制台。

        参数:
            key (str): 配置中消息模板的键。
            *args: 用于格式化消息字符串的参数。
        """
        message_text = self.get_message(key, *args)
        
        # 如果富文本窗口存在，则将消息发送到该窗口
        if self.output_view:
            # 对于特定消息，我们希望以Markdown格式显示
            if key in ("markdown_not_found", "welcome_message"):
                self.output_view.append_markdown(message_text)
                self.history.append(("markdown", message_text))
                if key == "welcome_message":
                    self.welcome_shown = True
            else:
                self.output_view.append_text(message_text)
                self.history.append(("text", message_text))
        else:
            # 如果输出视图不可用，将消息存储在历史记录中，以便在视图可用时显示
            self.history.append(("markdown" if key in ("markdown_not_found", "welcome_message") else "text", message_text))
            if key == "welcome_message":
                self.welcome_shown = True
            # 不再使用idaapi.msg，而是在适当的时候将消息显示在NexusAI窗口中

    def show_empty_line(self):
        """Displays an empty line in the output view."""
        """在输出视图中显示一个空行。"""
        if self.output_view:
            self.output_view.append_text("")
        # 记录空行到历史，以便窗口重新打开时能够 1:1 还原原始布局
        self.history.append(("text", ""))

    def start_stream_response(self):
        """
        Notifies the output view that a streaming response is starting.
        """
        """
        通知输出视图流式响应即将开始。
        """
        if self.output_view:
            self.output_view.mark_stream_start()

    def finalize_stream_response(self, markdown_text):
        """
        Finalizes the streaming response in the output view.

        Args:
            markdown_text (str): The complete markdown text of the response.
        """
        """
        在输出视图中完成流式响应。

        参数:
            markdown_text (str): 响应的完整 markdown 文本。
        """
        if self.output_view:
            self.output_view.finalize_stream(markdown_text)
            # 追加一个空 div 以结束 Markdown 列表或段落样式，防止影响后续消息
            self.output_view.append_text("<div style='margin: 0; padding: 0;'></div>")
        self.history.append(("markdown", markdown_text))

    def show_stream_chunk(self, chunk):
        """
        Displays a chunk of a streaming response in the output view.

        Args:
            chunk (str): The chunk of text to display.
        """
        """
        在输出视图中显示流式响应的数据块。

        参数:
            chunk (str): 要显示的文本块。
        """
        if self.output_view:
            self.output_view.append_stream_chunk(chunk)
            # 流式块不记录历史，最终Markdown会记录
        else:
            # 如果窗口不存在，则回退到在IDA输出窗口中打印
            # 使用sys.stdout以避免msg自动添加换行符
            sys.stdout.write(chunk)
            sys.stdout.flush()
            # 不记录

    def load_config(self):
        """
        Loads the configuration from the JSON file.

        If the file doesn't exist, it creates one with default settings.
        If the file is malformed, it reports an error.
        It also ensures that all default keys are present in the loaded config.
        """
        """
        从 JSON 文件加载配置。

        如果文件不存在，则使用默认设置创建一个。
        如果文件格式不正确，则报告错误。
        它还确保加载的配置中存在所有默认键。
        """
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    self.config = json.load(f)
                self._ensure_default_config() # 确保所有默认键都存在
                self.show_message("config_load_success", self.config_path)
            else:
                self.config = self.DEFAULT_CONFIG
                self.show_message("config_not_found", self.config_path)
                self.save_config()
        except json.JSONDecodeError as e:
            self.config = self.DEFAULT_CONFIG
            self.show_message("config_format_error", str(e))
            self.save_config()
        except Exception as e:
            self.config = self.DEFAULT_CONFIG
            self.show_message("config_load_error", str(e))

    def _ensure_default_config(self):
        """
        Ensures the current configuration contains all default keys.

        This method recursively updates the loaded configuration with any
        missing keys from the default configuration, preserving existing values.
        """
        """
        确保当前配置包含所有默认键。

        此方法会递归地使用默认配置中的任何缺失键来更新已加载的配置，
        同时保留现有值。
        """
        updated = [False]
        def recurse_update(d, u):
            nonlocal updated
            for k, v in u.items():
                if isinstance(v, dict):
                    # 如果当前值不是字典或键不存在，则创建一个新字典
                    node = d.get(k)
                    if not isinstance(node, dict):
                        node = {}
                        d[k] = node
                    recurse_update(node, v)
                elif k not in d:
                    d[k] = v
                    updated[0] = True
            return d

        recurse_update(self.config, self.DEFAULT_CONFIG)

        if updated[0]:
            self.show_message("config_updated")
            self.save_config()

    def save_config(self):
        """
        Saves the current configuration to the JSON file.
        """
        """
        将当前配置保存到 JSON 文件。
        """
        try:
            # 使用 indent=4 使JSON文件更易读
            with open(self.config_path, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=4, ensure_ascii=False)
            self.show_message("config_save_success", self.config_path)
        except IOError as e:
            self.show_message("config_save_error", str(e))

    def reload_config(self):
        """
        Reloads the configuration from the file and re-initializes the client.
        """
        """
        从文件重新加载配置并重新初始化客户端。
        """
        self.show_message("reload_config")
        # 保存当前语言
        old_lang = self.language
        self.load_config()
        # 确保提示词与语言匹配
        current_lang = self.language
        if current_lang != old_lang or "prompts" in self.config and current_lang in self.config["prompts"] and "system" in self.config["prompts"][current_lang]:
            # 如果语言发生变化或者提示词需要更新
            if "prompts" in self.config and current_lang in self.config["prompts"] and "system" in self.config["prompts"][current_lang]:
                self.config["prompt"] = self.config["prompts"][current_lang]["system"]
                self.save_config()
        self._create_openai_client()
        self.show_message("reload_complete", self.language, self.analysis_depth, self.model_name)

    def _create_openai_client(self):
        """
        Creates and configures the OpenAI client.

        Uses settings from the loaded configuration. If the API key is missing
        or still set to the default, an error is shown.
        """
        """
        创建并配置 OpenAI 客户端。

        使用从加载的配置中的设置。如果 API 密钥缺失或仍为默认值，
        则会显示错误。
        """
        api_key = self.config.get("openai", {}).get("api_key", "YOUR_API_KEY")
        base_url = self.config.get("openai", {}).get("base_url")
        proxy = self.config.get("openai", {}).get("proxy", "")

        if not api_key or api_key == "YOUR_API_KEY":
            self.show_message("api_key_not_set")
            self.openai_client = None
            return

        try:
            # 直接使用环境变量方式配置代理，避免自定义 http_client 阻断流式
            if proxy:
                import os
                os.environ["HTTP_PROXY"] = proxy
                os.environ["HTTPS_PROXY"] = proxy

            self.openai_client = OpenAI(
                api_key=api_key,
                base_url=base_url,
            )
            # 尝试发送一个小请求验证密钥和连接 (可选，但可以增加健壮性)
            # self.openai_client.models.list() # 可能会增加加载时间，暂时不加
            self.show_message("client_create_success")
        except Exception as e:
             self.openai_client = None
             self.show_message("client_create_error", str(e))
             # traceback.print_exc() # 打印详细错误堆栈 (可选)

    @property
    def model_name(self):
        """
        Gets the AI model name from the configuration.

        Returns:
            str: The name of the AI model.
        """
        """
        从配置中获取 AI 模型名称。

        返回:
            str: AI 模型的名称。
        """
        # 使用get方法提供默认值，防止key不存在
        return self.config.get("openai", {}).get("model", self.DEFAULT_CONFIG["openai"]["model"])

    @property
    def client(self):
        """
        Gets the OpenAI client instance.

        Returns:
            openai.OpenAI or None: The client instance or None if not initialized.
        """
        """
        获取 OpenAI 客户端实例。

        返回:
            openai.OpenAI or None: 客户端实例，如果未初始化则为 None。
        """
        if not self.openai_client:
             self._create_openai_client() # 尝试重新创建
        return self.openai_client

    @property
    def prompt(self):
        """
        Gets the system prompt for the current language.

        Returns:
            str: The system prompt.
        """
        """
        获取当前语言的系统提示。

        返回:
            str: 系统提示。
        """
        return self.config.get("prompt", self.DEFAULT_CONFIG["prompt"])

    @prompt.setter
    def prompt(self, value):
        """
        Sets the system prompt for the current language.

        Args:
            value (str): The new system prompt.
        """
        """
        设置当前语言的系统提示。

        参数:
            value (str): 新的系统提示。
        """
        if isinstance(value, str) and value.strip():
             self.config["prompt"] = value
             self.save_config()
             self.show_message("prompt_set")
        else:
             self.show_message("prompt_empty")

    @property
    def analysis_depth(self):
        """
        Gets the analysis depth from the configuration.

        Returns:
            int: The analysis depth. Defaults to 2 if not set or invalid.
        """
        """
        从配置中获取分析深度。

        返回:
            int: 分析深度。如果未设置或无效，则默认为 2。
        """
        # 确保返回的是整数，即使配置文件中是其他类型
        depth = self.config.get("analysis_depth", self.DEFAULT_CONFIG["analysis_depth"])
        try:
            return int(depth)
        except (ValueError, TypeError):
            default_depth = self.DEFAULT_CONFIG["analysis_depth"]
            self.show_message("depth_invalid", depth, default_depth)
            return default_depth

    @analysis_depth.setter
    def analysis_depth(self, value):
        """
        Sets the analysis depth in the configuration.

        Args:
            value (int or str): The new analysis depth. Must be a non-negative integer.
        """
        """
        在配置中设置分析深度。

        参数:
            value (int or str): 新的分析深度。必须是非负整数。
        """
        try:
            # 尝试转换为整数并验证非负
            int_value = int(value)
            if int_value >= 0:
                self.config["analysis_depth"] = int_value
                self.save_config()
            else:
                self.show_message("depth_negative")
        except (ValueError, TypeError):
            self.show_message("depth_not_int")

    @property
    def language(self):
        """
        Gets the current language from the configuration.

        Returns:
            str: The current language code (e.g., "zh_CN").
        """
        """
        从配置中获取当前语言。

        返回:
            str: 当前语言代码 (例如 "zh_CN")。
        """
        return self.config.get("language", self.DEFAULT_CONFIG["language"])
        
    @language.setter
    def language(self, value):
        """
        Sets the current language and updates the system prompt accordingly.

        Args:
            value (str): The new language code to set.
        """
        """
        设置当前语言并相应地更新系统提示。

        参数:
            value (str): 要设置的新语言代码。
        """
        if value in ["zh_CN", "en_US"]:
            old_lang = self.language
            # 如果语言发生变化
            if old_lang != value:
                self.config["language"] = value
                # 更新提示词，使用新语言的系统提示词
                if "prompts" in self.config and value in self.config["prompts"] and "system" in self.config["prompts"][value]:
                    self.config["prompt"] = self.config["prompts"][value]["system"]
                self.save_config()
                self.show_message("language_changed", value)
                # 发出语言已更改的信号
                event_bus.emit("language_changed")
        else:
            self.show_message("language_not_supported", value)

    @property
    def prompts(self):
        """
        Gets the dictionary of all prompts for the current language.

        Returns:
            dict: A dictionary of prompt templates.
        """
        """
        获取当前语言的所有提示字典。

        返回:
            dict: 提示模板的字典。
        """
        return self.config.get("prompts", self.DEFAULT_CONFIG["prompts"])
        
    def get_prompt_by_type(self, prompt_type):
        """
        Retrieves a specific type of prompt for the current language.
        
        Args:
            prompt_type (str): The type of prompt to retrieve (e.g., 'comment_function').
            
        Returns:
            str: The prompt template string, or an empty string if not found.
        """
        """
        检索当前语言的特定类型提示。

        参数:
            prompt_type (str): 要检索的提示类型 (例如 'comment_function')。

        返回:
            str: 提示模板字符串，如果未找到则返回空字符串。
        """
        current_lang = self.language
        
        # 首先尝试从当前语言的提示词中获取
        if current_lang in self.prompts and prompt_type in self.prompts[current_lang]:
            return self.prompts[current_lang][prompt_type]
        
        # 如果当前语言没有对应类型的提示词，尝试从顶层获取
        if prompt_type in self.prompts:
            # 添加语言提示
            prompt = self.prompts[prompt_type]
            lang_indicator = "请用中文回复" if current_lang == "zh_CN" else "Please reply in English"
            return f"{prompt} {lang_indicator}"
        
        # 如果都没有，返回默认系统提示词
        if current_lang in self.prompts and "system" in self.prompts[current_lang]:
            return self.prompts[current_lang]["system"]
        
        # 最后的回退，返回配置的通用提示词
        return self.prompt 

    @property
    def analysis_options(self):
        """
        Gets the analysis options from the configuration.

        Returns:
            dict: A dictionary of analysis options.
        """
        """
        从配置中获取分析选项。

        返回:
            dict: 分析选项的字典。
        """
        return self.config.get("analysis_options", {
            "include_type_definitions": True,
            "include_xrefs": True
        })

    @property
    def aimcp_enabled(self):
        """
        Checks if the AIMCP feature is enabled.

        Returns:
            bool: True if AIMCP is enabled, False otherwise.
        """
        """
        检查 AIMCP 功能是否已启用。

        返回:
            bool: 如果启用 AIMCP，则为 False。
        """
        return self.config.get("aimcp_enabled", False)
    
    @property
    def aimcp_max_iterations(self):
        """
        Gets the maximum number of iterations for AIMCP.

        Returns:
            int: The maximum number of iterations.
        """
        """
        获取 AIMCP 的最大迭代次数。

        返回:
            int: 最大迭代次数。
        """
        return self.config.get("aimcp_max_iterations", 10)

    def apply_settings(self, new_settings):
        """
        Applies a dictionary of new settings to the configuration.

        This method updates the configuration with the provided settings,
        saves the changes, and reloads the config to apply them.

        Args:
            new_settings (dict): A dictionary of settings to apply.
                                 Keys should match the structure of the config file.
        """
        """
        将新的设置字典应用于配置。

        此方法使用提供的设置更新配置，保存更改，并重新加载配置以应用它们。

        参数:
            new_settings (dict): 要应用的设置字典。
                                 键应与配置文件的结构匹配。
        """
        # 备份旧的快捷键设置，用于检测变更
        old_shortcuts = self.config.get("shortcuts", {}).copy()
        # 备份旧的语言设置，用于检测变更
        old_language = self.config.get("language", "zh_CN")
        
        # 更新配置
        self.config.update(new_settings)
        self.save_config()
        
        # 检查快捷键是否有变更
        new_shortcuts = self.config.get("shortcuts", {})
        shortcuts_changed = old_shortcuts != new_shortcuts
        
        # 检查语言是否有变更
        new_language = self.config.get("language", "zh_CN")
        language_changed = old_language != new_language
        
        # 如果快捷键有变更，发射信号
        if shortcuts_changed:
            try:
                # 更新IDA动作系统中的快捷键
                from ..Core.plugin import NexusAIPlugin
                instance = NexusAIPlugin.get_instance()
                if instance:
                    # 更新切换窗口快捷键
                    toggle_sc = new_shortcuts.get("toggle_output", "Ctrl+Shift+K")
                    idaapi.update_action_shortcut(NexusAIPlugin.ACTION_TOGGLE_OUTPUT_VIEW, toggle_sc)
                    
                    # 更新注释快捷键
                    action_shortcut_map = {
                        NexusAIPlugin.ACTION_COMMENT_FUNCTION: new_shortcuts.get("comment_function", "Ctrl+Shift+A"),
                        NexusAIPlugin.ACTION_COMMENT_LINE: new_shortcuts.get("comment_line", "Ctrl+Shift+S"),
                        NexusAIPlugin.ACTION_COMMENT_REPEATABLE: new_shortcuts.get("comment_repeatable", "Ctrl+Shift+D"),
                        NexusAIPlugin.ACTION_COMMENT_ANTERIOR: new_shortcuts.get("comment_anterior", "Ctrl+Shift+W"),
                    }
                    
                    for action_id, shortcut in action_shortcut_map.items():
                        idaapi.update_action_shortcut(action_id, shortcut)
                        
                    idaapi.msg("[NexusAI] 快捷键已更新\n")
            except Exception as e:
                idaapi.msg(f"[NexusAI] 更新快捷键失败: {e}\n")
                
            # 发射快捷键变更信号
            event_bus.emit("shortcuts_changed")
            
        # 如果语言有变更，立即更新语言设置并发射信号
        if language_changed:
            self.language = new_language  # 这会触发language_changed信号
            # 确保提示词与语言匹配
            if "prompts" in self.config and new_language in self.config["prompts"] and "system" in self.config["prompts"][new_language]:
                self.config["prompt"] = self.config["prompts"][new_language]["system"]
                self.save_config() 

    # ------------------------------------------------------------------
    # 历史会话相关辅助
    # ------------------------------------------------------------------
    def switch_session(self, session_name: str):
        """切换到指定会话并刷新 UI。"""
        try:
            self.history_manager.load_session(session_name, create_if_missing=False)
            self.history = self.history_manager.current  # type: ignore
            # 更新配置并持久化
            self.config["last_session_name"] = session_name
            self.save_config()
            # 若 UI 已打开，则刷新
            if self.output_view:
                self.output_view.clear()
                self.replay_history()
            # 触发会话变更事件，通知历史对话窗口刷新
            event_bus.emit("session_changed")
        except Exception as e:
            self.show_message("config_load_error", str(e))

    def create_new_session(self):
        """开始新对话 (新会话)。"""
        new_history = self.history_manager.create_new_session()
        self.history = new_history  # type: ignore
        self.config["last_session_name"] = new_history._meta["name"]
        self.save_config()
        # 刷新 UI
        if self.output_view:
            self.output_view.clear()
            self.replay_history()
        # 触发会话变更事件，通知历史对话窗口刷新
        event_bus.emit("session_changed")



