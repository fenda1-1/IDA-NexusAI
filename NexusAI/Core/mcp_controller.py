"""mcp_controller

核心自动化控制器，负责：
1. 接收 AIMCP 主题任务 (theme)，分析为子 action 列表。
2. 调用 `mcp_functions.mcp_call` 执行具体 IDA 操作。
3. 将执行结果拼装上下文，交给 AIService 继续对话 (ReAct 风格)。

Core automation controller, responsible for:
1. Receiving AIMCP theme tasks and analyzing them into sub-action lists.
2. Calling `mcp_functions.mcp_call` to execute specific IDA operations.
3. Assembling the execution results into context and passing them to AIService for continued dialogue (ReAct style).
"""
from __future__ import annotations

import json
import threading
import time
from typing import List
import re
from pathlib import Path

from ..Config.config import ConfigManager
from ..AIService.base_service import BaseAIService
from .mcp_functions import mcp_call
from ..Core.event_bus import get_event_bus
from ..Utils.mcp_task_manager import get_task_manager


class MCPTaskStatus:
    """任务状态枚举 / Task status constants."""

    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    ERROR = "error"
    CANCELLED = "cancelled"


class MCPTask:
    """MCP 任务结构 / Lightweight task record."""

    def __init__(self, theme: str):
        self.theme = theme
        self.status = MCPTaskStatus.PENDING
        self.result = ""
        self.error = ""


class MCPController:
    """自动化流程控制器 / Main automation controller.

    • **CN**：负责把高阶 *主题* 拆分为多轮 action 调用，并与 LLM 交互。
    • **EN**: Splits a high-level *theme* into multiple action invocations and
      converses with the LLM in a ReAct-like loop.
    """

    def __init__(self, config: ConfigManager, ai_service: BaseAIService):
        self.config = config
        self.ai_service = ai_service
        self._task_lock = threading.Lock()
        self.current_task: MCPTask | None = None
        if self.config.config.get("aimcp_limit_iters_enabled", False):
            self.max_iters = max(1, int(self.config.config.get("aimcp_max_iters", 5)))
        else:
            self.max_iters = 999999
        self.allowed_actions = list(mcp_call.__globals__["action_registry"].keys())
        self.cancel_event = threading.Event()

        # 初始化任务管理器
        config_dir = Path(config.script_dir) / "Config"
        self.task_manager = get_task_manager(config_dir)
        self.current_task_id = None

        get_event_bus().on("aimcp_toggle", self._on_toggle)

    def _on_toggle(self, state: bool):
        """UI 开关事件处理 / Handle UI toggle event."""
        if not state and self.current_task and self.current_task.status == MCPTaskStatus.RUNNING:
            self.cancel_event.set()
            if hasattr(self.ai_service, "stop_event"):
                self.ai_service.stop_event.set()
            self.config.show_message("aimcp_cancelled")

    def start(self, theme: str):
        """启动新任务 / Submit new theme asynchronous."""
        if self.config.config.get("aimcp_limit_iters_enabled", False):
            self.max_iters = max(1, int(self.config.config.get("aimcp_max_iters", 5)))
        else:
            self.max_iters = 999999
        if not self._task_lock.acquire(blocking=False):
            self.config.show_message("task_in_progress")
            return

        # 创建持久化任务记录
        model_config = {
            "api_base_url": getattr(self.ai_service, 'base_url', ''),
            "model_name": getattr(self.ai_service, 'model', ''),
            "api_key": getattr(self.ai_service, 'api_key', '')[:10] + "..." if hasattr(self.ai_service, 'api_key') else ''
        }

        self.current_task_id = self.task_manager.create_task(theme, model_config)
        self.task_manager.add_conversation_entry(self.current_task_id, "user_input", theme)

        self.current_task = MCPTask(theme)
        t = threading.Thread(target=self._run_task, daemon=True)
        t.start()

    def _run_task(self):
        """后台线程：执行交互循环 / Worker thread running the dialogue loop."""
        assert self.current_task is not None
        self.current_task.status = MCPTaskStatus.RUNNING

        # 更新任务状态
        if self.current_task_id:
            self.task_manager.update_task_status(self.current_task_id, "running")

        try:
            iteration = 0
            conversation_context = ""
            while iteration < self.max_iters and not self.cancel_event.is_set():
                iteration += 1
                arg_table = {
                    "list_funcs": "pattern?, limit?",
                    "get_decomp": "ea|address|func_addr",
                    "export_callgraph": "root_ea, depth?",
                    "disassemble": "address, count?",
                    "get_string_at_address": "address",
                    "analyze_cross_references": "address|ea|func_addr, ref_type?(code|data), limit?",
                    "list_strings": "pattern?, limit?",
                    "get_program_metadata": "",
                    "get_binary_entry_points": "",
                    "get_function_info_by_name": "func_name",
                    "get_function_info_by_address": "address|ea",
                    "get_current_function_info": "",
                    "get_current_cursor_address": "",
                    "search_strings_in_binary": "pattern, case_sensitive?, unicode?, limit?",
                    "list_imports": "pattern?, limit?",
                    "list_exports": "pattern?, limit?",
                    "list_local_vars": "function_address|ea, limit?",
                    "set_address_comment": "address|ea, comment_text, repeatable?",
                    "rename_func": "address|ea, new_name",
                    "rename_local_var": "function_address|ea, variable_offset, new_name",
                    "rename_global_var": "address|ea, new_name",
                    "set_local_var_type": "function_address|ea, variable_offset, type_string, arg_index?",
                    "set_global_var_type": "address|ea, type_string",
                    "set_func_prototype": "address|ea, prototype_string",
                    "declare_custom_c_type": "type_definition_string",
                }

                action_help = "; ".join(f"{k}({v})" for k, v in arg_table.items())

                base_prompt = (
                    "你是逆向分析专家，具备调用 MCP 工具链的能力。"
                    " 每次回复只能有两种形式之一:\n"
                    " 1) JSON 数组: 包含若干 {\"action\", \"args\"} 对象，用于执行二进制分析命令；\n"
                    " 2) [\"DONE\"]: 当不需要进一步动作、分析结束时。\n"
                    f"可用 action 及参数: {action_help}.\n"
                    "\n⚠️ 重要格式要求:\n"
                    "- 回复必须是纯JSON格式，不要添加解释文字\n"
                    "- 如需解释，请在JSON数组前简要说明，然后换行输出JSON\n"
                    "- JSON必须使用双引号，不能使用单引号\n"
                    "- 确保JSON语法正确，括号匹配\n"
                    "\n📋 JSON格式示例:\n"
                    "单个动作:\n"
                    "[{\"action\": \"get_decomp\", \"args\": {\"ea\": \"0x140002F60\"}}]\n"
                    "\n多个动作:\n"
                    "[\n"
                    "  {\"action\": \"get_current_cursor_address\", \"args\": {}},\n"
                    "  {\"action\": \"list_funcs\", \"args\": {\"pattern\": \"main\", \"limit\": 10}}\n"
                    "]\n"
                    "\n结束分析:\n"
                    "[\"DONE\"]\n"
                    "\n参数要求: \n"
                    "  • 所有地址/ea/func_addr 必须是十六进制字符串 (如 \"0x140123ABC\") 或整数, 禁止使用符号表达式。\n"
                    "  • 析构函数在符号表中通常带有 '~'，例如 \"LoadLevelLimiter::~LoadLevelLimiter\"，搜索时务必包含 '~'。\n"
                    "  • 每个动作对象必须包含 \"action\" 和 \"args\" 字段。\n"
                    "  • args 必须是对象 {}，即使为空也要写成 {\"args\": {}}。\n"
                    "\n回复格式:\n"
                    " 先简要说明本轮分析结果与下一步计划，然后输出 JSON 指令数组。"
                    " ⚠️ 解释部分禁止出现 '[' 字符；解释完毕后紧跟一个换行再写 JSON 数组。"
                    " JSON 数组必须严格符合上述示例格式，无多余字段；"
                    " 当需要批量操作地址时，单次回复中的 action 数量不得超过 20，"
                    " 如需更多请分批执行；大量字符串查询请优先使用 list_strings / pattern/limit。"
                )
                prompt = (
                    base_prompt
                    + f"\n用户主题: {self.current_task.theme}"
                    + (f"\n\n已知上下文:\n{conversation_context}" if conversation_context else "")
                )

                result_container: List[str] = []
                orig_append = (
                    self.config.show_stream_chunk if hasattr(self.config, "show_stream_chunk") else None
                )
                if orig_append:
                    self.config.show_stream_chunk = lambda x: result_container.append(x)  # type: ignore

                self.ai_service.query_stream(prompt)

                if self.cancel_event.is_set():
                    break

                if orig_append:
                    self.config.show_stream_chunk = orig_append  # type: ignore

                full_resp = "".join(result_container).strip()
                if not full_resp:
                    raise ValueError("LLM 空回复")

                # 记录AI回复到任务管理器
                if self.current_task_id:
                    self.task_manager.add_conversation_entry(
                        self.current_task_id, "ai_response", full_resp
                    )

                if full_resp.strip().upper().startswith("DONE"):
                    break

                json_fragment = self._extract_json_array(full_resp)
                if json_fragment is None:
                    # 尝试更智能的JSON提取
                    # Try smarter JSON extraction
                    json_fragment = self._smart_extract_json(full_resp)

                if json_fragment is None:
                    # 提供更详细的错误信息和调试帮助
                    # Provide more detailed error information and debugging help
                    debug_info = self._analyze_response_format(full_resp)
                    raise ValueError(
                        f"无法在回复中找到 JSON 指令数组。\n"
                        f"调试信息: {debug_info}\n"
                        f"回复示例: {full_resp[:300]}..."
                    )
                try:
                    # 检查并修复JSON中的重复键问题
                    # Check and fix duplicate key issues in JSON
                    cleaned_json = self._fix_duplicate_keys(json_fragment)
                    actions = json.loads(cleaned_json)
                except Exception as parse_e:
                    raise ValueError(
                        f"JSON 解析失败: {parse_e}\n提取内容: {json_fragment}"
                    ) from parse_e

                if not isinstance(actions, list):
                    raise ValueError("LLM response 不是 JSON 数组")

                if len(actions) == 1:
                    single = actions[0]
                    if (
                        (isinstance(single, str) and single.strip().upper() == "DONE") or
                        (isinstance(single, dict) and str(single.get("action", "")).strip().upper() == "DONE")
                    ):
                        break

                aggregated = []
                for action_item in actions:
                    action = action_item.get("action")
                    args = action_item.get("args", {})

                    # 验证参数格式 / Validate argument format
                    if not isinstance(args, dict):
                        error_msg = f"Invalid args format for action '{action}': expected dict, got {type(args).__name__}. Value: {args}"
                        res = {"success": False, "error": error_msg}
                        print(f"MCP Error: {error_msg}")
                    else:
                        res = mcp_call(action, **args)

                    aggregated.append({"request": action_item, "response": res})

                step_result_str = json.dumps(aggregated, ensure_ascii=False, indent=2)
                conversation_context += f"\n# Iteration {iteration} result:\n{step_result_str}\n"

                # 记录到任务管理器
                if self.current_task_id:
                    self.task_manager.add_conversation_entry(
                        self.current_task_id, "action_result", step_result_str
                    )
                    self.task_manager.update_task_iterations(self.current_task_id, iteration)

                if self.config.output_view:
                    self.config.output_view.append_markdown(
                        f"### Iteration {iteration} result\n```json\n{step_result_str}\n```"
                    )
                self.config.history.append((
                    "markdown",
                    f"### Iteration {iteration} result\n```json\n{step_result_str}\n```"
                ))

                if not actions:
                    break
            if self.cancel_event.is_set():
                self.current_task.status = MCPTaskStatus.CANCELLED
                if self.current_task_id:
                    self.task_manager.update_task_status(self.current_task_id, "cancelled")
            else:
                self.current_task.status = MCPTaskStatus.DONE
                if self.current_task_id:
                    self.task_manager.update_task_status(self.current_task_id, "done")
            self.current_task.result = conversation_context
        except Exception as e:  # noqa: BLE001
            self.current_task.status = MCPTaskStatus.ERROR
            self.current_task.error = str(e)
            if self.current_task_id:
                self.task_manager.update_task_status(self.current_task_id, "error", str(e))
                self.task_manager.add_conversation_entry(self.current_task_id, "error", str(e))
            self.config.show_message("task_execution_error", str(e))
        finally:
            self._task_lock.release()

    def continue_task(self, task_id: str, theme: str, context: str = ""):
        """继续未完成的任务 / Continue an incomplete task."""
        if not self._task_lock.acquire(blocking=False):
            self.config.show_message("task_in_progress")
            return

        # 获取任务记录
        task_record = self.task_manager.get_task(task_id)
        if not task_record:
            self._task_lock.release()
            raise ValueError(f"Task {task_id} not found")

        # 更新当前任务ID
        self.current_task_id = task_id

        # 更新模型配置（如果有变化）
        if task_record.model_config:
            model_config = task_record.model_config
            if hasattr(self.ai_service, 'base_url') and model_config.get('api_base_url'):
                self.ai_service.base_url = model_config['api_base_url']
            if hasattr(self.ai_service, 'model') and model_config.get('model_name'):
                self.ai_service.model = model_config['model_name']

        # 记录继续任务的操作
        self.task_manager.add_conversation_entry(task_id, "system", f"继续任务: {theme}")

        # 创建新的MCPTask实例
        self.current_task = MCPTask(theme)

        # 启动任务线程
        t = threading.Thread(target=self._run_continue_task, args=(context,), daemon=True)
        t.start()

    def _run_continue_task(self, context: str):
        """运行继续的任务 / Run continued task."""
        assert self.current_task is not None
        self.current_task.status = MCPTaskStatus.RUNNING

        # 更新任务状态
        if self.current_task_id:
            self.task_manager.update_task_status(self.current_task_id, "running")

        try:
            # 获取任务记录以确定当前迭代次数
            task_record = self.task_manager.get_task(self.current_task_id)
            start_iteration = task_record.iterations if task_record else 0

            iteration = start_iteration
            conversation_context = context

            while iteration < self.max_iters and not self.cancel_event.is_set():
                iteration += 1

                # 使用相同的逻辑继续任务（复用_run_task中的逻辑）
                # 这里可以调用_run_task的核心逻辑，但需要传入上下文
                # 为了简化，我们直接在这里实现核心逻辑

                arg_table = {
                    "list_funcs": "pattern?, limit?",
                    "get_decomp": "ea|address|func_addr",
                    "export_callgraph": "root_ea, depth?",
                    "disassemble": "address, count?",
                    "get_string_at_address": "address",
                    "analyze_cross_references": "address|ea|func_addr, ref_type?(code|data), limit?",
                    "list_strings": "pattern?, limit?",
                    "get_program_metadata": "",
                    "get_binary_entry_points": "",
                    "get_function_info_by_name": "func_name",
                    "get_function_info_by_address": "address|ea",
                    "get_current_function_info": "",
                    "get_current_cursor_address": "",
                    "search_strings_in_binary": "pattern, case_sensitive?, unicode?, limit?",
                    "list_imports": "pattern?, limit?",
                    "list_exports": "pattern?, limit?",
                    "list_local_vars": "function_address|ea, limit?",
                    "set_address_comment": "address|ea, comment_text, repeatable?",
                    "rename_func": "address|ea, new_name",
                    "rename_local_var": "function_address|ea, variable_offset, new_name",
                    "rename_global_var": "address|ea, new_name",
                    "set_local_var_type": "function_address|ea, variable_offset, type_string, arg_index?",
                    "set_global_var_type": "address|ea, type_string",
                    "set_func_prototype": "address|ea, prototype_string",
                    "declare_custom_c_type": "type_definition_string",
                }

                action_help = "; ".join(f"{k}({v})" for k, v in arg_table.items())

                base_prompt = (
                    "你是逆向分析专家，具备调用 MCP 工具链的能力。"
                    " 每次回复只能有两种形式之一:\n"
                    " 1) JSON 数组: 包含若干 {\"action\", \"args\"} 对象，用于执行二进制分析命令；\n"
                    " 2) [\"DONE\"]: 当不需要进一步动作、分析结束时。\n"
                    f"可用 action 及参数: {action_help}.\n"
                    "\n⚠️ 重要格式要求:\n"
                    "- 回复必须是纯JSON格式，不要添加解释文字\n"
                    "- 如需解释，请在JSON数组前简要说明，然后换行输出JSON\n"
                    "- JSON必须使用双引号，不能使用单引号\n"
                    "- 确保JSON语法正确，括号匹配\n"
                    "\n📋 JSON格式示例:\n"
                    "单个动作:\n"
                    "[{\"action\": \"get_decomp\", \"args\": {\"ea\": \"0x140002F60\"}}]\n"
                    "\n多个动作:\n"
                    "[\n"
                    "  {\"action\": \"get_current_cursor_address\", \"args\": {}},\n"
                    "  {\"action\": \"list_funcs\", \"args\": {\"pattern\": \"main\", \"limit\": 10}}\n"
                    "]\n"
                    "\n结束分析:\n"
                    "[\"DONE\"]\n"
                    "\n参数要求: \n"
                    "  • 所有地址/ea/func_addr 必须是十六进制字符串 (如 \"0x140123ABC\") 或整数, 禁止使用符号表达式。\n"
                    "  • 析构函数在符号表中通常带有 '~'，例如 \"LoadLevelLimiter::~LoadLevelLimiter\"，搜索时务必包含 '~'。\n"
                    "  • 每个动作对象必须包含 \"action\" 和 \"args\" 字段。\n"
                    "  • args 必须是对象 {}，即使为空也要写成 {\"args\": {}}。\n"
                    "\n回复格式:\n"
                    " 可以先简要说明本轮分析结果与下一步计划，然后输出 JSON 指令数组。"
                    " ⚠️ 如有解释文字，解释完毕后必须换行再写 JSON 数组。"
                    " JSON 数组必须严格符合上述示例格式，无多余字段；"
                    " 当需要批量操作地址时，单次回复中的 action 数量不得超过 20，"
                    " 如需更多请分批执行；大量字符串查询请优先使用 list_strings / pattern/limit。"
                )

                prompt = f"{base_prompt}\n\n# 当前任务:\n{self.current_task.theme}\n\n# 上下文:\n{conversation_context}"

                result_container = []
                orig_append = self.config.show_stream_chunk

                def append_chunk(chunk: str):
                    result_container.append(chunk)
                    if orig_append:
                        orig_append(chunk)

                self.config.show_stream_chunk = append_chunk

                self.ai_service.query_stream(prompt)

                if self.cancel_event.is_set():
                    break

                if orig_append:
                    self.config.show_stream_chunk = orig_append

                full_resp = "".join(result_container).strip()
                if not full_resp:
                    raise ValueError("LLM 空回复")

                # 记录AI回复到任务管理器
                if self.current_task_id:
                    self.task_manager.add_conversation_entry(
                        self.current_task_id, "ai_response", full_resp
                    )

                if full_resp.strip().upper().startswith("DONE"):
                    break

                json_fragment = self._extract_json_array(full_resp)
                if json_fragment is None:
                    json_fragment = self._smart_extract_json(full_resp)

                if json_fragment is None:
                    debug_info = self._analyze_response_format(full_resp)

                    # 提供更详细的错误信息和修复建议
                    error_msg = (
                        f"无法在回复中找到有效的 JSON 指令数组。\n\n"
                        f"调试信息: {debug_info}\n\n"
                        f"AI回复内容（前500字符）:\n{full_resp[:500]}...\n\n"
                        f"可能的原因:\n"
                        f"1. AI回复格式不正确，应该是纯JSON数组格式\n"
                        f"2. JSON语法错误（缺少引号、括号不匹配等）\n"
                        f"3. AI在JSON前添加了解释文本\n\n"
                        f"期望格式示例:\n"
                        f'[{{"action": "get_decomp", "args": {{"ea": "0x140001000"}}}}]\n'
                        f"或者:\n"
                        f'["DONE"]'
                    )
                    raise ValueError(error_msg)

                try:
                    cleaned_json = self._fix_duplicate_keys(json_fragment)
                    actions = json.loads(cleaned_json)
                except Exception as parse_e:
                    raise ValueError(
                        f"JSON 解析失败: {parse_e}\n提取内容: {json_fragment}"
                    ) from parse_e

                if actions == ["DONE"]:
                    break

                aggregated = []
                for action_item in actions:
                    action = action_item.get("action")
                    args = action_item.get("args", {})

                    if not isinstance(args, dict):
                        error_msg = f"Invalid args format for action '{action}': expected dict, got {type(args).__name__}. Value: {args}"
                        res = {"success": False, "error": error_msg}
                        print(f"MCP Error: {error_msg}")
                    else:
                        res = mcp_call(action, **args)

                    aggregated.append({"request": action_item, "response": res})

                step_result_str = json.dumps(aggregated, ensure_ascii=False, indent=2)
                conversation_context += f"\n# Iteration {iteration} result:\n{step_result_str}\n"

                # 记录到任务管理器
                if self.current_task_id:
                    self.task_manager.add_conversation_entry(
                        self.current_task_id, "action_result", step_result_str
                    )
                    self.task_manager.update_task_iterations(self.current_task_id, iteration)

                if self.config.output_view:
                    self.config.output_view.append_markdown(
                        f"### Iteration {iteration} result\n```json\n{step_result_str}\n```"
                    )
                self.config.history.append((
                    "markdown",
                    f"### Iteration {iteration} result\n```json\n{step_result_str}\n```"
                ))

                if not actions:
                    break

            if self.cancel_event.is_set():
                self.current_task.status = MCPTaskStatus.CANCELLED
                if self.current_task_id:
                    self.task_manager.update_task_status(self.current_task_id, "cancelled")
            else:
                self.current_task.status = MCPTaskStatus.DONE
                if self.current_task_id:
                    self.task_manager.update_task_status(self.current_task_id, "done")
            self.current_task.result = conversation_context
        except Exception as e:
            self.current_task.status = MCPTaskStatus.ERROR
            self.current_task.error = str(e)
            if self.current_task_id:
                self.task_manager.update_task_status(self.current_task_id, "error", str(e))
                self.task_manager.add_conversation_entry(self.current_task_id, "error", str(e))
            self.config.show_message("task_execution_error", str(e))
        finally:
            self._task_lock.release()

    def _extract_json_array(self, text: str):
        """提取 JSON 数组或对象 / Extract JSON array or object from raw LLM reply."""
        # 增强兼容性：处理多种格式的JSON标记
        # Enhanced compatibility: handle various JSON markup formats

        # 移除常见的代码块标记
        # Remove common code block markers
        text = re.sub(r'```json\s*', '', text, flags=re.IGNORECASE)
        text = re.sub(r'```\s*', '', text)
        text = re.sub(r'json\s*', '', text, flags=re.IGNORECASE)

        # 特殊处理：查找冒号或中文冒号后的JSON
        # Special handling: find JSON after colon (English or Chinese)
        colon_patterns = [
            r'[:：]\s*(\[.*?\])',  # 冒号后的数组
            r'[:：]\s*(\{.*?\})',  # 冒号后的对象
        ]

        for pattern in colon_patterns:
            matches = re.findall(pattern, text, re.DOTALL)
            for match in matches:
                try:
                    # 验证JSON格式
                    json.loads(match)
                    if match.startswith('['):
                        return match
                    else:
                        return f'[{match}]'  # 包装对象为数组
                except:
                    continue

        # 首先尝试查找JSON数组
        # First try to find JSON array
        array_result = self._extract_json_structure(text, '[', ']')
        if array_result:
            return array_result

        # 如果没有找到数组，尝试查找JSON对象并包装成数组
        # If no array found, try to find JSON object and wrap it as array
        object_result = self._extract_json_structure(text, '{', '}')
        if object_result:
            # 将单个对象包装成数组
            # Wrap single object as array
            return f'[{object_result}]'

        return None

    def _extract_json_structure(self, text: str, start_char: str, end_char: str):
        """提取JSON结构（数组或对象）/ Extract JSON structure (array or object)."""
        # 查找所有可能的JSON结构
        # Find all possible JSON structures
        candidates = []
        pos = 0

        while True:
            start = text.find(start_char, pos)
            if start == -1:
                break

            # 使用括号匹配算法提取完整的JSON结构
            # Use bracket matching algorithm to extract complete JSON structure
            depth = 0
            in_string = False
            escape_next = False

            for i in range(start, len(text)):
                c = text[i]

                if escape_next:
                    escape_next = False
                    continue

                if c == '\\':
                    escape_next = True
                    continue

                if c == '"' and not escape_next:
                    in_string = not in_string
                    continue

                if not in_string:
                    if c == start_char:
                        depth += 1
                    elif c == end_char:
                        depth -= 1
                        if depth == 0:
                            candidate = text[start:i+1]
                            # 验证是否包含action字段（有效的MCP指令）
                            # Validate if it contains action field (valid MCP instruction)
                            if self._is_valid_mcp_json(candidate):
                                candidates.append(candidate)
                            pos = i + 1
                            break
            else:
                # 如果没有找到匹配的结束字符，跳出循环
                break

        # 返回第一个有效的候选项
        # Return the first valid candidate
        return candidates[0] if candidates else None

    def _is_valid_mcp_json(self, json_text: str) -> bool:
        """验证是否为有效的MCP JSON指令 / Validate if it's a valid MCP JSON instruction."""
        try:
            parsed = json.loads(json_text)

            # 检查是否为数组
            if isinstance(parsed, list):
                # 特殊处理DONE指令
                if len(parsed) == 1 and parsed[0] == "DONE":
                    return True

                # 数组不能为空，且每个元素都应该有action字段
                return len(parsed) > 0 and all(isinstance(item, dict) and 'action' in item for item in parsed)

            # 检查是否为单个对象且包含action字段
            elif isinstance(parsed, dict):
                return 'action' in parsed

            return False

        except (json.JSONDecodeError, TypeError):
            return False

    def _analyze_response_format(self, text: str) -> str:
        """分析响应格式，提供调试信息 / Analyze response format for debugging."""
        info = []

        # 检查是否包含JSON标记
        if 'json' in text.lower():
            info.append("包含'json'标记")

        # 检查是否包含代码块标记
        if '```' in text:
            info.append("包含代码块标记(```)")

        # 检查是否包含方括号（数组）
        if '[' in text:
            bracket_pos = text.find('[')
            info.append(f"找到JSON数组'['在位置{bracket_pos}")

            # 检查方括号前的内容
            before_bracket = text[:bracket_pos].strip()
            if before_bracket:
                last_words = ' '.join(before_bracket.split()[-5:])
                info.append(f"'['前的内容: ...{last_words}")
        else:
            info.append("未找到JSON数组'['字符")

        # 检查是否包含右方括号
        if ']' in text:
            info.append("找到JSON数组']'字符")
        else:
            info.append("未找到JSON数组']'字符")

        # 检查是否包含大括号（对象）
        if '{' in text:
            brace_pos = text.find('{')
            info.append(f"找到JSON对象'{{'在位置{brace_pos}")

            # 检查大括号前的内容
            before_brace = text[:brace_pos].strip()
            if before_brace:
                last_words = ' '.join(before_brace.split()[-5:])
                info.append(f"'{{'前的内容: ...{last_words}")
        else:
            info.append("未找到JSON对象'{'字符")

        # 检查是否包含右大括号
        if '}' in text:
            info.append("找到JSON对象'}'字符")
        else:
            info.append("未找到JSON对象'}'字符")

        return "; ".join(info) if info else "无特殊标记"

    def _smart_extract_json(self, text: str) -> str:
        """智能JSON提取，处理各种格式 / Smart JSON extraction for various formats."""
        try:
            # 特殊处理：查找冒号后的JSON数组
            # Special handling: find JSON array after colon
            colon_pattern = r'[:：]\s*(\[.*\])'
            colon_match = re.search(colon_pattern, text, re.DOTALL)
            if colon_match:
                json_candidate = colon_match.group(1).strip()
                try:
                    # 验证JSON格式
                    json.loads(json_candidate)
                    return json_candidate
                except:
                    pass

            # 方法1：查找所有可能的JSON数组模式
            # Method 1: Find all possible JSON array patterns
            array_patterns = [
                r'```json\s*(\[.*?\])\s*```',  # ```json [array] ```
                r'```\s*(\[.*?\])\s*```',      # ``` [array] ```
                r'json\s*(\[.*?\])',           # json [array]
                r'(\[.*?\])',                  # [array]
            ]

            for pattern in array_patterns:
                matches = re.findall(pattern, text, re.DOTALL | re.IGNORECASE)
                if matches:
                    # 返回第一个匹配的有效JSON数组
                    for candidate in matches:
                        candidate = candidate.strip()
                        # 验证是否为有效的MCP JSON
                        if self._is_valid_mcp_json(candidate):
                            return candidate

            # 方法2：查找JSON对象模式并包装成数组
            # Method 2: Find JSON object patterns and wrap as array
            object_patterns = [
                r'```json\s*(\{.*?\})\s*```',  # ```json {object} ```
                r'```\s*(\{.*?\})\s*```',      # ``` {object} ```
                r'json\s*(\{.*?\})',           # json {object}
                r'(\{.*?\})',                  # {object}
            ]

            for pattern in object_patterns:
                matches = re.findall(pattern, text, re.DOTALL | re.IGNORECASE)
                if matches:
                    # 返回第一个匹配的有效JSON对象，包装成数组
                    for candidate in matches:
                        candidate = candidate.strip()
                        # 验证是否为有效的MCP JSON对象
                        if self._is_valid_mcp_json(candidate):
                            return f'[{candidate}]'  # 包装成数组

            # 方法2：逐行查找JSON数组
            # Method 2: Line-by-line JSON array search
            lines = text.split('\n')
            json_lines = []
            in_json = False

            for line in lines:
                line = line.strip()
                if not line:
                    continue

                # 检查是否是JSON数组的开始
                if line.startswith('[') or (in_json and line):
                    in_json = True
                    json_lines.append(line)

                    # 检查是否是JSON数组的结束
                    if line.endswith(']'):
                        candidate = '\n'.join(json_lines)
                        try:
                            json.loads(candidate)
                            return candidate
                        except:
                            json_lines = []
                            in_json = False
                            continue

            # 方法3：查找最后一个完整的JSON数组
            # Method 3: Find the last complete JSON array
            last_bracket_start = text.rfind('[')
            if last_bracket_start != -1:
                remaining_text = text[last_bracket_start:]
                bracket_end = remaining_text.find(']')
                if bracket_end != -1:
                    candidate = remaining_text[:bracket_end + 1]
                    try:
                        json.loads(candidate)
                        return candidate
                    except:
                        pass

        except Exception as e:
            print(f"Smart JSON extraction error: {e}")

        return None

    def _fix_duplicate_keys(self, json_text: str) -> str:
        """修复JSON中的重复键问题 / Fix duplicate key issues in JSON."""
        try:
            # 检测常见的重复键模式，特别是args键
            # Detect common duplicate key patterns, especially args keys

            # 模式1: "args": {...}, "args": "..."
            # Pattern 1: "args": {...}, "args": "..."
            pattern1 = r'"args"\s*:\s*\{[^}]*\}\s*,\s*"args"\s*:\s*"[^"]*"'
            if re.search(pattern1, json_text):
                # 移除第二个args（字符串类型的）
                json_text = re.sub(r',\s*"args"\s*:\s*"[^"]*"', '', json_text)

            # 模式2: "args": "...", "args": {...}
            # Pattern 2: "args": "...", "args": {...}
            pattern2 = r'"args"\s*:\s*"[^"]*"\s*,\s*"args"\s*:\s*\{[^}]*\}'
            if re.search(pattern2, json_text):
                # 移除第一个args（字符串类型的）
                json_text = re.sub(r'"args"\s*:\s*"[^"]*"\s*,\s*', '', json_text)

            # 通用重复键检测和修复
            # Generic duplicate key detection and fixing
            lines = json_text.split('\n')
            fixed_lines = []
            seen_keys_in_object = set()
            brace_depth = 0

            for line in lines:
                # 跟踪大括号深度
                brace_depth += line.count('{') - line.count('}')

                # 如果进入新对象，重置已见键集合
                if '{' in line:
                    seen_keys_in_object = set()

                # 检查是否是键值对行
                key_match = re.search(r'"([^"]+)"\s*:', line)
                if key_match:
                    key = key_match.group(1)
                    if key in seen_keys_in_object:
                        # 跳过重复的键
                        print(f"Skipping duplicate key: {key}")
                        continue
                    seen_keys_in_object.add(key)

                # 如果对象结束，清理已见键
                if '}' in line and brace_depth == 0:
                    seen_keys_in_object = set()

                fixed_lines.append(line)

            return '\n'.join(fixed_lines)

        except Exception as e:
            print(f"Error fixing duplicate keys: {e}")
            return json_text  # 返回原始文本