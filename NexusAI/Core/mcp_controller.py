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

from ..Config.config import ConfigManager
from ..AIService.base_service import BaseAIService
from .mcp_functions import mcp_call
from ..Core.event_bus import get_event_bus


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

        self.current_task = MCPTask(theme)
        t = threading.Thread(target=self._run_task, daemon=True)
        t.start()

    def _run_task(self):
        """后台线程：执行交互循环 / Worker thread running the dialogue loop."""
        assert self.current_task is not None
        self.current_task.status = MCPTaskStatus.RUNNING
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
                    "参数要求: \n"
                    "  • 所有地址/ea/func_addr 必须是十六进制字符串 (如 \"0x140123ABC\") 或整数, 禁止使用符号表达式。\n"
                    "  • 析构函数在符号表中通常带有 '~'，例如 \"LoadLevelLimiter::~LoadLevelLimiter\"，搜索时务必包含 '~'。"
                    " 先简要说明本轮分析结果与下一步计划，然后输出 JSON 指令数组。"
                    " ⚠️ 解释部分禁止出现 '[' 字符；解释完毕后紧跟一个换行再写 JSON 数组。"
                    " JSON 数组必须严格符合格式，无多余字段；"
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

                if full_resp.strip().upper().startswith("DONE"):
                    break

                json_fragment = self._extract_json_array(full_resp)
                if json_fragment is None:
                    raise ValueError(
                        f"无法在回复中找到 JSON 指令数组。回复示例: {full_resp[:200]}"
                    )
                try:
                    actions = json.loads(json_fragment)
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
                    res = mcp_call(action, **args)
                    aggregated.append({"request": action_item, "response": res})

                step_result_str = json.dumps(aggregated, ensure_ascii=False, indent=2)
                conversation_context += f"\n# Iteration {iteration} result:\n{step_result_str}\n"
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
            else:
                self.current_task.status = MCPTaskStatus.DONE
            self.current_task.result = conversation_context
        except Exception as e:  # noqa: BLE001
            self.current_task.status = MCPTaskStatus.ERROR
            self.current_task.error = str(e)
            self.config.show_message("task_execution_error", str(e))
        finally:
            self._task_lock.release()

    def _extract_json_array(self, text: str):
        """提取 JSON 数组 / Extract first JSON array from raw LLM reply."""
        start = text.find('[')
        if start == -1:
            return None
        depth = 0
        for i in range(start, len(text)):
            c = text[i]
            if c == '[':
                depth += 1
            elif c == ']':
                depth -= 1
                if depth == 0:
                    return text[start:i+1]
        return None