from typing import Union
"""任务控制模块 / Task Controller Module

负责管理AI任务，协调代码提取和AI交互 / Manages AI tasks, orchestrates code extraction, and AI interaction.
"""

import traceback
import threading
import idaapi
import idc
import ida_funcs
import ida_hexrays
from idaapi import msg, get_screen_ea, BADADDR
from idc import get_func_attr
from enum import Enum

from ..Config.config import ConfigManager
from ..Utils.code_extractor import CodeExtractor
from ..AIService.base_service import QueryStatus, BaseAIService
from ..Utils.comment_applicator import CommentApplicator

class TaskType(Enum):
    """定义用户请求的AI任务类型 / Define AI task types requested by the user."""
    ANALYZE_FUNCTION = 1
    CUSTOM_QUERY = 2
    CUSTOM_QUERY_WITH_CODE = 3
    ANALYZE_SELECTION = 4
    RENAME_FUNCTION = 5
    COMMENT_FUNCTION = 6
    IDENTIFY_FUNCTION = 7
    GENERATE_LINE_COMMENT = 8
    APPLY_COMMENT = 9
    AIMCP = 10

class TaskController:
    """任务控制器 / Task Controller.

    - **CN**: 管理 AI 任务，协调代码提取、Prompt 构造及与 AI 服务交互。
    - **EN**: Manages AI tasks, orchestrates code extraction, prompt building, and interaction with the AI service.
    """
    def __init__(self):
        self.config = ConfigManager()
        self.code_extractor = CodeExtractor()
        self.ai_service = self._service_factory()
        self.comment_applicator = CommentApplicator()
        self.current_task = None
        self.is_running = False
        self._task_lock = threading.Lock()
        self._current_task_thread = None
        from .mcp_controller import MCPController
        self.mcp_controller = MCPController(self.config, self.ai_service)

    def _service_factory(self) -> BaseAIService:
        """服务工厂 / AI Service Factory.

        - **CN**: 根据配置返回 `AIService` 实例，默认 `OpenAIService`。
        - **EN**: Returns an `AIService` instance based on config, defaults to `OpenAIService`.
        """
        provider = (
            self.config.config.get("provider") if hasattr(self.config, "config") else None
        ) or "openai"
        from ..AIService import get_provider_class

        provider_cls = get_provider_class(provider)
        if not provider_cls:
            raise ValueError(f"暂不支持的 AI provider: {provider}")
        return provider_cls(self.config)

    def start_task(self, task_type: TaskType, user_question: str = ""):
        """启动任务 / Start a new task.

        - **CN**: 若无任务运行，则在后台线程启动任务；否则显示提示。
        - **EN**: If no task is running, starts it in a background thread; otherwise, shows a notification.
        """
        if not self._task_lock.acquire(blocking=False):
            self.config.show_message("task_in_progress")
            return
        try:
            prompt = ""
            code_snippet = ""

            if task_type == TaskType.ANALYZE_FUNCTION:
                self.config.show_message("prepare_analyze_function")
                try:
                    code_snippet = self.code_extractor.extract_current_function_recursive(self.config.analysis_depth)
                    if not code_snippet:
                         raise ValueError("未能提取到当前函数及其调用链的代码。")
                except ValueError as e:
                    self.config.show_message("code_extract_failed", str(e))
                    self._task_lock.release()
                    return
                except Exception as e:
                    self.config.show_message("code_extract_error", str(e))
                    traceback.print_exc()
                    self._task_lock.release()
                    return
                prompt_template = self.config.get_prompt_by_type("analyze_function")
                code_snippet_with_prompt = prompt_template.format(code_snippet=code_snippet)
                prompt = f"{self.config.prompt}\n\n{code_snippet_with_prompt}"

            elif task_type == TaskType.ANALYZE_SELECTION:
                 self.config.show_message("prepare_analyze_selection")
                 try:
                     code_snippet = self.code_extractor.extract_selected_range()
                     if not code_snippet:
                          raise ValueError("未能提取到选中的代码范围。")
                 except ValueError as e:
                     self.config.show_message("code_extract_failed", str(e))
                     self._task_lock.release()
                     return
                 except Exception as e:
                     self.config.show_message("code_extract_error", str(e))
                     traceback.print_exc()
                     self._task_lock.release()
                     return
                 prompt_template = self.config.get_prompt_by_type("analyze_selection")
                 prompt = prompt_template.format(code_snippet=code_snippet)

            elif task_type == TaskType.CUSTOM_QUERY:
                if not user_question or not user_question.strip():
                     self.config.show_message("custom_query_empty")
                     self._task_lock.release()
                     return
                prompt = user_question

            elif task_type == TaskType.CUSTOM_QUERY_WITH_CODE:
                if not user_question or not user_question.strip():
                     self.config.show_message("custom_query_empty")
                     self._task_lock.release()
                     return
                self.config.show_message("prepare_extract_code")
                try:
                    current_ea = get_screen_ea()
                    func_start = get_func_attr(current_ea, idc.FUNCATTR_START)
                    if func_start == BADADDR:
                         raise ValueError("未能定位到当前函数起始地址。")
                    code_snippet = self.code_extractor._get_disassembly(func_start)
                    if not code_snippet:
                         decompiled_code = idaapi.decompile(func_start)
                         if decompiled_code:
                             code_snippet = str(decompiled_code)
                         else:
                             raise ValueError("未能提取到当前函数代码（汇编或反编译）。")
                except ValueError as e:
                    self.config.show_message("code_extract_failed", str(e))
                    self._task_lock.release()
                    return
                except Exception as e:
                    self.config.show_message("code_extract_error", str(e))
                    traceback.print_exc()
                    self._task_lock.release()
                    return
                prompt_template = self.config.get_prompt_by_type("custom_query_with_code")
                code_snippet_with_prompt = prompt_template.format(code_snippet=code_snippet)
                prompt = f"{user_question}\n\n{code_snippet_with_prompt}"

            elif task_type == TaskType.GENERATE_LINE_COMMENT or task_type == TaskType.COMMENT_FUNCTION:
                if not user_question or not user_question.strip():
                     self.config.show_message("custom_query_empty")
                     self._task_lock.release()
                     return

                self.config.show_message("prepare_extract_code")
                try:
                    current_ea = get_screen_ea()

                    if task_type == TaskType.COMMENT_FUNCTION:
                        func_start = get_func_attr(current_ea, idc.FUNCATTR_START)
                        if func_start == BADADDR:
                            raise ValueError("未能定位到当前函数起始地址。")

                        target_func_code = ""
                        try:
                            decompiled_code = idaapi.decompile(func_start)
                            if decompiled_code:
                                target_func_code = str(decompiled_code)
                            else:
                                target_func_code = self.code_extractor._get_disassembly(func_start)
                        except:
                            target_func_code = self.code_extractor._get_disassembly(func_start)

                        if not target_func_code:
                            raise ValueError("未能提取到当前函数代码。")

                        func_name = idc.get_func_name(func_start) or f"sub_{hex(func_start)}"

                        context_code = ""
                        try:
                            context_code = self.code_extractor.extract_current_function_recursive(self.config.analysis_depth, True)
                        except Exception as e:
                            context_code = f"// 上下文代码提取失败: {e}"

                        prompt_template = self.config.get_prompt_by_type("comment_function")
                        prompt = prompt_template.format(
                            func_name=func_name,
                            target_func_code=target_func_code,
                            context_code=context_code
                        )

                        if user_question:
                            prompt = f"{user_question}\n\n{prompt}"

                    else:  # GENERATE_LINE_COMMENT
                        sel_valid, sel_start, sel_end = idaapi.read_range_selection(None)
                        has_selection = (
                            sel_valid and sel_start != BADADDR and sel_end != BADADDR and sel_start < sel_end
                        )

                        context_lines = []
                        if has_selection:
                            addrs = []
                            curr = sel_start
                            while curr < sel_end:
                                addrs.append(curr)
                                nxt = idc.next_head(curr, sel_end)
                                if nxt == BADADDR or nxt <= curr:
                                    break
                                curr = nxt

                            for ea_i in addrs:
                                disasm_line = idc.generate_disasm_line(ea_i, 0) or idc.GetDisasm(ea_i)
                                if disasm_line:
                                    context_lines.append(f"> {disasm_line}")
                        else:
                            line = idc.generate_disasm_line(current_ea, 0) or idc.GetDisasm(current_ea)
                            if not line:
                                raise ValueError("无法获取当前行的反汇编文本。")

                            for i in range(-2, 3):
                                addr = idc.prev_head(current_ea) if i < 0 else (
                                    idc.next_head(current_ea) if i > 0 else current_ea
                                )
                                for _ in range(abs(i)):
                                    addr = idc.prev_head(addr) if i < 0 else idc.next_head(addr)

                                if addr != BADADDR:
                                    disasm_line = idc.generate_disasm_line(addr, 0)
                                    if disasm_line:
                                        prefix = "> " if addr == current_ea else "  "
                                        context_lines.append(f"{prefix}{disasm_line}")

                        context = "\n".join(context_lines)

                        prompt_template = self.config.get_prompt_by_type("generate_line_comment")
                        if has_selection:
                            extra_instruction = (
                                "\n\n- 如果提供了多行，请按顺序输出与原始代码行对应的注释，每行一条，不要额外解释。"
                                if self.config.language == "zh_CN" else
                                "\n\n- If multiple lines are provided, return one comment per line in the same order, each on its own line, with no extra explanations."
                            )
                            prompt_template += extra_instruction

                        prompt = prompt_template.format(context=context)

                        if user_question:
                            prompt = f"{user_question}\n\n{prompt}"

                except ValueError as e:
                    self.config.show_message("code_extract_failed", str(e))
                    self._task_lock.release()
                    return
                except Exception as e:
                    self.config.show_message("code_extract_error", str(e))
                    traceback.print_exc()
                    self._task_lock.release()
                    return

            elif task_type == TaskType.AIMCP:
                if not user_question:
                    self.config.show_message("custom_query_empty")
                    self._task_lock.release()
                    return
                self.mcp_controller.start(user_question)
                self._task_lock.release()
                return

            self._current_task_thread = threading.Thread(
                target=self._run_task_in_thread,
                args=(prompt,),
                daemon=True
            )
            self._current_task_thread.start()

        except Exception as e:
            self.config.show_message("task_start_error", str(e))
            traceback.print_exc()
            self._task_lock.release()

    def _run_task_in_thread(self, prompt: str):
        """后台任务 / Background task executor.

        - **CN**: 执行 AI 查询并将结果发送回主线程。
        - **EN**: Executes the AI query and sends results back to the main thread.
        """
        try:
            self.is_running = True
            self.ai_service.query_stream(prompt)
        except Exception as e:
            self.config.show_message("task_execution_error", str(e))
            traceback.print_exc()
        finally:
            self.is_running = False
            self._task_lock.release()

    def stop_task(self):
        """停止任务 / Stop current task."""
        self.config.show_message("stop_task")
        if self.is_running and self._current_task_thread and self._current_task_thread.is_alive():
            if hasattr(self.ai_service, "stop_event"):
                self.ai_service.stop_event.set()

    def set_analysis_depth(self, depth: int):
        """设置分析深度 / Set analysis depth."""
        self.config.analysis_depth = depth

    def set_analysis_prompt(self, prompt: str):
        """设置分析指令 / Set analysis prompt."""
        self.config.prompt = prompt

    def reload_config(self):
        """重新加载配置 / Reload configuration."""
        self.config.reload_config()

    def query_ai(self, task_type, code_str, custom_query=None):
        """通用 AI 查询 / Generic AI Query."""
        messages = []
        if task_type == 'analyze_function':
            messages = self.config.get_prompt_messages('analyze_function', code_str)
        elif task_type == 'rename_function':
            messages = self.config.get_prompt_messages('rename_function', code_str)
        elif task_type == 'comment_function':
            messages = self.config.get_prompt_messages('comment_function', code_str)
        elif task_type == 'identify_function':
            messages = self.config.get_prompt_messages('identify_function', code_str)
        elif task_type == 'custom_query':
            messages = self.config.get_prompt_messages('custom_query', code_str)

        if not messages:
            self.config.show_message("prompt_empty")
            return None

        return self.ai_service.query(messages)


def _is_library_code(ea: int) -> bool:
    """检查是否库代码 / Check if address belongs to library code."""
    func = ida_funcs.get_func(ea)
    if func:
        return (func.flags & ida_funcs.FUNC_LIB) != 0
    return False

def is_function_start(ea: int) -> bool:
    """检查是否函数起点 / Check if address is a function start."""
    return get_func_attr(ea, idc.FUNCATTR_START) == ea

def is_in_function(ea: int) -> bool:
    """检查是否在函数内 / Check if address is within any function."""
    return get_func_attr(ea, idc.FUNCATTR_START) != BADADDR

def get_current_function_ea() -> int:
    """获取当前函数 EA / Get current function's start EA."""
    return get_func_attr(get_screen_ea(), idc.FUNCATTR_START)

def get_selected_range() -> tuple[int, int]:
    """获取选中范围 / Get selected address range.

    Returns
    -------
    tuple[int, int]
        (start_ea, end_ea) or (BADADDR, BADADDR)
    """
    selection, start_ea, end_ea = read_range_selection(None)
    if selection:
        return start_ea, end_ea
    return BADADDR, BADADDR

def get_highlighted_identifier() -> Union[str, None]:
    """获取高亮标识符 / Get highlighted identifier."""
    widget = idaapi.get_current_widget()
    widget_type = idaapi.get_widget_type(widget)

    if widget_type == idaapi.BWN_PSEUDOCODE:
        vdui = ida_hexrays.get_widget_vdui(widget)
        if vdui and vdui.get_current_item(idaapi.USE_KEYBOARD):
            return vdui.item.c.get_text()
    elif widget_type == idaapi.BWN_DISASM:
        return idc.get_name(get_screen_ea(), idaapi.GN_VISIBLE)

    return None

def get_pseudocode() -> Union[str, None]:
    """获取伪代码 / Get pseudocode of current function."""
    ea = get_current_function_ea()
    if ea != BADADDR:
        try:
            cfunc = ida_hexrays.decompile(ea)
            return str(cfunc) if cfunc else None
        except ida_hexrays.DecompilationFailure:
            return None

    return None


def _is_library_code(ea: int) -> bool:
    """检查是否库代码 / Check if address belongs to library code."""
    func = ida_funcs.get_func(ea)
    if func:
        return (func.flags & ida_funcs.FUNC_LIB) != 0
    return False

def analyze_function_calls(ea: int) -> list:
    """分析函数调用 / Analyze function calls."""
    return []