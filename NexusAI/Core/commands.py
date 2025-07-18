"""commands
NexusAI **IDA Action** 定义模块。负责把菜单/快捷键触发的动作 (action) 转换为 :class:`Core.TaskController` 的具体任务。设计目标：轻量、无状态（除对 plugin_instance 的引用）。可扩展——新增 Action 仅需在入口处注册并在此处理。
This module maps IDA **actions** (menu items / hot-keys) to concrete tasks executed by :pyclass:`Core.TaskController`. It keeps minimal state and can be extended by adding new ``ACTION_*`` constants and handling branches.
"""

import traceback

import idaapi
import idc
from idaapi import (
    action_handler_t, msg, BADADDR, read_range_selection, ask_text, BWN_DISASM,
    BWN_PSEUDOCODE
)

from .task_controller import TaskType
from .extension_loader import get_extension_loader


class ActionHandler(action_handler_t):
    """动作处理器 / IDA action handler.

    Stand-alone handler that parses user actions and delegates them to :pyclass:`Core.TaskController`.
    """

    def __init__(self, action_id: str, plugin_instance):
        """初始化处理器 / Constructor."""
        super().__init__()
        self.action_id = action_id
        self.plugin = plugin_instance
        self.controller = plugin_instance.task_controller

    def activate(self, ctx):  # noqa: N802
        """执行动作 / Called when the action is triggered.

        Entry point for IDA when user triggers the action. Switches on ``self.action_id`` and delegates to task controller or plugin UI.
        """
        try:
            if not self.controller.config.client and self.action_id not in [self.plugin.ACTION_STOP_TASK]:
                self.controller.config.show_message("client_not_initialized")
                return 1

            if self.action_id == self.plugin.ACTION_ANALYZE_FUNC:
                self.controller.start_task(TaskType.ANALYZE_FUNCTION)

            elif self.action_id == self.plugin.ACTION_ANALYZE_SELECTION:
                valid, start_ea, end_ea = read_range_selection(None)
                if valid and start_ea != BADADDR and end_ea != BADADDR and start_ea < end_ea:
                    self.controller.start_task(TaskType.ANALYZE_SELECTION)
                else:
                    self.controller.config.show_message("no_selection")

            elif self.action_id == self.plugin.ACTION_STOP_TASK:
                if self.controller._current_task_thread and self.controller._current_task_thread.is_alive():
                    self.controller.stop_task()
                else:
                    self.controller.config.show_message("no_task_running")

            elif self.action_id == self.plugin.ACTION_TOGGLE_OUTPUT_VIEW:
                self.plugin.toggle_output_view()

            elif self.action_id == self.plugin.ACTION_RELOAD_EXTENSIONS:
                get_extension_loader().reload_extensions()
                self.controller.config.show_message("extensions_reloaded")

            elif self.action_id in [
                self.plugin.ACTION_COMMENT_FUNCTION,
                self.plugin.ACTION_COMMENT_LINE,
                self.plugin.ACTION_COMMENT_REPEATABLE,
                self.plugin.ACTION_COMMENT_ANTERIOR,
            ]:
                self._handle_comment_shortcut()

        except Exception as e:  # pylint: disable=broad-except
            stack_info = traceback.format_exc()
            msg(f"[!] NexusAI: 处理动作 '{self.action_id}' 失败: {e}\n")
            self.controller.config.show_message("task_start_error", str(e))
            if self.controller.config.output_view:
                self.controller.config.output_view.append_markdown(f"```text\n{stack_info}\n```")
            traceback.print_exc()
        return 1

    def update(self, ctx):  # noqa: N802
        """更新可用状态 / Decide if action is enabled."""
        return idaapi.AST_ENABLE_ALWAYS

    def _handle_comment_shortcut(self):
        """处理注释快捷键 / Handle four comment shortcuts."""
        instance = self.plugin
        if not instance.output_view:
            instance.toggle_output_view()
            idaapi.execute_sync(lambda: None, idaapi.MFF_WRITE)

        if instance.output_view:
            widget = idaapi.find_widget("NexusAI")
            if widget:
                idaapi.activate_widget(widget, True)

        comment_type_map = {
            instance.ACTION_COMMENT_FUNCTION: "function",
            instance.ACTION_COMMENT_LINE: "line",
            instance.ACTION_COMMENT_REPEATABLE: "repeatable",
            instance.ACTION_COMMENT_ANTERIOR: "anterior",
        }
        comment_type = comment_type_map.get(self.action_id)
        if comment_type and instance.output_view:
            idx = instance.output_view.comment_type_combo.findData(comment_type)
            if idx != -1:
                instance.output_view.comment_type_combo.setCurrentIndex(idx)
            instance.output_view.on_auto_comment_clicked()