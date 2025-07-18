"""
插件模块，负责IDA Pro插件集成
"""

import traceback
import idaapi
from idaapi import (
    UI_Hooks, msg, ask_text, get_widget_type, BWN_DISASM, BWN_PSEUDOCODE,
    read_range_selection, BADADDR, register_action, unregister_action, action_desc_t, 
    SETMENU_APP, AST_ENABLE_ALWAYS, AST_ENABLE_FOR_WIDGET, AST_DISABLE_FOR_WIDGET, attach_action_to_popup
)

# 引入外部命令处理器
from .commands import ActionHandler as PluginActionHandler
from .task_controller import TaskController, TaskType
from ..UI.ui_view import OutputView

from ..Core.event_bus import get_event_bus
from ..Core.extension_loader import get_extension_loader

class NexusAIPlugin(idaapi.plugin_t):
    """插件入口点 / Main plugin entry point."""
    flags = idaapi.PLUGIN_HIDE
    comment = "基于AI的逆向分析插件"
    help = "对二进制代码执行基于AI的分析"
    wanted_name = "NexusAI"
    wanted_hotkey = "Ctrl+Shift+A"
    
    _instance = None

    ACTION_PREFIX = "nexusai:"
    ACTION_ANALYZE_FUNC = f"{ACTION_PREFIX}analyze_func"
    ACTION_ANALYZE_SELECTION = f"{ACTION_PREFIX}analyze_selection"
    ACTION_STOP_TASK = f"{ACTION_PREFIX}stop_task"
    ACTION_TOGGLE_OUTPUT_VIEW = f"{ACTION_PREFIX}toggle_output_view"
    ACTION_COMMENT_FUNCTION = f"{ACTION_PREFIX}comment_function"
    ACTION_COMMENT_LINE = f"{ACTION_PREFIX}comment_line"
    ACTION_COMMENT_REPEATABLE = f"{ACTION_PREFIX}comment_repeatable"
    ACTION_COMMENT_ANTERIOR = f"{ACTION_PREFIX}comment_anterior"
    ACTION_RELOAD_EXTENSIONS = f"{ACTION_PREFIX}reload_extensions"

    @staticmethod
    def get_instance():
        return NexusAIPlugin._instance

    def init(self):
        """Called by IDA on load."""
        NexusAIPlugin._instance = self
        
        self.ui_hook = None
        self.output_view = None
        self._event_bus = get_event_bus()
        self.task_controller = TaskController()
        if not self.task_controller.config.client:
             self.task_controller.config.show_message("client_init_failed")
             self._register_actions()
             self._hook_ui()
             self.task_controller.config.show_message("plugin_load_limited")
             return idaapi.PLUGIN_KEEP


        self._register_actions()
        self._hook_ui()
        
        self._event_bus.on("language_changed", self._update_ui_for_language_change)
        
        self._create_menu_items()

        get_extension_loader().load_extensions()

        self.task_controller.config.show_message("plugin_load_success")
        self.task_controller.config.show_message("current_depth", self.task_controller.config.analysis_depth)
        self.task_controller.config.show_message("current_model", self.task_controller.config.model_name)
        msg("-" * 60 + "\n")

        self.toggle_output_view()

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        """Called by IDA on run.

        当 `flags=0` 时可通过热键或菜单调用；目前主要依赖 Action。
        """
        pass

    def term(self):
        """Called by IDA on unload."""
        if hasattr(self, "task_controller") and self.task_controller:
            self.task_controller.stop_task()
            
        if self.output_view:
            self.output_view.Close(0)
            
        self._event_bus.off("language_changed", self._update_ui_for_language_change)
            
        self._unhook_ui()
        self._unregister_actions()
        self._remove_menu_items()
        
        NexusAIPlugin._instance = None
        
        self.task_controller.config.show_message("plugin_unloaded")

    def _register_actions(self):
        """注册所有 IDA Action / Register all IDA actions."""
        current_lang = self.task_controller.config.language
        
        messages = self.task_controller.config.config.get("messages", {})
        lang_messages = messages.get(current_lang, messages.get("zh_CN", {}))
        menu_texts = lang_messages.get("menu_texts", {})
        tooltips = lang_messages.get("tooltip", {})
        
        shortcuts = self.task_controller.config.config.get("shortcuts", {})
        
        actions = [
            (self.ACTION_ANALYZE_FUNC, menu_texts.get("analyze_func", "分析函数"), tooltips.get("analyze_func", "分析当前函数的功能和逻辑"), ""),
            (self.ACTION_ANALYZE_SELECTION, menu_texts.get("analyze_selection", "分析选中代码"), tooltips.get("analyze_selection", "分析当前选中的代码片段"), ""),
            (self.ACTION_STOP_TASK, menu_texts.get("stop_task", "停止任务"), tooltips.get("stop_task", "停止当前正在执行的任务"), ""),
            (self.ACTION_TOGGLE_OUTPUT_VIEW, menu_texts.get("toggle_output_view", "显示/隐藏输出窗口"), tooltips.get("toggle_output_view", "切换NexusAI输出窗口"), self.task_controller.config.config.get("shortcuts", {}).get("toggle_output", "Ctrl+Shift+K")),
            (self.ACTION_COMMENT_FUNCTION, "函数注释", "添加函数注释", shortcuts.get("comment_function", "Ctrl+Shift+A")),
            (self.ACTION_COMMENT_LINE, "行注释", "添加行注释", shortcuts.get("comment_line", "Ctrl+Shift+S")),
            (self.ACTION_COMMENT_REPEATABLE, "可重复注释", "添加可重复注释", shortcuts.get("comment_repeatable", "Ctrl+Shift+D")),
            (self.ACTION_COMMENT_ANTERIOR, "前置注释", "添加前置注释", shortcuts.get("comment_anterior", "Ctrl+Shift+W")),
            (
                self.ACTION_RELOAD_EXTENSIONS,
                menu_texts.get("reload_extensions", "Reload Extensions" if current_lang == "en_US" else "重新加载扩展"),
                tooltips.get("reload_extensions", "Reload and hot-refresh extensions directory"),
                shortcuts.get("reload_extensions", "Ctrl+Shift+R"),
            ),
        ]

        for action_id, label, tooltip, *hotkey in actions:
            action_desc = idaapi.action_desc_t(
                action_id,
                label,
                PluginActionHandler(action_id, self),
                hotkey[0] if hotkey else None,
                tooltip,
                0
            )
            if not register_action(action_desc):
                 self.task_controller.config.show_message("register_action_failed", action_id)


    def _unregister_actions(self):
        """注销所有 IDA Action / Unregister all IDA actions."""
        actions_to_unregister = [
            self.ACTION_ANALYZE_FUNC, self.ACTION_ANALYZE_SELECTION,
            self.ACTION_STOP_TASK,
            self.ACTION_TOGGLE_OUTPUT_VIEW
            , self.ACTION_RELOAD_EXTENSIONS
        ]
        for action_id in actions_to_unregister:
             unregister_action(action_id)


    def _hook_ui(self):
        """挂载 UI 钩子 / Hook UI events for context menus."""
        self.ui_hook = self.UIMenuHook()
        self.ui_hook.hook()

    def _unhook_ui(self):
        """卸载 UI 钩子 / Unhook UI events."""
        if self.ui_hook:
            self.ui_hook.unhook()
            self.ui_hook = None
            
    def _create_menu_items(self):
        """创建主菜单 / Create main menu entries."""
        current_lang = self.task_controller.config.language
        
        menu_texts = self.task_controller.config.config.get("messages", {}).get(current_lang, {}).get("menu_texts", {})
        
        menu_title = menu_texts.get("menu_title", "NexusAI")
        menu_path = f"Edit/{menu_title}/"
        
        idaapi.attach_action_to_menu(f"{menu_path}{menu_texts.get('analyze_func', '分析当前函数 (AI)')}", self.ACTION_ANALYZE_FUNC, idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu(f"{menu_path}{menu_texts.get('analyze_selection', '分析选中代码 (AI)')}", self.ACTION_ANALYZE_SELECTION, idaapi.SETMENU_APP)
        
        idaapi.attach_action_to_menu(f"{menu_path}", None, idaapi.SETMENU_APP)
        
        idaapi.attach_action_to_menu(f"{menu_path}{menu_texts.get('stop_task', '停止当前分析')}", self.ACTION_STOP_TASK, idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu(f"{menu_path}{menu_texts.get('toggle_output_view', '显示/隐藏输出窗口')}", self.ACTION_TOGGLE_OUTPUT_VIEW, idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu(
            f"{menu_path}{menu_texts.get('reload_extensions', 'Reload Extensions' if current_lang == 'en_US' else '重新加载扩展')}",
            self.ACTION_RELOAD_EXTENSIONS,
            idaapi.SETMENU_APP,
        )
        
        idaapi.attach_action_to_menu(f"Windows/{menu_title}", self.ACTION_TOGGLE_OUTPUT_VIEW, idaapi.SETMENU_APP)

        self.task_controller.config.show_message("menu_added", menu_title)

    def _remove_menu_items(self):
        """移除主菜单 / Remove main menu entries."""
        current_lang = self.task_controller.config.language
        
        menu_texts = self.task_controller.config.config.get("messages", {}).get(current_lang, {}).get("menu_texts", {})
        
        menu_title = menu_texts.get("menu_title", "NexusAI")
        
        edit_menu_path = f"Edit/{menu_title}/"
        
        try:
            idaapi.del_menu_item(edit_menu_path)
            self.task_controller.config.show_message("menu_removed", edit_menu_path)
        except:
            pass

        try:
            idaapi.detach_action_from_menu(f"Windows/{menu_title}", self.ACTION_TOGGLE_OUTPUT_VIEW)
        except:
            pass

    def _update_ui_for_language_change(self):
        """语言切换后更新 UI / Update UI on language change."""
        current_lang = self.task_controller.config.language
        
        messages = self.task_controller.config.config.get("messages", {})
        lang_messages = messages.get(current_lang, messages.get("zh_CN", {}))
        menu_texts = lang_messages.get("menu_texts", {})
        tooltips = lang_messages.get("tooltip", {})

        action_text_map = {
            self.ACTION_ANALYZE_FUNC: "analyze_func",
            self.ACTION_ANALYZE_SELECTION: "analyze_selection",
            self.ACTION_STOP_TASK: "stop_task",
            self.ACTION_TOGGLE_OUTPUT_VIEW: "toggle_output_view",
            self.ACTION_RELOAD_EXTENSIONS: "reload_extensions",
        }

        for action_id, text_key in action_text_map.items():
            label = menu_texts.get(text_key)
            tooltip = tooltips.get(text_key)
            if label:
                idaapi.update_action_label(action_id, label)
            if tooltip:
                idaapi.update_action_tooltip(action_id, tooltip)

        self._remove_menu_items()
        self._create_menu_items()

    def toggle_output_view(self):
        """切换输出窗口 / Toggle output view visibility."""
        if self.output_view:
            self.output_view.Close(0)
            return

        self.output_view = OutputView(self.task_controller)
        self.output_view.Show()
        
    def on_output_view_close(self):
        """输出窗口关闭回调 / Callback on output view close."""
        self.output_view = None

    class UIMenuHook(UI_Hooks):
        """UI 钩子 / UI hook for context menus."""
        def finish_populating_widget_popup(self, form, popup):
            """填充右键菜单 / Populate right-click context menu."""
            current_lang = NexusAIPlugin._instance.task_controller.config.language
            
            menu_texts = NexusAIPlugin._instance.task_controller.config.config.get("messages", {}).get(current_lang, {}).get("menu_texts", {})
            
            menu_title = menu_texts.get("menu_title", "NexusAI")
            
            widget_type = get_widget_type(form)
            
            if widget_type in (BWN_DISASM, BWN_PSEUDOCODE):
                attach_action_to_popup(form, popup, NexusAIPlugin.ACTION_ANALYZE_FUNC, f"{menu_title}/", SETMENU_APP)
                attach_action_to_popup(form, popup, NexusAIPlugin.ACTION_ANALYZE_SELECTION, f"{menu_title}/", SETMENU_APP)
                attach_action_to_popup(form, popup, None, f"{menu_title}/", SETMENU_APP)
                attach_action_to_popup(form, popup, NexusAIPlugin.ACTION_STOP_TASK, f"{menu_title}/", SETMENU_APP)
                attach_action_to_popup(form, popup, NexusAIPlugin.ACTION_TOGGLE_OUTPUT_VIEW, f"{menu_title}/", SETMENU_APP)
            elif widget_type == 0:
                attach_action_to_popup(form, popup, None, f"{menu_title}/", SETMENU_APP)
                attach_action_to_popup(form, popup, NexusAIPlugin.ACTION_STOP_TASK, f"{menu_title}/", SETMENU_APP)
                attach_action_to_popup(form, popup, NexusAIPlugin.ACTION_TOGGLE_OUTPUT_VIEW, f"{menu_title}/", SETMENU_APP)