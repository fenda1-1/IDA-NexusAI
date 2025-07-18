from __future__ import annotations

import idaapi
import idc
from idaapi import msg
from typing import Optional

from .graph_exporter import GraphExporter

# Localization & dynamic menu rebuild
# 本地化 & 动态菜单重建
from typing import List

from NexusAI.Config.config import ConfigManager  # type: ignore
from NexusAI.Core.event_bus import get_event_bus  # type: ignore

_TXT = {
    "zh_CN": {
        "action_text": "导出调用/数据流图",
        "tooltip": "生成 JSON 图文件，可供 AI 分析",
        "menu_root": "Edit/NexusAI/",
        "menu_sub": "导出调用/数据流图",
        "ask_sub": "导出当前函数的子调用/数据流图 (深度2)？\n是=子图  否=完整图  取消=放弃",
        "ask_full": "确认导出完整图？  否=取消",
        "cancel": "已取消导出操作。",
        "export_call": "已导出调用图:",
        "export_dfg": "已导出数据流图:",
        "register_failed": "无法注册导出图动作，可能已存在。",
        "loaded": "Graph Export Extension loaded",
        "unloaded": "Graph Export Extension unloaded",
    },
    "en_US": {
        "action_text": "Export Call/Data Flow Graph",
        "tooltip": "Generate JSON graph files for AI analysis",
        "menu_root": "Edit/NexusAI/",
        "menu_sub": "Export Call/Data Flow Graph",
        "ask_sub": "Export subgraph of current function (depth=2)?\nYes=Subgraph  No=Full graph  Cancel=Abort",
        "ask_full": "Confirm export full graph?  No=Cancel",
        "cancel": "Export cancelled.",
        "export_call": "Call graph exported:",
        "export_dfg": "Data-flow graph exported:",
        "register_failed": "Cannot register export graph action, it might already exist.",
        "loaded": "Graph Export Extension loaded",
        "unloaded": "Graph Export Extension unloaded",
    },
}


def _t(key: str) -> str:
    lang = ConfigManager().language
    return _TXT.get(lang, _TXT["zh_CN"])[key]


ACTION_ID = "nexusai:export_graph"

_menu_items: List[str] = []


def _remove_menu():
    for p in _menu_items:
        try:
            idaapi.detach_action_from_menu(p, ACTION_ID)
        except Exception:
            pass
    _menu_items.clear()


def _add_menu():
    _remove_menu()
    root = _t("menu_root")
    sub = _t("menu_sub")
    menu_path = root + sub if not sub.startswith("Edit/") else sub
    try:
        idaapi.attach_action_to_menu(menu_path, ACTION_ID, idaapi.SETMENU_APP)
    except Exception:
        idaapi.attach_action_to_menu("Edit/", ACTION_ID, idaapi.SETMENU_APP)
        menu_path = "Edit/" + sub
    _menu_items.append(menu_path)


class _ExportGraphHandler(idaapi.action_handler_t):
    """IDA ActionHandler: 导出调用图 / 数据流图。
    IDA ActionHandler: Export Call Graph / Data Flow Graph.
    """

    def __init__(self):
        super().__init__()

    def activate(self, ctx):  # noqa: N802 (IDA API)
        """
        激活处理函数。
        Activate handler.
        """
        exporter = GraphExporter()

        current_ea = idc.here()
        func: Optional[idaapi.func_t] = idaapi.get_func(current_ea)
        use_subgraph = False
        if func:
            ans = idaapi.ask_yn(
                1,
                _t("ask_sub"),
            )
            if ans == -1:
                msg(_t("cancel"))
                return 1
            use_subgraph = ans == 1

        if use_subgraph:
            call_path, data_path = exporter.export_subgraph(func.start_ea, depth=2)
        else:
            if func is None:
                ans = idaapi.ask_yn(0, _t("ask_full"))
                if ans != 1:
                    msg(_t("cancel"))
                    return 1
            call_path, data_path = exporter.export()

        msg(f"{_t('export_call')} {call_path}\n")
        msg(f"{_t('export_dfg')} {data_path}\n")
        return 1

    def update(self, ctx):  # noqa: N802
        return idaapi.AST_ENABLE_ALWAYS


action_desc = idaapi.action_desc_t(
    ACTION_ID,
    _t("action_text"),
    _ExportGraphHandler(),
    "",
    _t("tooltip"),
    0,
)


def init_extension(event_bus):  # noqa: D401 (simple description)
    """注册动作与菜单。
    Register actions and menus.
    """
    if not idaapi.register_action(action_desc):
        msg(f"[NexusAI] {_t('register_failed')}\n")
    _add_menu()
    get_event_bus().on("language_changed", lambda *_: _add_menu())
    msg(f"[NexusAI] {_t('loaded')}\n")


def deinit_extension():
    """卸载扩展，清理动作与菜单。
    Unload extension, clear actions and menus.
    """
    idaapi.unregister_action(ACTION_ID)
    _remove_menu()
    msg(f"[NexusAI] {_t('unloaded')}\n")