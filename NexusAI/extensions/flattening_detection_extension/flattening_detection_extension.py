from __future__ import annotations

# ---------------------------------------------------------------------------
# Add multilingual support and dynamic menu refresh
# 增加多语言支持和动态菜单刷新
# ---------------------------------------------------------------------------

from typing import List

from NexusAI.Config.config import ConfigManager  # type: ignore
from NexusAI.Core.event_bus import get_event_bus  # type: ignore

_TEXTS = {
    "zh_CN": {
        "action_text": "检测控制流混淆函数 (CFF)",
        "tooltip": "扫描并标记疑似控制流平坦化函数",
        "no_found": "未检测到疑似控制流混淆函数。",
        "menu_root": "Edit/NexusAI/",
        "register_failed": "动作注册失败，可能已存在。",
        "loaded": "混淆函数检测扩展已加载。(Ctrl+Shift+F)",
        "unloaded": "混淆函数检查检测扩展已卸载。",
        "using_cache": "使用缓存",
        "detect_done": "检测完成",
        "table_shown": "结果已在表格窗口展示。",
        "cff_comment": "[NexusAI] 疑似 CFF (score={score:.2f})",
    },
    "en_US": {
        "action_text": "Detect CFF Functions",
        "tooltip": "Scan and highlight potential control-flow-flattening functions",
        "no_found": "No potential CFF functions detected.",
        "menu_root": "Edit/NexusAI/",
        "register_failed": "Failed to register CFF detection action, maybe exists.",
        "loaded": "Flattening Detection Extension loaded. (Ctrl+Shift+F)",
        "unloaded": "Flattening Detection Extension unloaded.",
        "using_cache": "using cache",
        "detect_done": "detection finished",
        "table_shown": "results shown in table window.",
        "cff_comment": "[NexusAI] Suspicious CFF (score={score:.2f})",
    },
}


def _t(key: str):
    lang = ConfigManager().language  # singleton
    return _TEXTS.get(lang, _TEXTS["zh_CN"])[key]

"""NexusAI Flattening Detection Extension

扫描目标二进制中疑似使用控制流平坦化 (CFF) 混淆的函数，并以高亮/注释方式标记。
"""

import idaapi
import idc
from idaapi import action_handler_t, msg

from .flattening_detector import detect_flattening_functions

ACTION_ID = "nexusai:detect_flattening"
ACTION_TEXT = _t("action_text")
ACTION_HOTKEY = "Ctrl+Shift+F"


class _FlatteningDetectHandler(action_handler_t):
    """
    IDA action handler: Execute detection synchronously in the main thread (requires IDA API).
    IDA 动作处理器：在主线程同步执行检测（需 IDA API）。
    """

    def activate(self, ctx):  # noqa: N802
        def _task():
            from .flattening_detector import load_cached_scores, detect_flattening_functions

            cached = load_cached_scores()
            using_cache = cached is not None

            suspects_all = detect_flattening_functions(0.0)

            threshold = 0.7

            idaapi.show_wait_box("{}\n{}".format("NexusAI", "正在检测控制流混淆函数…"))
            try:
                pass
            finally:
                idaapi.hide_wait_box()

            if not suspects_all:
                from .flattening_detector import get_top_function  # local import
                top = get_top_function()
                if top:
                    ea, sc = top
                    func_name = idc.get_func_name(ea)
                    idaapi.info(_t("no_found"))  # type: ignore[attr-defined]
                    msg(f"[NexusAI] {_t('no_found')} Top scored: 0x{ea:X} {func_name} (score={sc:.2f})\n")
                else:
                    idaapi.info(_t("no_found"))  # type: ignore[attr-defined]
                    msg(f"[NexusAI] {_t('no_found')}\n")
                return 1

            for ea, score in suspects_all:
                if score >= threshold:
                    idc.set_func_cmt(ea, _t("cff_comment").format(score=score), 1)
                    try:
                        idaapi.set_func_color(ea, 0xAA70FF)
                    except Exception:
                        pass

            from .flattening_table_view import FlatteningResultView
            view = FlatteningResultView(suspects_all)
            view.Show()

            msg(f"[NexusAI] {(_t('using_cache') if using_cache else _t('detect_done'))}，{_t('table_shown')}\n")
            return 1

        idaapi.execute_sync(_task, idaapi.MFF_WRITE)
        return 1

    def update(self, ctx):  # noqa: N802
        return idaapi.AST_ENABLE_ALWAYS


_menu_items: List[str] = []


def _remove_menu_items():
    for p in _menu_items:
        try:
            idaapi.detach_action_from_menu(p, ACTION_ID)
        except Exception:
            pass
    _menu_items.clear()


def _add_menu_items():
    _remove_menu_items()
    root = _t("menu_root")
    path = root
    try:
        idaapi.attach_action_to_menu(path, ACTION_ID, idaapi.SETMENU_APP)  # type: ignore[attr-defined]
    except Exception:
        idaapi.attach_action_to_menu("Edit/", ACTION_ID, idaapi.SETMENU_APP)
        path = "Edit/"
    _menu_items.append(path)


def init_extension(event_bus=None):  # pylint: disable=unused-argument
    """
    Register actions and menu items.
    注册动作和菜单项。
    """
    desc = idaapi.action_desc_t(
        ACTION_ID,
        ACTION_TEXT,
        _FlatteningDetectHandler(),
        ACTION_HOTKEY,
        _t("tooltip"),
        0,
    )
    if not idaapi.register_action(desc):
        msg(f"[NexusAI] {_t('register_failed')}\n")
    _add_menu_items()

    get_event_bus().on("language_changed", lambda *_: _add_menu_items())

    msg(f"[NexusAI] {_t('loaded')}\n")


def deinit_extension():
    """
    Unregister action.
    注销动作。
    """
    _remove_menu_items()
    try:
        idaapi.unregister_action(ACTION_ID)
    except Exception:  # pragma: no cover  # pylint: disable=broad-except
        pass
    msg(f"[NexusAI] {_t('unloaded')}\n")