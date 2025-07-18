from __future__ import annotations

"""
Helper module: Control Flow Flattening (CFF) detection algorithm.
辅助模块：控制流平坦化（CFF）检测算法

Note: `__nexus_extension__ = False` is used to tell ExtensionLoader that this file is not a loadable extension, but a library referenced by other extensions.
注意：`__nexus_extension__ = False` 用于告知 ExtensionLoader 该文件不是可加载扩展，而是被其他扩展引用的库。
"""

__nexus_extension__ = False

from typing import List, Tuple
import json
from pathlib import Path
import hashlib
import os

from NexusAI.Utils.ida_compat import ensure_module

idaapi = ensure_module("idaapi", {})
idautils = ensure_module("idautils", {"Functions": lambda: []})

_CACHE_DIR = Path(__file__).resolve().parent / "_cache"
_CACHE_DIR.mkdir(exist_ok=True)


def _compute_binary_id() -> str:
    """
    Generate a unique ID quickly through the input file path + file size + MD5.
    通过输入文件路径 + 文件大小 + MD5 快速生成唯一 ID。
    """
    try:
        path_getters: list[callable[[], str]] = []
        try:
            import ida_nalt  # type: ignore
            path_getters.append(lambda: ida_nalt.get_input_file_path())
        except Exception:
            pass
        path_getters.append(lambda: getattr(idaapi, "get_input_file_path", lambda: "")())
        try:
            import ida_loader  # type: ignore
            path_getters.append(lambda: ida_loader.get_path(ida_loader.PATH_TYPE_IDB))
        except Exception:
            pass

        path = ""
        for getter in path_getters:
            try:
                path = getter() or ""
                if path:
                    break
            except Exception:
                continue

        if not path or not os.path.isfile(path):
            import idc  # type: ignore
            idb_path = idc.get_idb_path()
            if idb_path and os.path.isfile(idb_path):
                path = idb_path
                idaapi.msg(f"[NexusAI] ⚠️ 使用 IDB 文件作为缓存标识: {Path(idb_path).name}\n")
            else:
                idaapi.msg("[NexusAI] ⚠️ 无法获取输入/IDB 文件路径, 使用 unknown_bin.json 缓存。\n")
                return "unknown_bin"

        size = os.path.getsize(path) if os.path.isfile(path) else 0
        with open(path, "rb") as f:
            data = f.read(65536)
        return Path(path).name
    except Exception as e:  # pragma: no cover
        idaapi.msg(f"[NexusAI] ⚠️ compute_binary_id 失败: {e}\n")
        import traceback
        traceback.print_exc()
        return "unknown_bin"


def _cache_path() -> Path:
    return _CACHE_DIR / f"{_compute_binary_id()}.json"


def load_cached_scores() -> List[Tuple[int, float]] | None:
    path = _cache_path()
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text("utf-8"))
        return [(int(ea, 16), float(score)) for ea, score in data]
    except Exception:  # pragma: no cover
        return None


def save_cached_scores(items: List[Tuple[int, float]]):
    path = _cache_path()
    try:
        json.dump([[hex(ea), score] for ea, score in items], path.open("w", encoding="utf-8"))
    except Exception:
        pass


from collections import Counter
import math

def _collect_basic_block_stats(func) -> Tuple[int, int, float]:
    try:
        flow = idaapi.FlowChart(func)  # type: ignore[attr-defined]
    except Exception:  # pragma: no cover  # pylint: disable=broad-except
        return 0, 0, 0.0

    blocks = 0
    uncond = 0
    cond_jumps = 0
    targets: dict[int, int] = {}
    for bb in flow:  # type: ignore[not-an-iterable]
        blocks += 1
        end_ea = idaapi.prev_head(bb.end_ea, bb.start_ea)
        if not idaapi.is_code(idaapi.get_full_flags(end_ea)):
            continue
        mnem = idaapi.print_insn_mnem(end_ea).lower()
        if mnem == "jmp":
            uncond += 1
            insn = idaapi.insn_t()
            if idaapi.decode_insn(insn, end_ea):
                op1 = insn.Op1
                if op1.type in (getattr(idaapi, "o_displ", -1), getattr(idaapi, "o_phrase", -1)):
                    base = getattr(op1, "addr", 0)
                    targets[base] = targets.get(base, 0) + 1
        elif mnem.startswith("j") and mnem != "jmp":
            cond_jumps += 1

    dispatcher = max(targets.values()) / blocks if targets else 0.0

    back_edges = 0
    for bb in flow:  # type: ignore[not-an-iterable]
        for succ in bb.succs():  # type: ignore[attr-defined]
            if succ.start_ea < bb.start_ea:
                back_edges += 1

    loop_ratio = min(back_edges / max(blocks, 1), 1.0)

    has_switch = 0
    if hasattr(idaapi, "get_switch_info_ex"):
        for bb in flow:
            end_ea = idaapi.prev_head(bb.end_ea, bb.start_ea)
            sinfo = idaapi.get_switch_info_ex(end_ea)  # type: ignore[attr-defined]
            if sinfo is not None:
                has_switch = 1
                break

    try:
        frame = idaapi.get_frame(func)  # type: ignore[attr-defined]
        stack_vars = frame.memqty if frame else 0
    except Exception:  # pragma: no cover
        stack_vars = 0

    extra = {
        "loop_ratio": loop_ratio,
        "has_switch": has_switch,
        "stack_var_ratio": min(stack_vars / 64.0, 1.0),
        "cond_ratio": cond_jumps / max(blocks, 1),
        "complexity_ratio": min((cond_jumps + uncond) / max(blocks, 1), 1.0),
    }

    mnem_counter = Counter()
    try:
        import idautils  # type: ignore
        func_items_iter = idautils.FuncItems(func.start_ea)
    except Exception:
        func_items_iter = []

    for insn_ea in func_items_iter:
        if idaapi.is_code(idaapi.get_full_flags(insn_ea)):
            mnem_counter[idaapi.print_insn_mnem(insn_ea).lower()] += 1

    if mnem_counter:
        total = sum(mnem_counter.values())
        probs = [c / total for c in mnem_counter.values()]
        entropy = -sum(p * math.log2(p) for p in probs)
        max_h = math.log2(len(mnem_counter))
        if max_h == 0:
            low_entropy = 1.0
        else:
            low_entropy = 1 - (entropy / max_h)
    else:
        low_entropy = 0
    extra["low_entropy"] = low_entropy

    return blocks, uncond, dispatcher, extra


def get_flattening_score(func) -> float:
    """
    Calculate the flattening score of a function.
    计算函数的平坦化得分。
    """
    collected = _collect_basic_block_stats(func)
    if len(collected) == 3:
        blocks, uncond, disp = collected
        extra = {"loop_ratio": 0, "has_switch": 0, "stack_var_ratio": 0}
    else:
        blocks, uncond, disp, extra = collected

    base_score = (
        0.3 * min(blocks / 200.0, 1.0)
        + 0.3 * (uncond / max(blocks, 1))
        + 0.1 * disp
    )

    extra_score = (
        0.1 * extra["loop_ratio"]
        + 0.1 * extra["has_switch"]
        + 0.1 * extra["stack_var_ratio"]
        + 0.05 * extra["cond_ratio"]
        + 0.05 * extra["complexity_ratio"]
        + 0.05 * extra["low_entropy"]
    )

    score = base_score + extra_score
    return round(min(score, 1.0), 3)


def detect_flattening_functions(threshold: float = 0.7) -> List[Tuple[int, float]]:
    """
    Traverse all functions in the program, return a list of suspected flattening function addresses and scores, and write to the cache.
    遍历程序所有函数，返回疑似平坦化函数地址及得分列表，并写入缓存。
    """
    cached = load_cached_scores()
    if cached is not None:
        return [item for item in cached if item[1] >= threshold]

    suspects: List[Tuple[int, float]] = []

    try:
        import ida_funcs  # type: ignore
        total_funcs = ida_funcs.get_func_qty()
    except Exception:
        try:
            import idautils  # type: ignore
            total_funcs = sum(1 for _ in idautils.Functions())
        except Exception:
            total_funcs = 0

    idaapi.show_wait_box("NexusAI: 正在扫描函数 (0/%d)" % total_funcs)

    processed = 0
    try:
        import idautils
    except Exception:
        import types, sys
        stub = types.ModuleType("idautils")
        stub.Functions = lambda: []
        sys.modules["idautils"] = stub
        import idautils

    for ea in idautils.Functions():  # type: ignore[attr-defined]
        func = idaapi.get_func(ea)  # type: ignore[attr-defined]
        if func is None:
            continue
        score = get_flattening_score(func)
        suspects.append((ea, score))

        processed += 1
        if processed % 128 == 0:
            idaapi.replace_wait_box("NexusAI: 扫描 %d/%d (%.1f%%)" % (processed, total_funcs, processed * 100 / max(total_funcs, 1)))

    save_cached_scores(suspects)
    idaapi.hide_wait_box()
    return [item for item in suspects if item[1] >= threshold]


def get_top_function() -> tuple[int, float] | None:
    """
    Returns the function with the highest score (ea, score), or None if there are no functions.
    返回评分最高的函数 (ea, score)，若无函数则 None。
    """
    top_ea = 0
    top_score = -1.0
    for ea in idautils.Functions():  # type: ignore[attr-defined]
        func = idaapi.get_func(ea)  # type: ignore[attr-defined]
        if func is None:
            continue
        score = get_flattening_score(func)
        if score > top_score:
            top_ea = ea
            top_score = score
    return (top_ea, top_score) if top_score >= 0 else None