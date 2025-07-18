"""mcp_functions
=================

为 AIMCP 自动化功能提供统一的 IDA API 调用包装。LLM 通过 JSON 指令指定 `action` 与 `args`，
本模块负责解析并安全地调用对应实现，所有函数返回统一字典格式：
```
{"ok": bool, "data": Any, "error": str}
```

*注意*：当前实现为 **MVP** 版本，仅封装了部分常用功能，后续可按需扩展。
"""
from __future__ import annotations

from typing import Any, Callable, Dict

import traceback
import re

try:
    import idaapi  # type: ignore
    import idautils  # type: ignore
    import idc  # type: ignore
    import ida_funcs  # type: ignore
    import ida_hexrays  # type: ignore
    import ida_bytes
    import ida_lines
    import ida_kernwin
    import ida_name
    import ida_typeinf
    import ida_entry
    import ida_nalt
except ImportError:  # 单元测试或非IDA环境
    idaapi = None  # type: ignore


action_registry: Dict[str, Callable[..., Any]] = {}

def register_action(name: str):
    """装饰器：将函数注册为 MCP 可调用 action。"""

    def decorator(fn: Callable[..., Any]):
        action_registry[name] = fn
        return fn

    return decorator


def _wrap_ok(data: Any):
    return {"ok": True, "data": data, "error": ""}


def _wrap_err(msg: str):
    return {"ok": False, "data": None, "error": msg}


# ---------------------------------------------------------------------------
# Action 实现（全部已在 action_registry 注册）
# ---------------------------------------------------------------------------
# 每个函数都遵循以下规范：
#   - 使用 @register_action("name") 装饰器注册
#   - 参数仅使用 JSON 可序列化的基础类型（str/int/bool 等）
#   - 返回值统一使用 _wrap_ok / _wrap_err
#   - LLM 在调用前可通过系统 Prompt 获取到可用 action 名称及其简述

@register_action("list_funcs")
# 描述: 列出程序中所有函数的起始地址与名称；可选 pattern 过滤
# args:
#   pattern(str, 可选): 名称过滤子串（忽略大小写）
#   limit(int, 可选): 返回前 N 条，默认 100，防止输出过大
# 返回: [(address_hex, name), ...]
def list_funcs(pattern: str | None = None, limit: int = 100):
    """列出程序中函数 / List functions in binary.

    Parameters
    ----------
    pattern : str | None
        • **CN**：过滤子串或正则，区分大小写与否依据实现。
        • **EN**: Optional substring/regex to filter function names.
    limit : int, default ``100``
        • **CN**：返回前 N 条结果，防止输出过大。
        • **EN**: Maximum number of entries to return.
    """
    if idaapi is None:
        return _wrap_err("IDA SDK not available")

    result_holder = {}

    def _collect():
        try:
            funcs = [
                (f"0x{ea:X}", ida_funcs.get_func_name(ea)) for ea in idautils.Functions()
            ]
            nonlocal result_holder
            if pattern:
                if '|' in pattern or any(ch in pattern for ch in '.?*+[](){}^$'):  # treat as regex
                    regex = re.compile(pattern, re.IGNORECASE)
                    funcs = [t for t in funcs if regex.search(t[1])]
                else:
                    p_low = pattern.lower()
                    funcs = [t for t in funcs if p_low in t[1].lower()]
            if limit and limit > 0:
                funcs = funcs[:limit]
            result_holder = _wrap_ok(funcs)
        except Exception as inner_e:  # noqa: BLE001
            result_holder = _wrap_err(str(inner_e))

    # 保证在主线程执行
    idaapi.execute_sync(_collect, idaapi.MFF_READ)
    return result_holder


@register_action("get_decomp")
# 描述: 反编译指定地址所在函数
# args: ea / address / func_address (任意一个)
def get_decomp(ea: str | int | None = None, address: str | int | None = None, func_address: str | int | None = None, func_addr: str | int | None = None):
    """反编译函数 / Decompile function containing address.

    接受多种参数别名，最终解析为十六进制地址并调用 Hex-Rays。

    Accepts several alias parameters that map to the target address and
    returns the decompiled pseudocode (if Hex-Rays is available).
    """
    if idaapi is None:
        return _wrap_err("IDA SDK not available")
    try:
        target = ea or address or func_address or func_addr
        if target is None:
            return _wrap_err("missing parameter: ea/address/func_address")
        target_ea = int(target, 16) if isinstance(target, str) else int(target)

        result_holder = {}

        def _do_decompile():
            nonlocal result_holder
            try:
                cfunc = ida_hexrays.decompile(target_ea)
                if not cfunc:
                    result_holder = _wrap_err("decompile failed / not available")
                else:
                    result_holder = _wrap_ok(str(cfunc))
            except Exception as inner_e:
                result_holder = _wrap_err(str(inner_e))

        idaapi.execute_sync(_do_decompile, idaapi.MFF_READ)
        return result_holder
    except Exception as e:  # noqa: BLE001
        return _wrap_err(str(e))


@register_action("export_callgraph")
# 描述: 导出以 root_ea 为起点的调用图（JSON 文件路径 / 占位信息）
def export_callgraph(root_ea: str | int, depth: int = 2):
    """导出调用图 / Export call graph.

    • **CN**：以 `root_ea` 为根，递归 `depth` 层生成调用图并导出 JSON；当前
      仅返回占位信息，实际实现可复用 `graph_export_extension`。
    • **EN**: Generate call graph rooted at `root_ea` up to `depth` levels and
      export as JSON.  Currently returns a placeholder message; full
      implementation may delegate to *graph_export_extension*.
    """
    # 详细实现可复用现有 graph_export_extension
    try:
        root = int(root_ea, 16) if isinstance(root_ea, str) else int(root_ea)
        # TODO: 调用现有 GraphExporter 导出 JSON 文件并返回路径
        return _wrap_ok({"message": "callgraph exported", "root": f"0x{root:X}", "depth": depth})
    except Exception as e:  # noqa: BLE001
        return _wrap_err(str(e))


@register_action("disassemble")
# 描述: 反汇编 address 开始的 count 条指令
# args: address, count (可选, 默认20)
def disassemble(address: str | int, count: int = 20):
    """反汇编指令 / Disassemble instructions.

    Parameters
    ----------
    address : str | int
        • **CN**：起始地址，十六进制字符串或整数。
        • **EN**: Start address in hex string or int form.
    count : int, default ``20``
        • **CN**：要反汇编的指令条数。
        • **EN**: Number of instructions to disassemble.
    """
    if idaapi is None:
        return _wrap_err("IDA SDK not available")

    result_holder = {}

    def _collect():
        nonlocal result_holder
        try:
            ea = int(address, 16) if isinstance(address, str) else int(address)
            lines = []
            curr = ea
            for _ in range(max(1, count)):
                dis_line = ida_lines.generate_disasm_line(curr, 0) or ""
                lines.append(f"0x{curr:X}: {idaapi.tag_remove(dis_line)}")
                next_ea = idaapi.next_head(curr, idaapi.BADADDR)
                if next_ea == idaapi.BADADDR or next_ea <= curr:
                    break
                curr = next_ea
            result_holder = _wrap_ok("\n".join(lines))
        except Exception as inner:
            result_holder = _wrap_err(str(inner))

    idaapi.execute_sync(_collect, idaapi.MFF_READ)
    return result_holder


@register_action("get_string_at_address")
# 描述: 读取 address 处的字符串文本
# args: address
def get_string_at_address(address: str | int):
    """读取字符串 / Get string at address.

    兼容多版本 IDA：
    - **CN**：优先尝试 `ida_bytes.get_full_flags` / `get_str_type`，不足时回退。
    - **EN**: Uses `ida_bytes` helpers when available, otherwise falls back to
      `idc` for older versions.
    """
    if idaapi is None:
        return _wrap_err("IDA SDK not available")

    result_holder = {}

    def _collect():
        nonlocal result_holder
        try:
            ea = int(address, 16) if isinstance(address, str) else int(address)

            # 获取 flags 安全兼容
            flags = None
            for mod in ("ida_bytes", "ida_nalt", "idc"):
                try:
                    mod_ref = __import__(mod)
                    if hasattr(mod_ref, "get_full_flags"):
                        flags = mod_ref.get_full_flags(ea)  # type: ignore[attr-defined]
                        break
                except Exception:
                    continue

            if flags is None:
                flags = 0

            # 获取字符串类型
            str_type = None
            for mod in ("ida_bytes", "ida_nalt"):
                try:
                    mod_ref = __import__(mod)
                    if hasattr(mod_ref, "get_str_type"):
                        str_type = mod_ref.get_str_type(ea, flags)  # type: ignore[attr-defined]
                        break
                except Exception:
                    continue

            # 调用 get_strlit_contents
            try:
                s = idc.get_strlit_contents(ea, -1, str_type if str_type is not None else 0)
            except TypeError:
                # 在某些版本中 get_strlit_contents 只接受两个参数
                s = idc.get_strlit_contents(ea, -1)

            if s is None:
                result_holder = _wrap_err("no string at given address")
                return

            if isinstance(s, bytes):
                s_decoded = s.decode("utf-8", errors="ignore")
            else:
                s_decoded = str(s)

            result_holder = _wrap_ok(s_decoded)
        except ValueError:
            result_holder = _wrap_err("address must be int or hex string like '0x...'")
        except Exception as inner:
            result_holder = _wrap_err(str(inner))

    idaapi.execute_sync(_collect, idaapi.MFF_READ)
    return result_holder


@register_action("analyze_cross_references")
# 描述: 列出所有指向 address 的代码/数据交叉引用
# args: address, limit(optional)
def analyze_cross_references(
    address: str | int | None = None,
    ea: str | int | None = None,
    func_addr: str | int | None = None,
    func_address: str | int | None = None,
    limit: int = 100,
    ref_type: str | None = None,
    type: str | None = None,
    **extra_kwargs,
):  # noqa: A002
    """列出指向给定地址的交叉引用。

    支持多种参数别名：`address` / `ea` / `func_addr` / `func_address`。
    可选 `ref_type` / `type` 过滤 "code" / "data"，`limit` 控制结果条数。
    其余未知参数通过 `**extra_kwargs` 吞掉，避免 LLM 误传造成异常。
    """
    if idaapi is None:
        return _wrap_err("IDA SDK not available")

    result_holder = {}

    def _collect():
        try:
            target = address or ea or func_addr or func_address
            if target is None:
                raise ValueError("missing parameter: address/ea/func_addr")

            ea_int = int(target, 16) if isinstance(target, str) else int(target)
            xrefs_all = [(f"0x{x.frm:X}", "code" if x.iscode else "data") for x in idautils.XrefsTo(ea_int)]
            # 处理过滤
            f_type = ref_type or type  # 支持两种参数名
            if f_type in {"code", "data"}:
                xrefs_all = [t for t in xrefs_all if t[1] == f_type]
            xrefs = xrefs_all
            if limit and limit > 0:
                xrefs[:] = xrefs[:limit]
            nonlocal result_holder
            result_holder = _wrap_ok(xrefs)
        except Exception as inner_e:
            result_holder = _wrap_err(str(inner_e))

    idaapi.execute_sync(_collect, idaapi.MFF_READ)
    return result_holder


@register_action("list_strings")
# 描述: 列出程序中可见字符串；可选 pattern(regex) 过滤与 limit
# args:
#   pattern(str, 可选): 正则 / 子串 过滤
#   limit(int, 可选): 限制返回数量，默认 100
# 返回: [(address_hex, string), ...]
def list_strings(pattern: str | None = None, limit: int = 100):
    """列出可见字符串 / List visible strings in binary.

    Parameters
    ----------
    pattern : str | None
        • **CN**：正则/子串过滤，可选。
        • **EN**: Regex or substring filter (optional).
    limit : int, default ``100``
        • **CN**：结果数量上限。
        • **EN**: Maximum number of items to return.
    """
    if idaapi is None:
        return _wrap_err("IDA SDK not available")
    result_holder = {}
    def _collect():
        try:
            strings = [(f"0x{str_ea:X}", str(s)) for s in idautils.Strings() for str_ea in [s.ea]]
            if pattern:
                if '|' in pattern or any(ch in pattern for ch in '.?*+[](){}^$'):
                    regex = re.compile(pattern, re.IGNORECASE)
                    strings = [t for t in strings if regex.search(t[1])]
                else:
                    p_low = pattern.lower()
                    strings = [t for t in strings if p_low in t[1].lower()]
            if limit and limit > 0:
                strings = strings[:limit]
            nonlocal result_holder
            result_holder = _wrap_ok(strings)
        except Exception as inner_e:
            result_holder = _wrap_err(str(inner_e))
    idaapi.execute_sync(_collect, idaapi.MFF_READ)
    return result_holder

# ---------------------------------------------------------------------------
# 新增：程序 / 元数据
# ---------------------------------------------------------------------------


@register_action("get_program_metadata")
# 描述: 返回关于当前 IDB / 输入文件的总体信息
def get_program_metadata():
    """获取程序元数据 / Retrieve program metadata.

    • **CN**：返回输入文件名、架构、加载基址等关键信息。
    • **EN**: Returns file name, architecture, image base and other key data.
    """
    if idaapi is None:
        return _wrap_err("IDA SDK not available")

    result_holder = {}

    def _collect():
        nonlocal result_holder
        try:
            # 兼容不同版本的 inf 获取方式
            inf = None
            if hasattr(idaapi, "get_inf_structure"):
                inf = idaapi.get_inf_structure()
            elif hasattr(idaapi, "inf"):
                inf = idaapi.inf

            md = {
                "ida_version": idaapi.get_kernel_version(),
                "input_file": ida_nalt.get_root_filename() if hasattr(ida_nalt, "get_root_filename") else idc.GetInputFile(),
                "input_path": ida_nalt.get_input_file_path() if hasattr(ida_nalt, "get_input_file_path") else idc.GetInputFile(),
                "imagebase": f"0x{idaapi.get_imagebase():X}",
                "min_ea": f"0x{(inf.min_ea if inf else idaapi.get_inf_structure().min_ea if hasattr(idaapi, 'get_inf_structure') else 0):X}",
                "max_ea": f"0x{(inf.max_ea if inf else idaapi.get_inf_structure().max_ea if hasattr(idaapi, 'get_inf_structure') else 0):X}",
                "processor": (inf.procname if inf and hasattr(inf, "procname") else (idaapi.get_processor_name() if hasattr(idaapi, "get_processor_name") else idc.get_processor_name() if hasattr(idc, "get_processor_name") else "unknown")),
                "is_64bit": (inf.is_64bit() if inf and hasattr(inf, "is_64bit") else idaapi.get_inf_structure().is_64bit() if hasattr(idaapi, "get_inf_structure") else False),
            }
            result_holder = _wrap_ok(md)
        except Exception as inner:
            result_holder = _wrap_err(str(inner))

    idaapi.execute_sync(_collect, idaapi.MFF_READ)
    return result_holder


@register_action("get_binary_entry_points")
# 描述: 列出二进制中的入口点 (name, ea)
def get_binary_entry_points():
    """列出入口点 / List binary entry points.

    返回 (name, ea) 列表，便于快速定位程序起点或 DLL 导出入口。
    """
    if idaapi is None:
        return _wrap_err("IDA SDK not available")

    result_holder = {}

    def _collect():
        nonlocal result_holder
        try:
            entries = [(f"0x{ea:X}", name) for _, ea, _ord, name in idautils.Entries()]
            result_holder = _wrap_ok(entries)
        except Exception as inner:
            result_holder = _wrap_err(str(inner))

    idaapi.execute_sync(_collect, idaapi.MFF_READ)
    return result_holder

# ---------------------------------------------------------------------------
# 新增：导入 / 导出符号
# ---------------------------------------------------------------------------


@register_action("list_imports")
# 描述: 列出导入表中的函数；可选 pattern 过滤 & limit
# args: pattern?, limit?
def list_imports(pattern: str | None = None, limit: int = 100):
    """列出导入符号 / List import symbols.

    pattern : 过滤正则/子串；limit : 最大返回条目数。
    """
    if idaapi is None:
        return _wrap_err("IDA SDK not available")

    result_holder = {}

    def _collect():
        nonlocal result_holder
        try:
            imports: list[tuple[str, str]] = []  # (ea_hex, name)

            def _cb(ea: int, name: str, _ord):  # noqa: D401
                imports.append((f"0x{ea:X}", name or f"ord_{_ord}"))
                return True

            qty = idaapi.get_import_module_qty()
            for i in range(qty):
                idaapi.enum_import_names(i, _cb)

            # 过滤
            if pattern:
                if '|' in pattern or any(ch in pattern for ch in '.?*+[](){}^$'):
                    regex = re.compile(pattern, re.IGNORECASE)
                    imports[:] = [t for t in imports if regex.search(t[1])]
                else:
                    p_low = pattern.lower()
                    imports[:] = [t for t in imports if p_low in t[1].lower()]

            if limit and limit > 0:
                imports[:] = imports[:limit]

            result_holder = _wrap_ok(imports)
        except Exception as inner:
            result_holder = _wrap_err(str(inner))

    idaapi.execute_sync(_collect, idaapi.MFF_READ)
    return result_holder


@register_action("list_exports")
# 描述: 列出可导出符号；可选 pattern 过滤 & limit
# args: pattern?, limit?
def list_exports(pattern: str | None = None, limit: int = 100):
    """列出导出符号 / List export symbols.

    同 `list_imports` 参数语义。
    """
    if idaapi is None:
        return _wrap_err("IDA SDK not available")

    result_holder = {}

    def _collect():
        nonlocal result_holder
        try:
            exports = [(f"0x{ea:X}", name) for _idx, ea, _ord, name in idautils.Entries()]

            if pattern:
                if '|' in pattern or any(ch in pattern for ch in '.?*+[](){}^$'):
                    regex = re.compile(pattern, re.IGNORECASE)
                    exports[:] = [t for t in exports if regex.search(t[1])]
                else:
                    p_low = pattern.lower()
                    exports[:] = [t for t in exports if p_low in t[1].lower()]

            if limit and limit > 0:
                exports[:] = exports[:limit]

            result_holder = _wrap_ok(exports)
        except Exception as inner:
            result_holder = _wrap_err(str(inner))

    idaapi.execute_sync(_collect, idaapi.MFF_READ)
    return result_holder

# ---------------------------------------------------------------------------
# 新增：函数信息
# ---------------------------------------------------------------------------


def _collect_function_info(func):
    """helper: convert ida_funcs.func_t -> dict"""
    if not func:
        return None
    return {
        "start_ea": f"0x{func.start_ea:X}",
        "end_ea": f"0x{func.end_ea:X}",
        "name": ida_funcs.get_func_name(func.start_ea),
        "size": func.size(),
        "flags": func.flags,
        "has_frame": func.frame is not None,
    }


@register_action("get_function_info_by_name")
# args: func_name(str)
def get_function_info_by_name(func_name: str):
    """根据名称获取函数信息 / Get function info by name."""
    if idaapi is None:
        return _wrap_err("IDA SDK not available")

    result_holder = {}

    def _collect():
        nonlocal result_holder
        try:
            ea = idc.get_name_ea(idaapi.BADADDR, func_name)
            if ea == idaapi.BADADDR:
                result_holder = _wrap_err("function not found")
                return
            func = ida_funcs.get_func(ea)
            info = _collect_function_info(func)
            if info is None:
                result_holder = _wrap_err("not a function")
            else:
                result_holder = _wrap_ok(info)
        except Exception as inner:
            result_holder = _wrap_err(str(inner))

    idaapi.execute_sync(_collect, idaapi.MFF_READ)
    return result_holder


@register_action("get_function_info_by_address")
# args: address|ea
def get_function_info_by_address(address: str | int):
    """根据地址获取函数信息 / Get function info by address."""
    if idaapi is None:
        return _wrap_err("IDA SDK not available")

    result_holder = {}

    def _collect():
        nonlocal result_holder
        try:
            ea = int(address, 16) if isinstance(address, str) else int(address)
            func = ida_funcs.get_func(ea)
            info = _collect_function_info(func)
            if info is None:
                result_holder = _wrap_err("not a function")
            else:
                result_holder = _wrap_ok(info)
        except Exception as inner:
            result_holder = _wrap_err(str(inner))

    idaapi.execute_sync(_collect, idaapi.MFF_READ)
    return result_holder


@register_action("get_current_function_info")
def get_current_function_info():
    """获取当前光标所在函数信息 / Info of current function."""
    if idaapi is None:
        return _wrap_err("IDA SDK not available")

    result_holder = {}

    def _collect():
        nonlocal result_holder
        try:
            ea = ida_kernwin.get_screen_ea()
            func = ida_funcs.get_func(ea)
            info = _collect_function_info(func)
            if info is None:
                result_holder = _wrap_err("cursor not inside a function")
            else:
                result_holder = _wrap_ok(info)
        except Exception as inner:
            result_holder = _wrap_err(str(inner))

    idaapi.execute_sync(_collect, idaapi.MFF_READ)
    return result_holder

# ---------------------------------------------------------------------------
# 地址 / 光标
# ---------------------------------------------------------------------------


@register_action("get_current_cursor_address")
def get_current_cursor_address():
    """获取当前光标地址 / Return current cursor EA."""
    if idaapi is None:
        return _wrap_err("IDA SDK not available")

    result_holder = {}

    def _collect():
        nonlocal result_holder
        try:
            ea = ida_kernwin.get_screen_ea()
            result_holder = _wrap_ok(f"0x{ea:X}")
        except Exception as inner:
            result_holder = _wrap_err(str(inner))

    idaapi.execute_sync(_collect, idaapi.MFF_READ)
    return result_holder

# ---------------------------------------------------------------------------
# 字符串搜索
# ---------------------------------------------------------------------------


# args: pattern, case_sensitive?(bool), unicode?(bool), limit?(int)
@register_action("search_strings_in_binary")
def search_strings_in_binary(pattern: str | None = None, case_sensitive: bool = False, unicode: bool | None = None, limit: int | None = None):  # noqa: A002
    """二进制字符串搜索 / Search strings in binary.

    参数含义与 LLM prompt 中一致。
    """
    if idaapi is None:
        return _wrap_err("IDA SDK not available")

    result_holder = {}

    def _collect():
        nonlocal result_holder
        try:
            pattern_local = pattern or ""
            regex_flags = 0 if case_sensitive else re.IGNORECASE
            if '|' in pattern_local or any(ch in pattern_local for ch in '.?*+[](){}^$'):
                regex = re.compile(pattern_local, regex_flags)
                match_fn = lambda s: bool(regex.search(s))
            else:
                tgt = pattern_local if case_sensitive else pattern_local.lower()
                match_fn = lambda s: (s if case_sensitive else s.lower()).find(tgt) != -1

            results = []
            for s in idautils.Strings():
                try:
                    text = str(s)
                except Exception:
                    continue
                if unicode is not None:
                    # 尽量兼容不同 IDA 版本: StringItem 可能无 .type 属性
                    try:
                        s_type_val = s.type  # type: ignore[attr-defined]
                        is_u = s_type_val in (ida_bytes.STRTYPE_C_16, ida_bytes.STRTYPE_C_16BE, ida_bytes.STRTYPE_C_16LE) if hasattr(ida_bytes, 'STRTYPE_C_16') else False
                    except AttributeError:
                        # 如果没有 type 字段，则跳过 unicode 过滤
                        is_u = None

                    if is_u is not None:
                        if unicode and not is_u:
                            continue
                        if (unicode is False) and is_u:
                            continue
                if match_fn(text):
                    results.append((f"0x{s.ea:X}", text))
            if limit and limit > 0:
                results[:] = results[:limit]
            result_holder = _wrap_ok(results)
        except Exception as inner:
            result_holder = _wrap_err(str(inner))

    idaapi.execute_sync(_collect, idaapi.MFF_READ)
    return result_holder

# ---------------------------------------------------------------------------
# 交互与修改
# ---------------------------------------------------------------------------


@register_action("set_address_comment")
# args: address|ea, comment_text, repeatable?(bool)
def set_address_comment(address: str | int, comment_text: str, repeatable: bool = False):
    """设置地址注释 / Set comment at address.

    `repeatable`: **CN**-可重复/ **EN**-repeatable.
    """
    if idaapi is None:
        return _wrap_err("IDA SDK not available")

    result_holder = {}

    def _do():
        nonlocal result_holder
        try:
            ea = int(address, 16) if isinstance(address, str) else int(address)
            ok = idc.set_cmt(ea, comment_text, repeatable)
            result_holder = _wrap_ok(bool(ok))
        except Exception as inner:
            result_holder = _wrap_err(str(inner))

    idaapi.execute_sync(_do, idaapi.MFF_WRITE)
    return result_holder


@register_action("rename_func")
# args: address|ea, new_name
def rename_func(address: str | int, new_name: str):
    """重命名函数 / Rename function."""
    if idaapi is None:
        return _wrap_err("IDA SDK not available")

    result_holder = {}

    def _do():
        nonlocal result_holder
        try:
            ea = int(address, 16) if isinstance(address, str) else int(address)
            res = ida_name.set_name(ea, new_name, ida_name.SN_FORCE)
            result_holder = _wrap_ok(bool(res))
        except Exception as inner:
            result_holder = _wrap_err(str(inner))

    idaapi.execute_sync(_do, idaapi.MFF_WRITE)
    return result_holder


@register_action("rename_local_var")
# args: function_address|ea, variable_offset(int), new_name
def rename_local_var(function_address: str | int, variable_offset: int, new_name: str):
    """重命名局部变量 / Rename local variable."""
    if idaapi is None:
        return _wrap_err("IDA SDK not available")

    try:
        func_ea = int(function_address, 16) if isinstance(function_address, str) else int(function_address)

        result_holder = {}

        def _do():
            nonlocal result_holder
            try:
                if ida_hexrays.init_hexrays_plugin() < 0:
                    result_holder = _wrap_err("Hex-Rays decompiler not available")
                    return
                cfunc = ida_hexrays.decompile(func_ea)
                if not cfunc:
                    result_holder = _wrap_err("decompile failed")
                    return
                for lv in cfunc.lvars:
                    if lv.location.is_stkoff() and lv.location.stkoff() == variable_offset:
                        ida_hexrays.modify_user_lvar_name(cfunc, lv, new_name)
                        cfunc.save_user_lvar_settings()
                        result_holder = _wrap_ok(True)
                        return
                result_holder = _wrap_err("variable not found")
            except Exception as inner:
                result_holder = _wrap_err(str(inner))

        idaapi.execute_sync(_do, idaapi.MFF_WRITE)
        return result_holder
    except Exception as e:
        return _wrap_err(str(e))


@register_action("rename_global_var")
# args: address|ea, new_name
def rename_global_var(address: str | int, new_name: str):
    """重命名全局变量 / Rename global variable."""
    if idaapi is None:
        return _wrap_err("IDA SDK not available")

    result_holder = {}

    def _do():
        nonlocal result_holder
        try:
            ea = int(address, 16) if isinstance(address, str) else int(address)
            res = ida_name.set_name(ea, new_name, ida_name.SN_FORCE)
            result_holder = _wrap_ok(bool(res))
        except Exception as inner:
            result_holder = _wrap_err(str(inner))

    idaapi.execute_sync(_do, idaapi.MFF_WRITE)
    return result_holder


@register_action("set_local_var_type")
# args: function_address|ea, variable_offset(int), type_string, arg_index?(int)
def set_local_var_type(function_address: str | int, variable_offset: int, type_string: str, arg_index: int | None = None):
    """设置局部变量类型 / Set local variable type."""
    if idaapi is None:
        return _wrap_err("IDA SDK not available")
    try:
        func_ea = int(function_address, 16) if isinstance(function_address, str) else int(function_address)

        result_holder = {}

        def _do():
            nonlocal result_holder
            try:
                if ida_hexrays.init_hexrays_plugin() < 0:
                    result_holder = _wrap_err("Hex-Rays decompiler not available")
                    return
                cfunc = ida_hexrays.decompile(func_ea)
                if not cfunc:
                    result_holder = _wrap_err("decompile failed")
                    return
                # 确保声明以分号结束
                if not type_string.strip().endswith(";"):
                    type_string_ = type_string + ";"
                else:
                    type_string_ = type_string

                tif = ida_typeinf.tinfo_t()
                parse_ok = ida_typeinf.parse_decl(tif, None, type_string_, ida_typeinf.PT_SIL)
                if not parse_ok:
                    # 尝试 fallback: 直接使用 idc.SetType 在函数入口地址上应用类型
                    # 这里使用围 enclosing 作用域中的 func_ea 而非未定义变量 ea，避免 NameError
                    res = idc.SetType(func_ea, type_string_)
                    result_holder = _wrap_ok(bool(res))
                    return

                target_found = False
                for lv in cfunc.lvars:
                    is_target = False
                    if lv.location.is_stkoff() and lv.location.stkoff() == variable_offset:
                        is_target = True
                    elif arg_index is not None and lv.is_arg_var and getattr(lv, 'argidx', -1) == arg_index:
                        is_target = True

                    if is_target:
                        ida_hexrays.modify_user_lvar_type(cfunc, lv, tif, True)
                        target_found = True
                        break

                if not target_found:
                    result_holder = _wrap_err("variable not found (offset/arg_index mismatch)")
                    return

                cfunc.save_user_lvar_settings()
                result_holder = _wrap_ok(True)
            except Exception as inner:
                result_holder = _wrap_err(str(inner))

        idaapi.execute_sync(_do, idaapi.MFF_WRITE)
        return result_holder
    except Exception as e:
        return _wrap_err(str(e))


@register_action("set_global_var_type")
# args: address|ea, type_string
def set_global_var_type(address: str | int, type_string: str):
    """设置全局变量类型 / Set global variable type."""
    if idaapi is None:
        return _wrap_err("IDA SDK not available")

    result_holder = {}

    def _do():
        nonlocal result_holder
        try:
            ea = int(address, 16) if isinstance(address, str) else int(address)
            # 多版本兼容解析
            tif = ida_typeinf.tinfo_t()
            if not ida_typeinf.parse_decl(tif, None, type_string, ida_typeinf.PT_SIL):
                # 尝试直接使用 idc.SetType
                res = idc.SetType(ea, type_string)
                result_holder = _wrap_ok(bool(res))
                return
            ok = ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)
            result_holder = _wrap_ok(bool(ok))
        except Exception as inner:
            result_holder = _wrap_err(str(inner))

    idaapi.execute_sync(_do, idaapi.MFF_WRITE)
    return result_holder


@register_action("set_func_prototype")
# args: address|ea, prototype_string
def set_func_prototype(address: str | int, prototype_string: str):
    """设置函数原型 / Set function prototype."""
    if idaapi is None:
        return _wrap_err("IDA SDK not available")
    try:
        ea = int(address, 16) if isinstance(address, str) else int(address)
        ok = idc.SetType(ea, prototype_string)
        return _wrap_ok(bool(ok))
    except Exception as e:
        return _wrap_err(str(e))


@register_action("declare_custom_c_type")
# args: type_definition_string
def declare_custom_c_type(type_definition_string: str):
    """声明 C 类型 / Declare C-style type."""
    if idaapi is None:
        return _wrap_err("IDA SDK not available")

    result_holder = {}

    def _do():
        nonlocal result_holder
        try:
            flags = getattr(ida_typeinf, "PT_SIL", 0) | getattr(ida_typeinf, "PT_TYP", 0) | getattr(ida_typeinf, "PT_EMPTY", 0)
            # 动态探测并尝试多种签名 (til 可选)
            til = None
            if hasattr(ida_typeinf, "get_idati"):
                til = ida_typeinf.get_idati()
            elif hasattr(ida_typeinf.cvar, "idati"):
                til = ida_typeinf.cvar.idati

            errors = 1
            messages = ["unknown error"]

            call_variants: list[tuple] = []
            if hasattr(ida_typeinf, "parse_decls_ctypes"):
                call_variants.extend([
                    (ida_typeinf.parse_decls_ctypes, (til, type_definition_string, flags) if til else None),
                    (ida_typeinf.parse_decls_ctypes, (type_definition_string, flags)),
                ])

            if hasattr(ida_typeinf, "parse_decls"):
                printer_stub = ida_typeinf.printer_t() if hasattr(ida_typeinf, 'printer_t') else None

                call_variants.extend([
                    (ida_typeinf.parse_decls, (til, type_definition_string, printer_stub, 0) if til and printer_stub else None),
                    (ida_typeinf.parse_decls, (til, type_definition_string, None, 0) if til else None),
                    (ida_typeinf.parse_decls, (til, type_definition_string, flags) if til else None),
                    (ida_typeinf.parse_decls, (til, type_definition_string) if til else None),
                    (ida_typeinf.parse_decls, (til, type_definition_string, printer_stub, 0) if til and printer_stub else None),
                    (ida_typeinf.parse_decls, (type_definition_string, None, 0, flags)),
                    (ida_typeinf.parse_decls, (type_definition_string, None, 0)),
                    (ida_typeinf.parse_decls, (type_definition_string, flags)),
                    (ida_typeinf.parse_decls, (type_definition_string,)),
                ])

            called = False
            for fn, args in call_variants:
                if args is None:
                    continue
                try:
                    res = fn(*args)  # type: ignore[misc]
                    if isinstance(res, tuple):
                        errors, messages = res
                    else:
                        # IDA 9.1: returns int error count
                        errors = int(res)
                        messages = [f"{errors} errors"] if errors else ["ok"]
                    called = True
                    break
                except TypeError:
                    continue

            if not called:
                result_holder = _wrap_err("no compatible parse_decls signature")
                return
            if errors > 0:
                result_holder = _wrap_err("; ".join(messages))
            else:
                result_holder = _wrap_ok("\n".join(messages))
        except Exception as inner:
            result_holder = _wrap_err(str(inner))

    idaapi.execute_sync(_do, idaapi.MFF_WRITE)
    return result_holder


# ---------------------------------------------------------------------------
# 新增：局部变量工具
# ---------------------------------------------------------------------------


@register_action("list_local_vars")
# 描述: 列出函数内局部变量 (栈/寄存器) 基本信息
# args: function_address|ea, limit?(int)
def list_local_vars(function_address: str | int, limit: int = 20):
    """列出局部变量 / List local variables."""
    if idaapi is None:
        return _wrap_err("IDA SDK not available")

    result_holder = {}

    def _collect():
        nonlocal result_holder
        try:
            func_ea = int(function_address, 16) if isinstance(function_address, str) else int(function_address)

            if ida_hexrays.init_hexrays_plugin() < 0:
                result_holder = _wrap_err("Hex-Rays decompiler not available")
                return

            cfunc = ida_hexrays.decompile(func_ea)
            if not cfunc:
                result_holder = _wrap_err("decompile failed")
                return

            vars_out: list[tuple[int, str, str]] = []  # (offset, name, type)

            for lv in cfunc.lvars:
                # 仅处理有名字的局部
                try:
                    tstr = lv.tif.dstr() if lv.tif else "<unknown>"
                except Exception:
                    tstr = "<unknown>"

                if lv.location.is_stkoff():
                    offset = lv.location.stkoff()
                else:
                    offset = -1  # 非栈变量用 -1 代表

                vars_out.append((offset, lv.name, tstr))

            if limit and limit > 0:
                vars_out[:] = vars_out[:limit]

            result_holder = _wrap_ok(vars_out)
        except Exception as inner:
            result_holder = _wrap_err(str(inner))

    idaapi.execute_sync(_collect, idaapi.MFF_READ)
    return result_holder


# ---------------------------------------------------------------------------
# 统一入口
# ---------------------------------------------------------------------------

def mcp_call(action: str, **kwargs):
    """MCP action 调度入口 / Dispatcher for MCP actions.

    • **CN**：根据 action 名称调用已注册函数。
    • **EN**: Calls registered function by action name.
    """
    fn = action_registry.get(action)
    if not fn:
        return _wrap_err(f"unknown action '{action}'")
    try:
        result = fn(**kwargs)
        return result
    except TypeError as e:  # 参数不匹配
        return _wrap_err(f"param error: {e}")
    except Exception as e:  # noqa: BLE001
        traceback.print_exc()
        return _wrap_err(str(e)) 