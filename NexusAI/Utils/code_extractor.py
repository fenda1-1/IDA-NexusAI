"""
Code extraction utilities for IDA Pro.

Extract assembly instructions or decompiled pseudocode for functions or
arbitrary selections. Provides helpers to recursively gather call-chains,
include local type definitions, and generate human-readable cross-reference
information.

代码提取工具，用于在 IDA Pro 中提取汇编指令或反编译伪代码。

支持递归收集函数调用链、提取局部类型定义，并为输出添加可读的交叉引用信息。
"""

import idaapi
import idc
import idautils
import ida_xref
import ida_hexrays  # 用于类型信息处理
from idaapi import tag_remove, msg, get_screen_ea, BADADDR, generate_disasm_line, next_head, read_range_selection
from idc import get_func_attr  # 恢复简写以兼容旧代码
from ..Config.config import ConfigManager

class CodeExtractor:
    """
    Extract assembly or decompiled pseudocode from IDA Pro.

    从 IDA Pro 提取汇编指令或反编译伪代码的辅助类。
    """
    def __init__(self):
        """
        Initialize the CodeExtractor instance and load global configuration.

        初始化 CodeExtractor 实例并加载全局配置。
        """
        self.config = ConfigManager()  # 访问全局配置

    def extract_current_function_recursive(self, max_depth: int = 2):
        """
        Extract the current function and, recursively, its callees up to
        *max_depth* levels. The routine prefers decompiled pseudocode but will
        gracefully fall back to raw assembly if Hex-Rays decompilation is not
        available.

        提取当前函数及其调用链（深度由 *max_depth* 控制）的反编译伪代码。
        当反编译不可用时，会自动回退到汇编指令。

        Args:
            max_depth (int): Recursion depth. ``0`` 表示仅提取当前函数。
        """
        current_ea = get_screen_ea() # 获取当前光标地址
        func_start = get_func_attr(current_ea, idc.FUNCATTR_START) # 获取当前函数起始地址

        if func_start == BADADDR:
            # 如果无法获取函数起始地址，抛出错误
            raise ValueError("未能定位到函数起始地址，请将光标置于函数内部。")

        if self.config.language == "en_US":
            msg(f"[*] NexusAI: Extracting current function and its call chain code (depth: {max_depth})...\n")
        else:
            msg(f"[*] NexusAI: 正在提取当前函数及其调用链代码 (深度: {max_depth})...\n")
        processed_funcs = set() # 用于跟踪已处理的函数，避免无限递归
        func_disasm_list = [] # 存储提取到的函数代码字符串列表

        include_types = self.config.analysis_options.get("include_type_definitions", True)
        type_definitions = self._extract_local_types(func_start) if include_types else ""

        # 开始递归提取
        self._extract_recursive(func_start, max_depth, processed_funcs, func_disasm_list)

        if not func_disasm_list:
             # 如果列表为空，说明未能提取到任何代码
             raise ValueError("未能提取到任何函数代码。")

        msg("[*] NexusAI: Code extraction completed.\n" if self.config.language == "en_US" else "[*] NexusAI: 代码提取完成。\n")

        joined_code = "\n".join(func_disasm_list)

        # 如果提取到了类型定义，则将其放在最前面
        if type_definitions:
            return f"/* === Local Type Definitions === */\n{type_definitions}\n\n{joined_code}"
        else:
            return joined_code

    # ------------------------------------------------------------------
    # 新增: 提取局部变量使用到的结构体与枚举定义
    # ------------------------------------------------------------------
    def _extract_local_types(self, func_ea):
        """
        Collect struct/union/enum definitions referenced by local variables
        and function arguments, returning them as C declarations.

        提取当前函数的局部变量及参数所引用的结构体、联合或枚举定义，并以
        C 语言声明字符串形式返回。
        """
        try:
            cfunc = ida_hexrays.decompile(func_ea)
        except Exception as e:
            msg(f"[!] NexusAI: 反编译函数失败，无法提取类型信息: {e}\n")
            return ""

        if not cfunc:
            return ""

        type_decls = {}

        # 遍历局部变量收集类型信息
        for lvar in cfunc.lvars:
            tif = lvar.tif
            if not tif:
                continue

            try:
                if tif.is_struct() or tif.is_union() or tif.is_enum():
                    type_name = tif.dstr()  # 获取类型名
                    if type_name in type_decls:
                        continue  # 已收集

                    # 打印类型定义
                    decl = idaapi.print_tinfo("", 0, 0,
                                              idaapi.PRTYPE_MULTI | idaapi.PRTYPE_TYPEDEF | idaapi.PRTYPE_CPP,
                                              tif, type_name, "")
                    if decl:
                        type_decls[type_name] = decl
            except Exception:
                # 遇到无法处理的类型时跳过
                continue

        # 有时函数参数也是感兴趣的
        for arg in cfunc.arguments:
            tif = arg.tif
            if not tif:
                continue
            try:
                if tif.is_struct() or tif.is_union() or tif.is_enum():
                    type_name = tif.dstr()
                    if type_name not in type_decls:
                        decl = idaapi.print_tinfo("", 0, 0,
                                                  idaapi.PRTYPE_MULTI | idaapi.PRTYPE_TYPEDEF | idaapi.PRTYPE_CPP,
                                                  tif, type_name, "")
                        if decl:
                            type_decls[type_name] = decl
            except Exception:
                continue

        # 返回合并后的声明
        return "\n\n".join(type_decls.values())

    def extract_selected_range(self):
        """
        Extract the code within the current selection in IDA. The function
        works for both disassembly and decompiler views.

        提取用户在 IDA 中当前选中的地址范围，可用于反汇编视图或反编译
        视图。
        """
        # read_range_selection 返回 (start_ea, end_ea) 如果有选中范围，否则返回 (BADADDR, BADADDR)
        valid_selection, start_ea, end_ea = read_range_selection(None)

        if start_ea == BADADDR or end_ea == BADADDR or start_ea >= end_ea:
            raise ValueError("未能获取有效的选中范围。请在IDA视图中选中一段代码。")

        # 显示明显的代码范围分隔符
        msg("=*50 +\n")
        label = "CODE RANGE" if self.config.language == "en_US" else "代码范围"
        msg(f"=================={label}====================\n")
        if self.config.language == "en_US":
            msg(f"[*] Selected code from {hex(start_ea)} to {hex(end_ea)}\n")
        else:
            msg(f"[*] 从地址 {hex(start_ea)} 到 {hex(end_ea)} 的选中代码\n")

        code_lines = []
        ea = start_ea
        # 遍历选中范围内的所有指令
        while ea < end_ea:
            # generate_disasm_line 返回指令的汇编字符串
            line_with_tags = generate_disasm_line(ea, 0)
            if line_with_tags:
                # 移除颜色标记，获取纯净的文本
                line = tag_remove(line_with_tags)
                # 在终端中显示每一行代码，添加前缀使其更明显
                msg(f"[*] {hex(ea)}     {line}\n")
                code_lines.append(line)
            # next_head 移动到下一个指令的起始地址
            next_ea = next_head(ea, end_ea)
            if next_ea == BADADDR or next_ea <= ea:
                break # 防止死循环
            ea = next_ea

        if not code_lines:
             raise ValueError("未能提取到选中范围内的任何指令。")

        # 显示结束分隔符
        msg(f"=================={label}====================\n")
        msg("=*50 +\n")

        # 添加范围信息作为注释，并返回格式化的代码
        return f"; Selected Code Range: {hex(start_ea)}-{hex(end_ea)}\n" + "\n".join(code_lines)

    def extract_function(self, func, max_depth: int = 0):
        """
        Extract *func* and, optionally, its callees up to *max_depth* levels.
        Decompilation is preferred; assembly is used as a fallback.

        提取给定函数及其调用链（由 *max_depth* 决定）的反编译代码；若
        反编译失败，则回退到汇编指令。

        Args:
            func: IDA function object to start from.
            max_depth (int): Recursion depth, ``0`` 表示仅提取 *func* 本身。

        Returns:
            str: Concatenated source of all extracted functions.
        """
        if not func:
            raise ValueError("无效的函数对象")
            
        func_ea = func.start_ea
        if self.config.language == "en_US":
            msg(f"[*] NexusAI: Extracting function code (depth: {max_depth})...\n")
        else:
            msg(f"[*] NexusAI: 正在提取函数代码 (深度: {max_depth})...\n")
        processed_funcs = set()  # 用于跟踪已处理的函数，避免无限递归
        func_disasm_list = []  # 存储提取到的函数代码字符串列表
        
        # 开始递归提取
        self._extract_recursive(func_ea, max_depth, processed_funcs, func_disasm_list)
        
        if not func_disasm_list:
            # 如果列表为空，说明未能提取到任何代码
            raise ValueError("未能提取到任何函数代码。")
            
        msg("[*] NexusAI: Code extraction completed.\n" if self.config.language == "en_US" else "[*] NexusAI: 代码提取完成。\n")
        return "\n".join(func_disasm_list)  # 将所有函数代码合并成一个字符串
        
    def extract_selection(self):
        """
        Alias for :py:meth:`extract_selected_range` kept for backward
        compatibility.

        与 :py:meth:`extract_selected_range` 等价，保留该别名以保持旧版
        API 兼容。

        Returns:
            str | None: Extracted code string or ``None`` if nothing selected.
        """
        try:
            return self.extract_selected_range()
        except ValueError:
            return None

    def _extract_recursive(self, func_ea, depth, processed_funcs, func_disasm_list):
        """
        Internal helper that appends code for *func_ea* and, recursively,
        for each callee until *depth* reaches zero.

        内部递归辅助函数：负责提取 *func_ea* 的代码并继续遍历其被调用者，
        直到 *depth* 递减至 0。
        """
        # 递归终止条件：已处理过该函数，或者深度小于0
        if func_ea in processed_funcs or depth < 0:
            return

        processed_funcs.add(func_ea) # 将当前函数标记为已处理
        func_name = idc.get_func_name(func_ea) or f"sub_{hex(func_ea)}" # 获取函数名或使用地址
        func_end = get_func_attr(func_ea, idc.FUNCATTR_END) # 获取函数结束地址

        # ---------- 交叉引用信息 ----------
        xref_info_str = ""
        if self.config.analysis_options.get("include_xrefs", True):
            callers = set()
            for xref in idautils.XrefsTo(func_ea):
                caller_name = idc.get_func_name(xref.frm)
                if caller_name:
                    callers.add(caller_name)

            callees = [idc.get_func_name(ea) or f"sub_{hex(ea)}" for ea in self._get_called_functions(func_ea)]

            if callers or callees:
                callers_str = ", ".join(sorted(callers)) if callers else "None"
                callees_str = ", ".join(sorted(set(callees))) if callees else "None"
                xref_info_str = f"// Called by: {callers_str}\n// Calls to: {callees_str}\n"

        # 显示明显的代码范围分隔符
        msg("=*50 +\n")
        label = "CODE RANGE" if self.config.language == "en_US" else "代码范围"
        msg(f"=================={label}====================\n")
        if self.config.language == "en_US":
            msg(f"[*] Function: {func_name} ({hex(func_ea)})\n")
        else:
            msg(f"[*] 函数: {func_name} ({hex(func_ea)})\n")

        try:
            # 尝试反编译函数
            decompiled_code = idaapi.decompile(func_ea)
            if decompiled_code:
                code_str = str(decompiled_code)
                # 添加注释和函数头，然后是反编译代码
                header = f"// Function: {func_name} ({hex(func_ea)})\n"
                if xref_info_str:
                    header += xref_info_str
                func_disasm_list.append(f"{header}{code_str}\n")
                
                # 显示部分代码行，避免输出过多
                lines = code_str.split('\n')
                if len(lines) > 10:
                    # 显示前5行和后5行，中间用省略号表示
                    for i, line in enumerate(lines[:5]):
                        msg(f"[*] {line}\n")
                    msg("[*]......\n")
                    for i, line in enumerate(lines[-5:]):
                        msg(f"[*] {line}\n")
                else:
                    # 显示全部代码
                    for line in lines:
                        msg(f"[*] {line}\n")
            else:
                 # 如果反编译失败，回退到提取汇编代码
                 msg(f"[!] NexusAI: 反编译函数 {func_name} 失败，回退到汇编.\n")
                 disasm_code = self._get_disassembly(func_ea)
                 # 添加注释和函数头，然后是汇编代码
                 header = f"; Function: {func_name} ({hex(func_ea)} - Disassembly Fallback)\n"
                 if xref_info_str:
                     header += xref_info_str
                 func_disasm_list.append(f"{header}{disasm_code}\n")
                 
                 # 显示部分汇编代码
                 lines = disasm_code.split('\n')
                 if len(lines) > 10:
                     # 显示前5行和后5行，中间用省略号表示
                     for i, line in enumerate(lines[:5]):
                         msg(f"[*] {hex(func_ea + i * 4)}     {line}\n")  # 这里地址计算是简化的
                     msg("[*]......\n")
                     for i, line in enumerate(lines[-5:]):
                         msg(f"[*] {hex(func_end - (5-i) * 4)}     {line}\n")  # 这里地址计算是简化的
                 else:
                     # 显示全部代码
                     ea = func_ea
                     for line in lines:
                         msg(f"[*] {hex(ea)}     {line}\n")
                         ea = next_head(ea, func_end)

        except Exception as e:
            # 捕获反编译或汇编提取失败的错误
            msg(f"[!] NexusAI: 提取函数 {func_name} 代码失败: {str(e)}\n")
            # traceback.print_exc() # 打印详细错误堆栈 (可选)
            # 即使提取失败，仍然尝试处理被调用者，以便遍历调用图

        # 显示结束分隔符
        msg(f"=================={label}====================\n")
        msg("=*50 +\n")

        # 处理被调用者，深度减1
        for callee_ea in self._get_called_functions(func_ea):
            self._extract_recursive(callee_ea, depth - 1, processed_funcs, func_disasm_list)

    def _get_disassembly(self, func_ea):
        """
        Return the raw disassembly listing of a single function.

        提取并返回单个函数的汇编指令列表。
        """
        disasm_lines = []
        func_end = get_func_attr(func_ea, idc.FUNCATTR_END) # 获取函数结束地址
        if func_end == BADADDR:
             return "" # 如果不是有效函数，返回空字符串

        ea = func_ea
        # 遍历函数内的所有指令
        while ea < func_end:
            line_with_tags = generate_disasm_line(ea, 0) # 生成指令的汇编字符串
            if line_with_tags:
                # 移除颜色标记，获取纯净的文本
                line = tag_remove(line_with_tags)
                disasm_lines.append(line)
            next_ea = next_head(ea, func_end) # 移动到下一条指令
            if next_ea == BADADDR or next_ea <= ea:
                break # 防止死循环
            ea = next_ea
        return "\n".join(disasm_lines) # 将所有汇编指令合并成一个字符串


    def _get_called_functions(self, func_ea):
        """
        Enumerate and return addresses of functions invoked by the function
        located at *func_ea*.

        枚举并返回位于 *func_ea* 的函数内部所调用的其他函数的地址集合。
        """
        callees = set() # 使用集合存储被调用者地址，自动去重
        func_end = get_func_attr(func_ea, idc.FUNCATTR_END)
        if func_end == BADADDR:
             return callees # 如果不是有效函数，返回空集合

        # 遍历函数内的所有地址
        for ea in range(func_ea, func_end):
            # 遍历从当前地址发出的所有交叉引用
            for xref in idautils.XrefsFrom(ea):
                # 检查是否是代码执行引用（调用或跳转）
                if xref.type in [ida_xref.fl_CN, ida_xref.fl_CF]:
                    callee_ea = xref.to # 获取引用的目标地址
                    # 确保目标地址是一个函数起始地址
                    if get_func_attr(callee_ea, idc.FUNCATTR_START) == callee_ea:
                        callees.add(callee_ea) # 将被调用者地址添加到集合
        return callees 