"""
Apply AI-generated comments to IDA Pro disassembly or pseudocode views.

This module centralizes helper routines to toggle comment mode, clean and
pre-process LLM output, ask the user how to merge with existing comments,
and write line, repeatable, anterior or function comments through both the
IDA disassembly and decompiler APIs.

应用 AI 生成的注释至 IDA Pro 的反汇编或反编译视图。

提供切换注释模式、清理及预处理 LLM 输出、提示用户合并策略，并通过反汇编
与反编译 API 写入行注释、可重复注释、前注释或函数注释等功能。
"""

import idaapi
import idc
import ida_funcs
import ida_kernwin
import ida_hexrays
import ida_lines
import ida_ua
import re
import time
import traceback
from typing import Union
from ..Config.config import ConfigManager as _Cfg

# ------------------------------------------------------------------
# 语言辅助函数: _t(cn, en) 根据当前语言返回中文或英文
# ------------------------------------------------------------------

def _current_lang() -> str:
    """获取最新语言设置，避免切换后仍使用旧值。"""
    try:
        return _Cfg().language
    except Exception:
        return "zh_CN"


def _t(cn: str, en: str) -> str:
    """根据最新语言返回对应文本。"""
    return en if _current_lang() == "en_US" else cn

# 若只提供中文，则尝试在此映射表中查找对应英文
_TRANS = {
    "默认使用追加策略": "Default to append strategy",
    "没有需要重置的设置": "No settings needed to reset",
    "刷新视图时出错": "Error refreshing view",
    "刷新窗口时出错": "Error refreshing window",
    "刷新反编译视图时出错": "Error refreshing pseudocode view",
    "强制刷新视图时出错": "Error during force refresh",
    "正在强制刷新所有视图": "Forcing refresh of all views",
    "视图刷新完成": "View refresh completed",
    "反编译插件未初始化": "Decompiler plugin not initialized",
    "已标记函数需要重新反编译": "Function marked for re-decompile",
    "无法应用函数注释，注释文本为空": "Cannot apply function comment, text empty",
    "用户取消了注释应用": "User cancelled comment application",
    "设置函数注释失败，可能是权限问题或地址无效": "Failed to set function comment, permission or invalid address",
    "在反编译视图中设置注释失败": "Failed to set comment in pseudocode view",
    "应用函数注释时出错": "Error applying function comment",
    "无法应用注释，注释文本为空": "Cannot apply comment, text empty",
    "批量注释失败: 注释文本为空": "Batch comment failed: text empty",
    "批量注释完成": "Batch comment completed",
    "无效的地址": "Invalid address",
    "设置注释失败，可能是权限问题或地址无效": "Failed to set comment, permission or invalid address"
}

def _auto_t(msg: str) -> str:
    """若当前语言为英语且消息是中文，尝试翻译"""
    if _current_lang() == "en_US":
        for zh, en in _TRANS.items():
            if zh in msg:
                return msg.replace(zh, en)
    return msg

# 用于选择注释覆盖策略的辅助函数
def _ask_comment_strategy():
    """弹出对话框询问用户在注释冲突时的处理策略。返回 'replace', 'append' 或 'cancel'"""
    try:
        # 使用基本的按钮对话框
        choice = ida_kernwin.ask_buttons(
            "替换", "追加", "取消", 1,
            "检测到目标地址已有注释，选择处理方式:\n\n替换: 用新的注释覆盖旧注释\n追加: 将新注释追加在旧注释之后\n取消: 取消本次注释操作"
        )
        
        # IDA 按钮返回值顺序与视觉顺序可能不同
        if choice == 0:
            return "append"  # 第二个按钮
        elif choice == 1:
            return "replace"  # 第一个按钮
        else:
            return "cancel"
    except Exception as e:
        # 如果对话框失败，尝试使用最简单的yes/no对话框
        log_message(_t(f"基本对话框显示失败: {str(e)}", f"Basic dialog display failed: {str(e)}"), "warning")
        try:
            choice = ida_kernwin.ask_yn(1, "检测到已有注释\n是替换(Yes)还是追加(No)?")
            if choice == 1:  # Yes
                return "replace"
            elif choice == 0:  # No
                return "append"
            else:  # -1, 取消
                return "cancel"
        except Exception as last_error:
            # 如果所有对话框方法都失败，默认追加
            log_message(_t(f"所有对话框方法都失败: {str(last_error)}", f"All dialog methods failed: {str(last_error)}"), "error")
            log_message(_t("默认使用追加策略", "Default to append strategy"), "warning")
            return "append"

def _merge_comments(old, new, strategy):
    """合并注释，strategy是字符串 'replace' 或 'append'"""
    if strategy == "replace":
        return new
    elif strategy == "append":
        sep = "\n" if old and not old.endswith("\n") else ""
        return f"{old}{sep}{new}"
    else:
        return None

# 避免循环导入，使用函数来动态获取log_message
def log_message(message, message_type="info"):
    """
    将消息记录到NexusAI窗口，使用适当的样式。
    
    Args:
        message: 消息内容
        message_type: 消息类型，可以是 "info", "success", "error", "warning"
    """
    # 动态导入，避免循环引用
    from ..UI.ui_view import log_message as ui_log_message
    ui_log_message(message, message_type)

class CommentApplicator:
    """
    High-level helper class that applies cleaned comment text to different
    locations inside IDA Pro (line, repeatable, anterior or whole function).

    将清理后的注释文本应用到 IDA Pro 中的行、可重复、前置或整函数注释的高
    级封装类。
    """
    def __init__(self):
        """初始化注释应用器。"""
        self.is_comment_mode_active = False  # 标记注释模式是否激活
        self.comment_text = ""  # 存储AI生成的注释文本
    
    def toggle_comment_mode(self, state=None):
        """
        Toggle the *comment mode* flag.

        切换 **注释模式** 开关。

        Args:
            state (Union[bool, None]): If provided, force the mode to the given
                value; otherwise the current state is inverted.

        Returns:
            bool: New state of *comment mode* / 返回新的注释模式状态。
        """
        if state is not None:
            # 直接设置为指定状态
            self.is_comment_mode_active = state
        else:
            # 切换当前状态
            self.is_comment_mode_active = not self.is_comment_mode_active
            
        log_message(_t(f"注释模式{'已开启' if self.is_comment_mode_active else '已关闭'}",
                       f"Comment mode {'enabled' if self.is_comment_mode_active else 'disabled'}"), "info")
        return self.is_comment_mode_active
    
    def reset_settings(self):
        """
        Reset all runtime settings maintained by the applicator, including
        the *comment mode* flag.

        重置应用器维护的所有运行时设置（包含注释模式开关）。

        Returns:
            bool: ``True`` if something changed, ``False`` otherwise.
        """
        result = False
        if self.is_comment_mode_active:
            self.is_comment_mode_active = False
            log_message(_t("已关闭注释模式", "Comment mode disabled"), "info")
            result = True
            
        if not result:
            log_message(_t("没有需要重置的设置", "No settings needed to reset"), "info")
        
        return result
    
    def set_comment_text(self, text):
        """
        Sanitize and store the raw comment text produced by an LLM so that it
        can later be applied to the database.

        清理并存储由 LLM 生成的原始注释文本，便于后续写入数据库。

        Args:
            text (str): Raw multiline comment content.
        """
        # 清理注释文本，删除多余的空行和格式化字符
        cleaned_text = text
        
        # 删除常见的系统消息开头
        system_markers = [
            "NexusAI:", "✅", "❌", "ℹ️", "💡", 
            "<div", "<span", "<b>", "</b>", "<hr",
            "分析完成", "Analysis complete", "回复开始", "AI Response",
            "请为以下函数生成"
        ]
        
        # 分行处理，去除系统消息行
        lines = []
        for line in cleaned_text.split('\n'):
            line = line.strip()
            # 跳过空行和系统消息行
            if not line or any(marker in line for marker in system_markers):
                continue
            
            # 删除Markdown格式符号（保持谨慎，避免误删内容中正常使用的符号）
            # 只处理行首的Markdown标记
            if line.startswith(('#', '-', '*', '>')):
                line = line[1:].strip()
            elif line.startswith(('1.', '2.', '3.')):
                line = line[2:].strip()
                
            # 删除行内的Markdown强调标记
            line = line.replace('**', '').replace('__', '').replace('`', '')
            
            # 删除行末的多余注释符号 */
            if line.endswith('*/'):
                line = line[:-2].strip()
            
            # 删除反汇编地址和指令前缀
            line = re.sub(r'^\.text:[0-9A-F]+\s+', '', line)
            # 删除指令部分，保留注释部分 "mov eax, [ebx] ; 这是注释" -> "这是注释"
            if ';' in line:
                parts = line.split(';', 1)
                if len(parts) > 1 and parts[1].strip():
                    line = parts[1].strip()
                    # 再次检查注释部分中可能包含的多余标记
                    if line.endswith('*/'):
                        line = line[:-2].strip()
                
            lines.append(line)
        
        # 重新组合文本，保留结构
        self.comment_text = "\n".join(lines)
        
        # 清除最常见的Markdown标题
        self.comment_text = self.comment_text.replace('功能：', '功能:').replace('参数：', '参数:')
        self.comment_text = self.comment_text.replace('返回值：', '返回值:').replace('特殊算法/技术：', '特殊算法/技术:')
        
        # 清除所有行末的多余注释符号，以防上面的单行处理未能捕获
        self.comment_text = re.sub(r'\s*\*/\s*$', '', self.comment_text, flags=re.MULTILINE)
        
        # 移除每行末尾的其他常见无用标记
        self.comment_text = re.sub(r'\s*\*/\s*$', '', self.comment_text, flags=re.MULTILINE)  # 结束注释标记
        self.comment_text = re.sub(r'\s*//\s*$', '', self.comment_text, flags=re.MULTILINE)   # 行注释
        self.comment_text = re.sub(r'\s*/\*\s*$', '', self.comment_text, flags=re.MULTILINE)  # 开始注释标记
        
        # 清理空行和无意义的行
        lines = []
        for line in self.comment_text.split('\n'):
            line = line.strip()
            if not line:
                continue
            # 跳过只含有注释符号的行
            if line in ['*/', '/*', '//', '**/', '/**', '*']:
                continue
            lines.append(line)
        
        # 重新组合文本
        self.comment_text = "\n".join(lines)
        
        # 确保注释文本不以空白字符开头或结尾
        self.comment_text = self.comment_text.strip()
        
        # 记录设置的注释文本
        log_message(_t(f"注释文本已设置 ({len(lines)}行)", f"Annotation text set ({len(lines)} lines)"), "info")
        
        # 显示注释预览
        if lines:
            preview = lines[0][:80] + ("..." if len(lines[0]) > 80 else "")
            log_message(_t("准备应用的注释内容（前80个字符）：", "Preview of annotation (first 80 chars):"), "info")
            log_message(preview, "info")
    
    def refresh_pseudocode_view(self, func_ea):
        """
        Refresh all open pseudocode widgets so that newly added comments are
        rendered immediately.

        刷新所有已打开的反编译窗口，确保新添加的注释能够即时显示。

        Args:
            func_ea (int): Start address of the function whose view should be
                refreshed.
        """
        log_message(_t("正在刷新反编译视图...", "Refreshing decompiled view..."), "info")
        
        try:
            # 确保反编译插件已初始化
            if not ida_hexrays.init_hexrays_plugin():
                log_message(_t("反编译插件未初始化，无法刷新反编译视图", "Decompiler plugin not initialized, cannot refresh view"), "error")
                return False
                
            # 获取函数对象
            func = ida_funcs.get_func(func_ea)
            if not func:
                log_message(_t(f"地址 {hex(func_ea)} 不在任何函数内", f"Address {hex(func_ea)} is not inside any function"), "error")
                return False
                
            # 方法1: 直接通过反编译API刷新
            try:
                # 标记函数需要重新反编译
                ida_hexrays.mark_cfunc_dirty(func.start_ea)
                log_message(_t("已刷新反编译函数文本", "Decompiled function text refreshed"), "info")
            except Exception as e:
                log_message(_t(f"刷新反编译文本时出错: {str(e)}", f"Error refreshing decompiled text: {str(e)}"), "error")
                
            # 方法2: 尝试获取并刷新所有反编译视图窗口
            try:
                for widget_title in ["Pseudocode-A", "Pseudocode-B", "Pseudocode-C"]:
                    widget = ida_kernwin.find_widget(widget_title)
                    if widget:
                        # 获取反编译视图对象
                        vu = ida_hexrays.get_widget_vdui(widget)
                        if vu and vu.cfunc and vu.cfunc.entry_ea == func.start_ea:
                            # 强制刷新文本
                            vu.refresh_ctext(True)
                            log_message(_t(f"已刷新 {widget_title} 视图", f"Refreshed {widget_title} view"), "info")
            except Exception as e:
                log_message(_t(f"刷新反编译窗口时出错: {str(e)}", f"Error refreshing pseudocode window: {str(e)}"), "error")
                
            # 方法3: 尝试使用UI操作刷新
            try:
                # 模拟用户交互刷新
                ida_kernwin.process_ui_action("hx:Refresh")
                time.sleep(0.1)
                ida_kernwin.process_ui_action("UndoEmptyPlaceholder")  # 触发刷新
                log_message(_t("已通过UI操作刷新反编译视图", "Decompiled view refreshed via UI interaction"), "info")
            except Exception as e:
                log_message(_t(f"通过UI操作刷新反编译视图时出错: {str(e)}", f"Error refreshing pseudocode view via UI action: {str(e)}"), "error")
                
            return True
        except Exception as e:
            log_message(_t(f"刷新反编译视图时出错: {str(e)}", f"Error refreshing pseudocode view: {str(e)}"), "error")
            return False
    
    def refresh_views(self, ea):
        """
        刷新所有视图，确保注释显示在视图中。
        
        Args:
            ea: 需要刷新的地址
        """
        log_message(_t("正在刷新视图...", "Refreshing view..."), "info")
        
        try:
            # 刷新当前反汇编视图
            ida_kernwin.refresh_idaview_anyway()
            
            # 尝试刷新反编译视图
            try:
                func = ida_funcs.get_func(ea)
                if func:
                    # 标记函数需要重新反编译
                    ida_hexrays.mark_cfunc_dirty(func.start_ea)
                    
                    # 尝试刷新所有打开的反编译视图
                    for widget_title in ["Pseudocode-A", "Pseudocode-B", "Pseudocode-C"]:
                        widget = ida_kernwin.find_widget(widget_title)
                        if widget:
                            # 获取反编译视图对象
                            vu = ida_hexrays.get_widget_vdui(widget)
                            if vu and vu.cfunc and vu.cfunc.entry_ea == func.start_ea:
                                # 刷新视图
                                vu.refresh_view(True)
                                vu.refresh_ctext(True)
                    
                    # 尝试通过UI操作刷新反编译视图
                    try:
                        # 适用于较新版本的IDA
                        for vu in ida_hexrays.get_current_viewers():
                            ida_hexrays.refresh_pseudocode_view(vu, True)
                    except:
                        # 适用于较旧版本的IDA
                        pass
                    
                    # 尝试以另一种方式刷新反编译视图
                    try:
                        ida_kernwin.process_ui_action("hx:Refresh")
                    except:
                        pass
            except Exception as e:
                log_message(_t("刷新反编译视图时出错 (不影响注释应用):", "Error refreshing pseudocode view (does not affect comment application):"), "info")
                log_message(f"{str(e)}", "info")
                
            
            # 强制刷新所有视图
            ida_kernwin.refresh_idaview_anyway()
            ida_kernwin.request_refresh(0xFFFFFFFF)  # 请求全屏刷新
            
            log_message(_t("视图刷新完成", "View refresh completed"), "info")
        except Exception as e:
            log_message(_auto_t("刷新视图时出错 (不影响注释应用):"), "info")
            log_message(f"{str(e)}", "info")
            
    def force_update_views(self):
        """
        强制刷新所有可能的视图，这是一个更温和的刷新方法
        """
        log_message(_auto_t("正在强制刷新所有视图..."), "info")
        
        try:
            # 获取当前地址
            ea = idaapi.get_screen_ea()
            
            # 刷新所有已打开的窗口，但不要关闭任何窗口
            try:
                for title in ["IDA View-A", "Pseudocode-A", "Hex View-A"]:
                    widget = ida_kernwin.find_widget(title)
                    if widget:
                        # 激活窗口但不关闭它
                        ida_kernwin.activate_widget(widget, True)
                        # 尝试刷新
                        ida_kernwin.process_ui_action("UndoEmptyPlaceholder")  # 触发刷新
                        
                        # 如果是反编译视图，使用专门的刷新方法
                        if "Pseudocode" in title:
                            # 获取反编译视图对象
                            vu = ida_hexrays.get_widget_vdui(widget)
                            if vu:
                                vu.refresh_view(True)
                                vu.refresh_ctext(True)
            except Exception as e:
                log_message(_auto_t("刷新窗口时出错:"), "error")
                log_message(f"{str(e)}", "error")
                
            # 刷新整个屏幕
            ida_kernwin.refresh_idaview_anyway()
            
            # 强制刷新反编译视图，但不关闭它
            func = ida_funcs.get_func(ea)
            if func:
                # 使用更温和的刷新方法
                try:
                    if ida_hexrays.init_hexrays_plugin():
                        # 标记函数需要重新反编译
                        ida_hexrays.mark_cfunc_dirty(func.start_ea)
                        
                        # 查找并刷新所有反编译视图
                        for widget_title in ["Pseudocode-A", "Pseudocode-B", "Pseudocode-C"]:
                            widget = ida_kernwin.find_widget(widget_title)
                            if widget:
                                # 激活窗口
                                ida_kernwin.activate_widget(widget, True)
                                # 获取反编译视图对象
                                vu = ida_hexrays.get_widget_vdui(widget)
                                if vu and vu.cfunc and vu.cfunc.entry_ea == func.start_ea:
                                    # 刷新视图
                                    vu.refresh_view(True)
                                    # 强制刷新反编译文本
                                    vu.refresh_ctext(True)
                except Exception as e:
                    log_message(_auto_t("刷新反编译视图时出错:"), "error")
                    log_message(f"{str(e)}", "error")
        except Exception as e:
            log_message(_auto_t("强制刷新视图时出错:"), "error")
            log_message(f"{str(e)}", "error")
    
    def force_refresh_decompiler(self, func_ea):
        """
        强制刷新反编译视图，包括重新生成反编译代码和刷新UI。
        
        Args:
            func_ea: 函数起始地址
        """
        log_message(_auto_t("正在强制刷新所有视图..."), "info")
        
        try:
            # 保存当前活动窗口，以便在刷新后恢复
            original_widget = ida_kernwin.get_current_widget()
            original_widget_type = ida_kernwin.get_widget_type(original_widget)
            
            # 确保反编译插件已初始化
            if not ida_hexrays.init_hexrays_plugin():
                log_message(_auto_t("反编译插件未初始化"), "error")
                return False
                
            # 获取函数对象
            func = ida_funcs.get_func(func_ea)
            if not func:
                log_message(_t(f"地址 {hex(func_ea)} 不在任何函数内", f"Address {hex(func_ea)} is not inside any function"), "error")
                return False
            
            # 方法1: 标记函数需要重新反编译
            try:
                # 标记函数需要重新反编译
                ida_hexrays.mark_cfunc_dirty(func.start_ea)
                log_message(_auto_t("已标记函数需要重新反编译"), "info")
            except Exception as e:
                log_message(_t(f"标记函数需要重新反编译时出错: {str(e)}", f"Error marking function for re-decompile: {str(e)}"), "error")
            
            # 方法2: 模拟用户交互操作，但不关闭视图
            try:
                found_pseudocode = False
                # 检查所有打开的反编译视图
                for widget_title in ["Pseudocode-A", "Pseudocode-B", "Pseudocode-C"]:
                    widget = ida_kernwin.find_widget(widget_title)
                    if widget:
                        # 激活窗口
                        ida_kernwin.activate_widget(widget, True)
                        
                        # 获取反编译视图对象
                        vu = ida_hexrays.get_widget_vdui(widget)
                        if vu and vu.cfunc and vu.cfunc.entry_ea == func.start_ea:
                            # 强制刷新视图
                            vu.refresh_view(True)
                            vu.refresh_ctext(True)
                            
                            # 模拟刷新操作
                            ida_kernwin.process_ui_action("hx:Refresh")
                            
                            log_message(_t(f"已通过模拟交互刷新 {widget_title} 视图", f"Refreshed {widget_title} view via simulated interaction"), "info")
                            found_pseudocode = True
            except Exception as e:
                log_message(_t(f"模拟用户交互刷新视图时出错: {str(e)}", f"Error refreshing view via simulated user interaction: {str(e)}"), "error")
            
            # 恢复原始窗口（如果是反编译视图）
            if original_widget and original_widget_type == ida_kernwin.BWN_PSEUDOCODE:
                ida_kernwin.activate_widget(original_widget, True)
            
            log_message(_auto_t("视图刷新完成"), "info")
            return True
        except Exception as e:
            log_message(_auto_t("刷新视图时出错:"), "error")
            log_message(f"{str(e)}", "error")
            return False
    
    def apply_function_comment(self, ea):
        """
        应用函数注释。
        
        Args:
            ea: 函数地址
        
        Returns:
            bool: 是否成功应用注释
        """
        if not self.comment_text:
            log_message(_auto_t("无法应用函数注释，注释文本为空"), "error")
            return False
        
        try:
            # 确保地址在函数内
            func = ida_funcs.get_func(ea)
            if not func:
                log_message(_t(f"地址 {hex(ea)} 不在任何函数内", f"Address {hex(ea)} is not inside any function"), "error")
                return False
            
            # 设置函数注释（在反汇编中的函数头部显示）
            func_name = idc.get_func_name(func.start_ea) or f"sub_{hex(func.start_ea)}"
            log_message(_t(f"正在为函数 {func_name} 应用注释...", f"Applying comment to function {func_name}..."), "info")
            
            existing = idc.get_func_cmt(func.start_ea, 0)
            comment_to_set = self.comment_text
            if existing and existing.strip():
                # 弹出选择对话框
                strategy = _ask_comment_strategy()
                if strategy == "cancel":
                    log_message(_auto_t("用户取消了注释应用"), "warning")
                    return False
                comment_to_set = _merge_comments(existing, self.comment_text, strategy)
            result = idc.set_func_cmt(func.start_ea, comment_to_set, 0)
            if not result:
                log_message(_auto_t("设置函数注释失败，可能是权限问题或地址无效"), "error")
                return False
                
            log_message(_t(f"已成功为函数 {func_name} 添加注释", f"Successfully added comment to function {func_name}"), "info")
            
            # 尝试在反编译视图中设置函数注释
            try:
                # 确保反编译插件已初始化
                if ida_hexrays.init_hexrays_plugin():
                    # 标记函数需要重新反编译
                    ida_hexrays.mark_cfunc_dirty(func.start_ea)
                    
                    # 刷新反编译视图
                    ida_kernwin.refresh_idaview_anyway()
                    log_message(_t("已在反编译视图中更新函数注释", "Updated function comment in pseudocode view"), "info")
                    
                    # 尝试直接应用到所有打开的反编译视图
                    for widget_title in ["Pseudocode-A", "Pseudocode-B", "Pseudocode-C"]:
                        widget = ida_kernwin.find_widget(widget_title)
                        if widget:
                            # 获取反编译视图对象
                            vu = ida_hexrays.get_widget_vdui(widget)
                            if vu and vu.cfunc and vu.cfunc.entry_ea == func.start_ea:
                                # 刷新视图
                                vu.refresh_view(True)
                                log_message(_t(f"已在 {widget_title} 视图中更新函数注释", f"Updated function comment in {widget_title} view"), "info")
            except Exception as e:
                log_message(_auto_t("在反编译视图中设置注释失败:"), "error")
                log_message(f"{str(e)}", "error")
                # 这不影响函数注释的应用，只是一个额外的功能
                
            # 刷新视图以显示注释
            self.refresh_views(ea)
            
            # 注释应用完成后，自动退出注释模式
            self.is_comment_mode_active = False
            log_message(_t("注释应用完成，已自动退出注释模式", "Comment applied, exited comment mode"), "info")
            return True
        except Exception as e:
            log_message(_auto_t("应用函数注释时出错:"), "error")
            traceback.print_exc()
            return False
    
    def _set_comment_single(self, ea: int, comment: str, repeatable: bool = False, anterior: bool = False):
        """为单条指令设置注释，封装公共流程。"""
        try:
            cmt_type = 1 if repeatable else 0
            if anterior:
                # 前置注释
                if hasattr(idc, "set_pre_cmt") and callable(idc.set_pre_cmt):
                    return idc.set_pre_cmt(ea, comment)
                else:
                    return ida_lines.update_extra_cmt(ea, ida_lines.E_PREV, comment)
            else:
                return idc.set_cmt(ea, comment, cmt_type)
        except Exception:
            return False
    
    def _apply_comment(self, ea=None, mode="line", skip_selection=False):
        """统一处理行/可重复/前置注释逻辑。
        
        Args:
            ea: 当前地址，默认为光标地址。
            mode: "line" | "repeatable" | "anterior"。
            skip_selection: 兼容旧递归接口，已无实际作用。
        """
        if not self.comment_text:
            log_message(_auto_t("无法应用注释，注释文本为空"), "error")
            return False

        # 默认地址
        if ea is None:
            ea = idaapi.get_screen_ea()

        # -----------------------------------------------
        # 1) 检查是否为多行选区，若是走批量逻辑
        # -----------------------------------------------
        try:
            sel_valid, sel_start, sel_end = idaapi.read_range_selection(None)
        except Exception:
            sel_valid, sel_start, sel_end = False, idaapi.BADADDR, idaapi.BADADDR

        has_selection = (
            not skip_selection and sel_valid and sel_start != idaapi.BADADDR and sel_end != idaapi.BADADDR and sel_start < sel_end
        )

        if has_selection:
            # 拆分注释行
            comment_lines = [ln.strip() for ln in self.comment_text.split("\n") if ln.strip()]
            if not comment_lines:
                log_message(_auto_t("批量注释失败: 注释文本为空"), "error")
                return False

            # 收集选区地址
            addrs = []
            curr = sel_start
            while curr < sel_end:
                addrs.append(curr)
                nxt = idc.next_head(curr, sel_end)
                if nxt == idaapi.BADADDR or nxt <= curr:
                    break
                curr = nxt

            for idx, ea_i in enumerate(addrs):
                cmt = comment_lines[idx] if idx < len(comment_lines) else comment_lines[-1]
                if mode == "line":
                    self._set_comment_single(ea_i, cmt, repeatable=False)
                elif mode == "repeatable":
                    self._set_comment_single(ea_i, cmt, repeatable=True)
                else:  # anterior
                    self._set_comment_single(ea_i, cmt, anterior=True)

            # 统一刷新
            self.refresh_views(sel_start)
            # 选区批量完成后退出注释模式
            self.is_comment_mode_active = False
            log_message(_auto_t("批量注释完成"), "info")
            return True

        # -----------------------------------------------
        # 2) 单行逻辑（与旧实现保持一致）
        # -----------------------------------------------
        if ea == idaapi.BADADDR:
            log_message(_auto_t("无效的地址"), "error")
            return False

        # 保存窗口信息，刷新后恢复
        original_widget = ida_kernwin.get_current_widget()
        original_widget_type = ida_kernwin.get_widget_type(original_widget)

        # 处理现有注释冲突
        if mode == "line":
            existing = idc.get_cmt(ea, 0)
        elif mode == "repeatable":
            existing = idc.get_cmt(ea, 1)
        else:
            try:
                existing = (
                    idc.get_pre_cmt(ea) if hasattr(idc, "get_pre_cmt") else ida_lines.get_extra_cmt(ea, ida_lines.E_PREV)
                )
            except Exception:
                existing = ""

        comment_to_set = self.comment_text
        if existing and existing.strip():
            # 弹出选择对话框
            strategy = _ask_comment_strategy()
            if strategy == "cancel":
                log_message(_auto_t("用户取消了注释应用"), "warning")
                return False
            comment_to_set = _merge_comments(existing, self.comment_text, strategy)

        # 实际设置注释
        ok = False
        if mode == "line":
            ok = self._set_comment_single(ea, comment_to_set, repeatable=False)
        elif mode == "repeatable":
            ok = self._set_comment_single(ea, comment_to_set, repeatable=True)
        else:
            ok = self._set_comment_single(ea, comment_to_set, anterior=True)

        if not ok:
            log_message(_auto_t("设置注释失败，可能是权限问题或地址无效"), "error")
            return False

        log_message(_t(f"已成功为地址 {hex(ea)} 添加{mode}注释", f"Successfully added {mode} comment to address {hex(ea)}"), "info")

        # 刷新视图
        self.refresh_views(ea)

        # 若在函数内则刷新反编译
        func = ida_funcs.get_func(ea)
        if func:
            self.force_refresh_decompiler(func.start_ea)

        # 恢复原窗口（如反编译）
        if original_widget and original_widget_type == ida_kernwin.BWN_PSEUDOCODE:
            ida_kernwin.activate_widget(original_widget, True)

        # 结束注释模式
        self.is_comment_mode_active = False
        log_message(_t("注释应用完成，已自动退出注释模式", "Comment applied, exited comment mode"), "info")
        return True

    def apply_line_comment(self, ea=None, skip_selection=False):
        """公开接口：行注释 (尾部注释)"""
        return self._apply_comment(ea, "line", skip_selection)

    def apply_repeatable_comment(self, ea=None, skip_selection=False):
        """公开接口：可重复注释"""
        return self._apply_comment(ea, "repeatable", skip_selection)

    def apply_anterior_comment(self, ea=None, skip_selection=False):
        """公开接口：前置 (anterior) 注释"""
        return self._apply_comment(ea, "anterior", skip_selection)