"""
UI components for the NexusAI plugin.
This module defines user interface elements such as the output window.

界面组件模块，定义了诸如输出窗口等 NexusAI 插件的 UI 元素。
"""
import idaapi
import idc
from PyQt5 import QtWidgets, QtCore, QtGui

import json
from pathlib import Path
import re

from importlib import import_module


def _get_graph_exporter_cls():
    """
    Dynamically retrieve the ``GraphExporter`` class if the corresponding
    extension has been loaded; otherwise return ``None``.

    动态获取 ``GraphExporter`` 类；若对应扩展尚未加载，则返回 ``None``。
    """
    try:
        module = import_module("nexusai_extensions.graph_export_extension.graph_exporter")
        return getattr(module, "GraphExporter", None)
    except Exception:
        return None

from ..Core.task_controller import TaskType
from ..Config.config import ConfigManager
from ..Core.event_bus import get_event_bus
from ..Utils.comment_applicator import _t

def log_message(message, message_type="info"):
    """Record a message in the NexusAI output window with proper styling."""
    config_manager = ConfigManager()
    
    color = "#1E90FF"
    if message_type == "success":
        color = "#2ECC71"
    elif message_type == "error":
        color = "#FF4500"
    elif message_type == "warning":
        color = "#FFA500"
    
    html_message = f"<div style='color:{color};'>{'❌ ' if message_type == 'error' else '✅ ' if message_type == 'success' else 'ℹ️ ' if message_type == 'info' else '⚠️ '}<b>{message}</b></div>"
    
    if config_manager.output_view:
        config_manager.output_view.append_text(html_message)
    else:
        idaapi.msg(f"{message}\n")

try:
    import markdown
except ImportError:
    markdown = None
    log_message("'markdown' library not found. Please install it for rich text rendering: python -m pip install markdown", "error")


class SettingsDialog(QtWidgets.QDialog):
    """
    Settings dialog for configuring various options of NexusAI.
    NexusAI 设置对话框，用于配置插件的各项参数。
    """
    def __init__(self, parent=None, config_manager=None):
        super(SettingsDialog, self).__init__(parent)
        self.config_manager = config_manager or ConfigManager()
        self._strings = {
            "zh_CN": {
                "window_title": "NexusAI 设置",
                "tab_api": "API设置",
                "tab_analysis": "分析设置",
                "tab_prompts": "提示词设置",
                "tab_ui": "UI设置",
                "api_key": "API 密钥:",
                "base_url": "API Base URL:",
                "model": "AI 模型:",
                "analysis_depth": "分析深度：",
                "aimcp_enable": "限制 AIMCP 最大轮数",
                "aimcp_label": "最大轮数：",
                "language": "语言:",
                "system_prompt": "系统提示词:",
                "auto_open": "启动时自动打开窗口:",
                "prompt_type": "提示词类型:",
                "prompt_content": "提示词内容:",
                "temperature": "随机性:",
                "max_tokens": "最大令牌数:",
                "proxy": "代理地址:",
                "proxy_placeholder": "留空则不使用代理",
                "shortcuts_group": "快捷键",
                "shortcut_toggle": "切换窗口:",
                "shortcut_function": "函数注释:",
                "shortcut_line": "行注释:",
                "shortcut_repeatable": "可重复注释:",
                "shortcut_anterior": "前置注释:",
                "include_types": "提取结构体/枚举定义:",
                "include_xrefs": "包含交叉引用信息:",
                "api_profile": "API配置分组:",
                "test_model": "测试模型",
            },
            "en_US": {
                "window_title": "NexusAI Settings",
                "tab_api": "API",
                "tab_analysis": "Analysis",
                "tab_prompts": "Prompt",
                "tab_ui": "UI",
                "api_key": "API Key:",
                "base_url": "API Base URL:",
                "model": "AI Model:",
                "analysis_depth": "Analysis Depth:",
                "aimcp_enable": "Enable AIMCP iteration limit",
                "aimcp_label": "Max iterations:",
                "language": "Language:",
                "system_prompt": "System Prompt:",
                "auto_open": "Auto Open Window on Start:",
                "prompt_type": "Prompt Type:",
                "prompt_content": "Prompt Content:",
                "temperature": "Randomness:",
                "max_tokens": "Max Tokens:",
                "proxy": "Proxy:",
                "proxy_placeholder": "Leave empty to disable proxy",
                "shortcuts_group": "Shortcuts",
                "shortcut_toggle": "Toggle Window:",
                "shortcut_function": "Function Comment:",
                "shortcut_line": "Line Comment:",
                "shortcut_repeatable": "Repeatable Comment:",
                "shortcut_anterior": "Anterior Comment:",
                "include_types": "Include Struct/Enum Definitions:",
                "include_xrefs": "Include Xrefs Info:",
                "api_profile": "API Profile:",
                "test_model": "Test Model",
            },
        }

        get_event_bus().on("language_changed", self._update_language_texts)
        self.init_ui()
        
        dlg_sizes = self.config_manager.config.setdefault("dialog_sizes", {})
        w, h = dlg_sizes.get("settings_dialog", (700, 550))
        self.resize(w, h)
        
    def init_ui(self):
        """
        Initialize all UI elements in the settings dialog.
        初始化设置对话框中的所有界面元素。
        """
        self.setMinimumWidth(500)
        cur_lang = self.config_manager.language
        s = self._strings.get(cur_lang, self._strings["zh_CN"])
        self.setWindowTitle(s["window_title"])
        
        layout = QtWidgets.QVBoxLayout()
        
        self.tab_widget = QtWidgets.QTabWidget()
        
        api_tab = QtWidgets.QWidget()
        api_layout = QtWidgets.QFormLayout(api_tab)
        
        self.profiles_data = self.config_manager.config.get(
            "api_profiles",
            {"OpenAI": self.config_manager.config.get("openai", {}).copy()},
        )
        self.current_profile_name = self.config_manager.config.get(
            "current_profile", list(self.profiles_data.keys())[0]
        )

        profile_row_widget = QtWidgets.QWidget()
        profile_hlayout = QtWidgets.QHBoxLayout(profile_row_widget)
        profile_hlayout.setContentsMargins(0, 0, 0, 0)
        self.profile_combo = QtWidgets.QComboBox()
        self.profile_combo.addItems(self.profiles_data.keys())
        if self.current_profile_name in self.profiles_data:
            self.profile_combo.setCurrentText(self.current_profile_name)
        btn_add_profile = QtWidgets.QPushButton("+")
        btn_remove_profile = QtWidgets.QPushButton("-")
        profile_hlayout.addWidget(self.profile_combo, 1)
        profile_hlayout.addWidget(btn_add_profile)
        profile_hlayout.addWidget(btn_remove_profile)

        self.profile_label = QtWidgets.QLabel(s["api_profile"])
        api_layout.addRow(self.profile_label, profile_row_widget)

        self.profile_combo.currentIndexChanged.connect(self.on_profile_changed)
        btn_add_profile.clicked.connect(self.on_add_profile)
        btn_remove_profile.clicked.connect(self.on_remove_profile)
 
        self.api_key_edit = QtWidgets.QLineEdit()
        self.api_key_edit.setEchoMode(QtWidgets.QLineEdit.Password)
        self.api_key_label = QtWidgets.QLabel(s["api_key"])
        api_layout.addRow(self.api_key_label, self.api_key_edit)
 
        self.base_url_edit = QtWidgets.QLineEdit()
        self.base_url_label = QtWidgets.QLabel(s["base_url"])
        api_layout.addRow(self.base_url_label, self.base_url_edit)
 
        self.proxy_edit = QtWidgets.QLineEdit()
        self.proxy_edit.setPlaceholderText(s["proxy_placeholder"])
        self.proxy_label = QtWidgets.QLabel(s["proxy"])
        api_layout.addRow(self.proxy_label, self.proxy_edit)
 
        self.model_combo = QtWidgets.QComboBox()
        self.model_combo.setEditable(True)
        self.model_label = QtWidgets.QLabel(s["model"])
        model_row_widget = QtWidgets.QWidget()
        model_hlayout = QtWidgets.QHBoxLayout(model_row_widget)
        model_hlayout.setContentsMargins(0, 0, 0, 0)
        model_hlayout.addWidget(self.model_combo, 1)
        btn_add_model = QtWidgets.QPushButton("+")
        btn_remove_model = QtWidgets.QPushButton("-")
        model_hlayout.addWidget(btn_add_model)
        model_hlayout.addWidget(btn_remove_model)
        api_layout.addRow(self.model_label, model_row_widget)
        btn_add_model.clicked.connect(self.on_add_model)
        btn_remove_model.clicked.connect(self.on_remove_model)

        self.load_profile_into_fields()
 
        self.temperature_slider = QtWidgets.QSlider(QtCore.Qt.Horizontal)
        self.temperature_slider.setRange(0, 100)
        self.temperature_slider.setValue(int(self.config_manager.config.get("temperature", 0.7) * 100))
        self.temperature_slider.setTickPosition(QtWidgets.QSlider.TicksBelow)
        self.temperature_slider.setTickInterval(10)
        temp_layout = QtWidgets.QHBoxLayout()
        temp_layout.addWidget(self.temperature_slider)
        temp_value_label = QtWidgets.QLabel(f"{self.temperature_slider.value() / 100.0:.2f}")
        temp_layout.addWidget(temp_value_label)
        self.temperature_slider.valueChanged.connect(
            lambda v: temp_value_label.setText(f"{v / 100.0:.2f}")
        )
        self.temperature_label = QtWidgets.QLabel(s["temperature"])
        api_layout.addRow(self.temperature_label, temp_layout)
        
        self.max_tokens_edit = QtWidgets.QLineEdit()
        self.max_tokens_edit.setText(str(self.config_manager.config.get("max_tokens", 2000)))
        self.max_tokens_edit.setValidator(QtGui.QIntValidator(100, 10000))
        self.max_tokens_label = QtWidgets.QLabel(s["max_tokens"])
        api_layout.addRow(self.max_tokens_label, self.max_tokens_edit)
        
        self.test_model_btn = QtWidgets.QPushButton(s["test_model"])
        self.test_model_btn.clicked.connect(self.on_test_model)
        api_layout.addRow(QtWidgets.QLabel(""), self.test_model_btn)
        
        self.tab_widget.addTab(api_tab, s["tab_api"])
        
        analysis_tab = QtWidgets.QWidget()
        analysis_layout = QtWidgets.QFormLayout(analysis_tab)
        
        self.depth_spin = QtWidgets.QSpinBox()
        self.depth_spin.setRange(0, 10)
        self.depth_spin.setValue(self.config_manager.config.get("analysis_depth", 2))
        self.depth_label = QtWidgets.QLabel(s["analysis_depth"])
        analysis_layout.addRow(self.depth_label, self.depth_spin)

        self.iter_limit_check = QtWidgets.QCheckBox(s["aimcp_enable"])
        enabled_default = self.config_manager.config.get("aimcp_limit_iters_enabled", False)
        self.iter_limit_check.setChecked(enabled_default)
        analysis_layout.addRow(self.iter_limit_check)

        self.iter_limit_spin = QtWidgets.QSpinBox()
        self.iter_limit_spin.setRange(1, 50)
        self.iter_limit_spin.setValue(self.config_manager.config.get("aimcp_max_iters", 5))
        self.iter_limit_spin.setEnabled(enabled_default)
        self.iter_limit_label = QtWidgets.QLabel(s["aimcp_label"])
        analysis_layout.addRow(self.iter_limit_label, self.iter_limit_spin)

        self.iter_limit_check.stateChanged.connect(lambda st: self.iter_limit_spin.setEnabled(bool(st)))
        
        self.language_combo = QtWidgets.QComboBox()
        languages = [("zh_CN", "简体中文"), ("en_US", "English")]
        for code, name in languages:
            self.language_combo.addItem(name, code)
        current_lang = self.config_manager.config.get("language", "zh_CN")
        for i in range(self.language_combo.count()):
            if self.language_combo.itemData(i) == current_lang:
                self.language_combo.setCurrentIndex(i)
                break
        self.language_label = QtWidgets.QLabel(s["language"])
        analysis_layout.addRow(self.language_label, self.language_combo)

        self.include_types_check = QtWidgets.QCheckBox()
        self.include_types_check.setChecked(self.config_manager.analysis_options.get("include_type_definitions", True))
        self.include_types_label = QtWidgets.QLabel(s["include_types"])
        analysis_layout.addRow(self.include_types_label, self.include_types_check)

        self.include_xrefs_check = QtWidgets.QCheckBox()
        self.include_xrefs_check.setChecked(self.config_manager.analysis_options.get("include_xrefs", True))
        self.include_xrefs_label = QtWidgets.QLabel(s["include_xrefs"])
        analysis_layout.addRow(self.include_xrefs_label, self.include_xrefs_check)

        self.language_combo.currentIndexChanged.connect(self.on_language_combo_changed)
        
        self.tab_widget.addTab(analysis_tab, s["tab_analysis"])
        
        prompts_tab = QtWidgets.QWidget()
        prompts_layout = QtWidgets.QVBoxLayout(prompts_tab)
        
        self.prompt_type_combo = QtWidgets.QComboBox()
        self.prompt_type_combo.setToolTip("选择要编辑的提示词类型")
        
        self.prompt_content_edit = QtWidgets.QTextEdit()
        self.prompt_content_edit.setMinimumHeight(200)
        
        prompts_form_layout = QtWidgets.QFormLayout()
        self.prompt_type_label = QtWidgets.QLabel(s["prompt_type"])
        self.prompt_content_label = QtWidgets.QLabel(s["prompt_content"])
        prompts_form_layout.addRow(self.prompt_type_label, self.prompt_type_combo)
        prompts_form_layout.addRow(self.prompt_content_label, self.prompt_content_edit)
        
        prompts_layout.addLayout(prompts_form_layout)
        
        self.prompt_type_combo.currentIndexChanged.connect(self.on_prompt_type_changed)
        
        self.load_prompt_settings()
        
        self.tab_widget.addTab(prompts_tab, s["tab_prompts"])
        
        ui_tab = QtWidgets.QWidget()
        ui_layout = QtWidgets.QFormLayout(ui_tab)
        
        self.auto_open_check = QtWidgets.QCheckBox()
        self.auto_open_check.setChecked(True)
        self.auto_open_label = QtWidgets.QLabel(s["auto_open"])
        ui_layout.addRow(self.auto_open_label, self.auto_open_check)

        shortcuts_group = QtWidgets.QGroupBox(s["shortcuts_group"])
        shortcuts_layout = QtWidgets.QFormLayout(shortcuts_group)

        def get_sc(key, default):
            return self.config_manager.config.get("shortcuts", {}).get(key, default)

        self.shortcut_toggle_edit = QtWidgets.QKeySequenceEdit(QtGui.QKeySequence(get_sc("toggle_output", "Ctrl+Shift+K")))
        shortcuts_layout.addRow(QtWidgets.QLabel(s["shortcut_toggle"]), self.shortcut_toggle_edit)

        self.shortcut_function_edit = QtWidgets.QKeySequenceEdit(QtGui.QKeySequence(get_sc("comment_function", "Ctrl+Shift+A")))
        shortcuts_layout.addRow(QtWidgets.QLabel(s["shortcut_function"]), self.shortcut_function_edit)

        self.shortcut_line_edit = QtWidgets.QKeySequenceEdit(QtGui.QKeySequence(get_sc("comment_line", "Ctrl+Shift+S")))
        shortcuts_layout.addRow(QtWidgets.QLabel(s["shortcut_line"]), self.shortcut_line_edit)

        self.shortcut_repeatable_edit = QtWidgets.QKeySequenceEdit(QtGui.QKeySequence(get_sc("comment_repeatable", "Ctrl+Shift+D")))
        shortcuts_layout.addRow(QtWidgets.QLabel(s["shortcut_repeatable"]), self.shortcut_repeatable_edit)

        self.shortcut_anterior_edit = QtWidgets.QKeySequenceEdit(QtGui.QKeySequence(get_sc("comment_anterior", "Ctrl+Shift+W")))
        shortcuts_layout.addRow(QtWidgets.QLabel(s["shortcut_anterior"]), self.shortcut_anterior_edit)

        ui_layout.addRow(shortcuts_group)
        
        self.tab_widget.addTab(ui_tab, s["tab_ui"])
        
        layout.addWidget(self.tab_widget)
        
        button_box = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel | QtWidgets.QDialogButtonBox.Apply
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        button_box.button(QtWidgets.QDialogButtonBox.Apply).clicked.connect(self.apply_settings)
        
        layout.addWidget(button_box)
        self.setLayout(layout)

    def _update_language_texts(self):
        """
        Refresh all static texts according to the current language.
        根据当前语言刷新所有静态文本。
        """
        lang = self.config_manager.language
        s = self._strings.get(lang, self._strings["zh_CN"])

        self.setWindowTitle(s["window_title"])
        self.tab_widget.setTabText(0, s["tab_api"])
        self.tab_widget.setTabText(1, s["tab_analysis"])
        self.tab_widget.setTabText(2, s["tab_prompts"])
        self.tab_widget.setTabText(3, s["tab_ui"])

        self.api_key_label.setText(s["api_key"])
        self.base_url_label.setText(s["base_url"])
        self.proxy_label.setText(s["proxy"])
        self.proxy_edit.setPlaceholderText(s["proxy_placeholder"])
        self.model_label.setText(s["model"])
        self.depth_label.setText(s["analysis_depth"])
        self.language_label.setText(s["language"])
        self.prompt_type_label.setText(s["prompt_type"])
        self.prompt_content_label.setText(s["prompt_content"])
        self.auto_open_label.setText(s["auto_open"])
        self.temperature_label.setText(s["temperature"])
        self.max_tokens_label.setText(s["max_tokens"])
        self.include_types_label.setText(s["include_types"])
        self.include_xrefs_label.setText(s["include_xrefs"])
        self.iter_limit_check.setText(s["aimcp_enable"])
        self.iter_limit_label.setText(s["aimcp_label"])
        self.profile_label.setText(s["api_profile"])
        
        for child in self.findChildren(QtWidgets.QGroupBox):
            if child.title() in [self._strings["zh_CN"]["shortcuts_group"], self._strings["en_US"]["shortcuts_group"]]:
                child.setTitle(s["shortcuts_group"])
                break
                
        shortcut_labels = {
            "shortcut_toggle": None,
            "shortcut_function": None,
            "shortcut_line": None,
            "shortcut_repeatable": None,
            "shortcut_anterior": None
        }
        
        for label in self.findChildren(QtWidgets.QLabel):
            for key in shortcut_labels:
                if label.text() in [self._strings["zh_CN"][key], self._strings["en_US"][key]]:
                    label.setText(s[key])
                    shortcut_labels[key] = label
                    break

        for i in range(self.language_combo.count()):
            if self.language_combo.itemData(i) == lang:
                self.language_combo.setCurrentIndex(i)
                break

        self.load_prompt_settings()

        if hasattr(self, "test_model_btn"):
            self.test_model_btn.setText(s["test_model"])

    def on_language_combo_changed(self, index):
        """
        Preview UI language change immediately when user selects a new language.
        当用户选择新的语言时，立即预览界面语言变化。
        """
        new_language = self.language_combo.itemData(index)
        if new_language:
            lang = new_language
            s = self._strings.get(lang, self._strings["zh_CN"])
            
            self.setWindowTitle(s["window_title"])
            self.tab_widget.setTabText(0, s["tab_api"])
            self.tab_widget.setTabText(1, s["tab_analysis"])
            self.tab_widget.setTabText(2, s["tab_prompts"])
            self.tab_widget.setTabText(3, s["tab_ui"])
            
            self.api_key_label.setText(s["api_key"])
            self.base_url_label.setText(s["base_url"])
            self.proxy_label.setText(s["proxy"])
            self.proxy_edit.setPlaceholderText(s["proxy_placeholder"])
            self.model_label.setText(s["model"])
            self.depth_label.setText(s["analysis_depth"])
            self.language_label.setText(s["language"])
            self.prompt_type_label.setText(s["prompt_type"])
            self.prompt_content_label.setText(s["prompt_content"])
            self.auto_open_label.setText(s["auto_open"])
            self.temperature_label.setText(s["temperature"])
            self.max_tokens_label.setText(s["max_tokens"])
            self.include_types_label.setText(s["include_types"])
            self.include_xrefs_label.setText(s["include_xrefs"])
            self.iter_limit_check.setText(s["aimcp_enable"])
            self.iter_limit_label.setText(s["aimcp_label"])
            self.profile_label.setText(s["api_profile"])
            
            for child in self.findChildren(QtWidgets.QGroupBox):
                if child.title() in [self._strings["zh_CN"]["shortcuts_group"], self._strings["en_US"]["shortcuts_group"]]:
                    child.setTitle(s["shortcuts_group"])
                    break
                    
            shortcut_labels = {
                "shortcut_toggle": None,
                "shortcut_function": None,
                "shortcut_line": None,
                "shortcut_repeatable": None,
                "shortcut_anterior": None
            }
            
            for label in self.findChildren(QtWidgets.QLabel):
                for key in shortcut_labels:
                    if label.text() in [self._strings["zh_CN"][key], self._strings["en_US"][key]]:
                        label.setText(s[key])
                        shortcut_labels[key] = label
                        break
                        
        self.load_prompt_settings()



    def on_profile_changed(self, index):
        """当用户选择不同的 API 配置分组时，更新下方字段。"""
        if index < 0:
            return
        self.current_profile_name = self.profile_combo.currentText()
        self.load_profile_into_fields()

    def load_profile_into_fields(self):
        """根据当前分组名称，将配置填充到编辑框。"""
        profile = self.profiles_data.get(self.current_profile_name, {})

        self.api_key_edit.setText(profile.get("api_key", ""))
        self.base_url_edit.setText(profile.get("base_url", "https://api.openai.com/v1"))
        self.proxy_edit.setText(profile.get("proxy", ""))

        models = profile.get("models")
        if models is None:
            single = profile.get("model", "gpt-3.5-turbo")
            models = [single] if single else []
            profile["models"] = models

        self.model_combo.blockSignals(True)
        self.model_combo.clear()
        self.model_combo.addItems(models)

        current_model = profile.get("model", models[0] if models else "")
        if current_model and self.model_combo.findText(current_model) == -1:
            self.model_combo.addItem(current_model)
        self.model_combo.setCurrentText(current_model)
        self.model_combo.blockSignals(False)

    def on_add_profile(self):
        """新增一个 API 配置分组。"""
        name, ok = QtWidgets.QInputDialog.getText(self, "新增 API 配置分组", "输入分组名称:")
        name = name.strip()
        if ok and name:
            if name in self.profiles_data:
                QtWidgets.QMessageBox.warning(self, "提示", f"分组 '{name}' 已存在！")
                return
            self.profiles_data[name] = {
                "api_key": "",
                "base_url": "https://api.openai.com/v1",
                "proxy": "",
                "models": ["gpt-3.5-turbo"],
                "model": "gpt-3.5-turbo",
            }
            self.profile_combo.addItem(name)
            self.profile_combo.setCurrentText(name)

    def on_remove_profile(self):
        """删除当前选中的配置分组（至少保留一个）。"""
        if len(self.profiles_data) <= 1:
            QtWidgets.QMessageBox.warning(self, "提示", "至少需要保留一个配置分组！")
            return
        name = self.profile_combo.currentText()
        if QtWidgets.QMessageBox.question(
            self,
            "确认删除",
            f"确定删除分组 '{name}'?",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
        ) == QtWidgets.QMessageBox.Yes:
            self.profiles_data.pop(name, None)
            idx = self.profile_combo.currentIndex()
            self.profile_combo.removeItem(idx)
            self.current_profile_name = self.profile_combo.currentText()
            self.load_profile_into_fields()

    def on_add_model(self):
        """新增一个自定义模型名称到下拉框。"""
        name, ok = QtWidgets.QInputDialog.getText(self, "新增模型", "输入模型名称:")
        name = name.strip()
        if ok and name:
            if self.model_combo.findText(name) == -1:
                self.model_combo.addItem(name)
            self.model_combo.setCurrentText(name)
            profile = self.profiles_data[self.current_profile_name]
            models = profile.setdefault("models", [])
            if name not in models:
                models.append(name)
            profile["model"] = name

    def on_remove_model(self):
        """删除当前选择的模型名称（仅影响下拉框显示）。"""
        idx = self.model_combo.currentIndex()
        if idx >= 0:
            removed = self.model_combo.itemText(idx)
            self.model_combo.removeItem(idx)
            profile = self.profiles_data[self.current_profile_name]
            models = profile.setdefault("models", [])
            if removed in models:
                models.remove(removed)
            if models:
                profile["model"] = self.model_combo.currentText()

    def on_test_model(self):
        """测试当前分组配置与模型是否可用。"""
        api_key = self.api_key_edit.text().strip()
        base_url = self.base_url_edit.text().strip()
        model_name = self.model_combo.currentText().strip()
        lang = self.config_manager.language
        title_success = "成功" if lang == "zh_CN" else "Success"
        title_fail = "错误" if lang == "zh_CN" else "Error"

        if not api_key:
            QtWidgets.QMessageBox.warning(self, title_fail, "API Key 未设置" if lang == "zh_CN" else "API Key is not set")
            return

        proxy = self.proxy_edit.text().strip()
        try:
            from openai import OpenAI
            if proxy:
                try:
                    import httpx
                    client = OpenAI(api_key=api_key, base_url=base_url,
                                    http_client=httpx.Client(proxy=proxy, timeout=120.0))
                except Exception:
                    client = OpenAI(api_key=api_key, base_url=base_url)
            else:
                client = OpenAI(api_key=api_key, base_url=base_url)

            # 使用models.list()而不是models.retrieve()，因为某些API提供商不支持retrieve端点
            models = client.models.list()
            model_names = [model.id for model in models.data]

            if model_name in model_names:
                QtWidgets.QMessageBox.information(self, title_success, "模型可用！" if lang == "zh_CN" else "Model is available!")
            else:
                available_models = ", ".join(model_names[:5])  # 显示前5个可用模型
                error_msg = (f"模型 '{model_name}' 不可用。\n可用模型包括: {available_models}..."
                           if lang == "zh_CN"
                           else f"Model '{model_name}' is not available.\nAvailable models include: {available_models}...")
                QtWidgets.QMessageBox.warning(self, title_fail, error_msg)
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, title_fail, str(e))

    def apply_settings(self):
        """
        Collect all user inputs from the dialog and persist the settings.
        收集用户在对话框中的输入并保存设置。
        """
        settings = {}
            
        models_list = [self.model_combo.itemText(i) for i in range(self.model_combo.count())]

        self.profiles_data[self.current_profile_name] = {
            "api_key": self.api_key_edit.text(),
            "base_url": self.base_url_edit.text(),
            "proxy": self.proxy_edit.text(),
            "models": models_list,
            "model": self.model_combo.currentText(),
        }

        settings["api_profiles"] = self.profiles_data
        settings["current_profile"] = self.current_profile_name
        settings["openai"] = self.profiles_data[self.current_profile_name]

        settings["analysis_depth"] = self.depth_spin.value()

        
        if hasattr(self, "temperature_slider"):
            settings["temperature"] = self.temperature_slider.value() / 100.0
        if hasattr(self, "max_tokens_edit"):
            try:
                settings["max_tokens"] = int(self.max_tokens_edit.text())
            except (ValueError, AttributeError):
                settings["max_tokens"] = 2000

        settings["analysis_options"] = {
            "include_type_definitions": self.include_types_check.isChecked(),
            "include_xrefs": self.include_xrefs_check.isChecked()
        }

        settings["aimcp_limit_iters_enabled"] = self.iter_limit_check.isChecked()
        settings["aimcp_max_iters"] = self.iter_limit_spin.value()
        
        shortcuts = {}
        shortcuts["toggle_output"] = self.shortcut_toggle_edit.keySequence().toString()
        shortcuts["comment_function"] = self.shortcut_function_edit.keySequence().toString()
        shortcuts["comment_line"] = self.shortcut_line_edit.keySequence().toString()
        shortcuts["comment_repeatable"] = self.shortcut_repeatable_edit.keySequence().toString()
        shortcuts["comment_anterior"] = self.shortcut_anterior_edit.keySequence().toString()
        settings["shortcuts"] = shortcuts
        
        new_language = self.language_combo.currentData()

        def _apply_async():
            try:
                idaapi.show_wait_box("Applying settings...")
                self.config_manager.apply_settings(settings)
                self.config_manager.save_config()
            except Exception as e:
                idaapi.msg("Error applying settings:\n%s\n" % str(e))
                raise
            finally:
                idaapi.hide_wait_box()

        QtCore.QTimer.singleShot(0, _apply_async)
        
    def accept(self):
        """当用户点击OK按钮时被调用。"""
        self.apply_settings()
        super(SettingsDialog, self).accept()

    def load_prompt_settings(self):
        """加载当前语言的所有提示词到UI。"""
        self.prompt_type_combo.blockSignals(True)
        self.prompt_type_combo.clear()
        
        current_lang = self.language_combo.currentData()
        prompts = self.config_manager.config.get("prompts", {}).get(current_lang, {})
        
        # 定义一个更友好的显示名称映射
        prompt_display_names = {
            "system": "系统提示词 (System)",
            "comment_function": "函数注释 (Function Comment)",
            "generate_line_comment": "行注释 (Line Comment)",
            "custom_query_with_code": "带代码的提问 (Query With Code)",
            "analyze_function": "分析函数 (Analyze Function)",
            "analyze_selection": "分析选中 (Analyze Selection)"
        }
        
        for key, value in prompts.items():
            display_name = prompt_display_names.get(key, key)
            self.prompt_type_combo.addItem(display_name, key)
            
        self.prompt_type_combo.blockSignals(False)
        
        # 手动触发第一次加载
        if self.prompt_type_combo.count() > 0:
            self.on_prompt_type_changed(0)

    def on_prompt_type_changed(self, index):
        """当用户选择不同的提示词类型时，更新编辑框内容。"""
        if index < 0:
            return
        
        prompt_key = self.prompt_type_combo.itemData(index)
        current_lang = self.language_combo.currentData()
        
        prompt_content = self.config_manager.config.get("prompts", {}).get(current_lang, {}).get(prompt_key, "")
        self.prompt_content_edit.setText(prompt_content)

# ------------------------------------------------------------------
# 新增: 上下文选择对话框
# ------------------------------------------------------------------


class ContextSelectionDialog(QtWidgets.QDialog):
    """
    Dialog allowing the user to select additional context to be attached
    to the AI prompt, such as data-flow graphs or call-chain code.

    上下文选择对话框，允许用户选择附加到 AI 提示中的额外上下文，
    例如数据流图或函数调用链代码。
    """
    def __init__(self, parent=None, options=None):
        """
        Initialize the dialog with default or provided context options.

        初始化对话框，并使用默认或传入的上下文选项。
        """
        super().__init__(parent)
        self.setWindowTitle("选择附加上下文")

        # 用于保存窗口大小等设置的配置管理器
        self._cfg = ConfigManager()

        self._options = options or {
            "data_flow_graph": False,
            "current_function": False,
            "decompiled_function": False,
            "call_chain": False,
            "dfg_depth": 2,
            "dfg_max_chars": 5000,
            "dfg_truncate": True,
        }

        layout = QtWidgets.QVBoxLayout(self)

        self.chk_data_flow = QtWidgets.QCheckBox("数据流图 (Data-Flow Graph)")
        self.chk_data_flow.setChecked(self._options.get("data_flow_graph", False))

        self.chk_current_func = QtWidgets.QCheckBox("当前函数代码 (Asm)")
        self.chk_current_func.setChecked(self._options.get("current_function", False))

        self.chk_decompiled_func = QtWidgets.QCheckBox("当前函数反编译代码 (Pseudo)")
        self.chk_decompiled_func.setChecked(self._options.get("decompiled_function", False))

        self.chk_call_chain = QtWidgets.QCheckBox("函数调用链代码")
        self.chk_call_chain.setChecked(self._options.get("call_chain", False))

        for w in (self.chk_data_flow, self.chk_current_func, self.chk_decompiled_func, self.chk_call_chain):
            layout.addWidget(w)

        # 数据流图设置组合框
        dfg_group = QtWidgets.QGroupBox("数据流图设置 / Data-Flow Graph")
        dfg_vlayout = QtWidgets.QVBoxLayout(dfg_group)

        # 深度
        depth_layout = QtWidgets.QHBoxLayout()
        depth_spin = QtWidgets.QSpinBox()
        depth_spin.setRange(1, 10)
        depth_spin.setValue(self._options.get("dfg_depth", 2))
        depth_layout.addWidget(QtWidgets.QLabel("深度/Depth:"))
        depth_layout.addWidget(depth_spin)
        depth_layout.addStretch(1)
        dfg_vlayout.addLayout(depth_layout)

        # 截断开关与上限
        trunc_layout = QtWidgets.QHBoxLayout()
        trunc_chk = QtWidgets.QCheckBox("启用截断/Truncate")
        trunc_chk.setChecked(self._options.get("dfg_truncate", True))
        max_spin = QtWidgets.QSpinBox()
        max_spin.setRange(1000, 50000)
        max_spin.setValue(self._options.get("dfg_max_chars", 5000))
        trunc_layout.addWidget(trunc_chk)
        trunc_layout.addWidget(QtWidgets.QLabel("最大字符/Max:"))
        trunc_layout.addWidget(max_spin)
        trunc_layout.addStretch(1)
        dfg_vlayout.addLayout(trunc_layout)

        layout.addWidget(dfg_group)

        # 控件启用/禁用逻辑
        def update_enabled(state):
            enabled = state == QtCore.Qt.Checked
            for w in (depth_spin, trunc_chk, max_spin):
                w.setEnabled(enabled)
            max_spin.setEnabled(enabled and self.chk_data_flow.isChecked())

        def toggle_max(state):
            max_spin.setEnabled(state == QtCore.Qt.Checked and self.chk_data_flow.isChecked())

        self.chk_data_flow.stateChanged.connect(update_enabled)
        trunc_chk.stateChanged.connect(toggle_max)
        update_enabled(self.chk_data_flow.checkState())

        self._depth_spin = depth_spin
        self._max_spin = max_spin
        self._trunc_chk = trunc_chk

        btn_box = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        btn_box.accepted.connect(self.accept)
        btn_box.rejected.connect(self.reject)
        layout.addWidget(btn_box)

    def get_options(self):
        """
        Return the options selected by the user. / 返回用户勾选的上下文选项。
        """
        return {
            "data_flow_graph": self.chk_data_flow.isChecked(),
            "current_function": self.chk_current_func.isChecked(),
            "decompiled_function": self.chk_decompiled_func.isChecked(),
            "call_chain": self.chk_call_chain.isChecked(),
            "dfg_depth": self._depth_spin.value(),
            "dfg_max_chars": self._max_spin.value(),
            "dfg_truncate": self._trunc_chk.isChecked(),
        }

    def closeEvent(self, event):
        size = self.size()
        dlg_sizes = self._cfg.config.setdefault("dialog_sizes", {})
        dlg_sizes["context_dialog"] = (size.width(), size.height())
        try:
            self._cfg.save_config()
        except Exception:
            pass
        super().closeEvent(event)

class PromptEditorDialog(QtWidgets.QDialog):
    """
    A simple dialog that displays the full prompt text and lets the user
    edit it before sending to the AI backend.
    提示词查看/编辑对话框，允许用户在提交给 AI 之前查看并编辑完整 Prompt。
    """
    def __init__(self, parent=None, prompt_text=""):
        """
        Create the editor dialog and restore its last size from configuration.
        创建编辑器对话框，并从配置中恢复上次窗口大小。
        """
        super().__init__(parent)
        self.setWindowTitle("查看 / 编辑提示词")

        from ..Config.config import ConfigManager  # 延迟导入避免循环
        self._cfg = ConfigManager()

        dlg_sizes = self._cfg.config.setdefault("dialog_sizes", {})
        width, height = dlg_sizes.get("prompt_editor", (800, 600))
        self.resize(width, height)
        self.setMinimumSize(600, 400)

        self._edit = QtWidgets.QPlainTextEdit()
        self._edit.setPlainText(prompt_text)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(self._edit)

        btn_box = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        btn_box.accepted.connect(self.accept)
        btn_box.rejected.connect(self.reject)
        layout.addWidget(btn_box)

    def get_prompt(self):
        """Return the current prompt text from the editor. / 返回编辑器中的当前 Prompt 文本。"""
        return self._edit.toPlainText()

    def closeEvent(self, event):
        """
        Save current window size back to configuration on close.
        在关闭对话框时，将当前窗口大小保存回配置文件。
        """
        size = self.size()
        dlg_sizes = self._cfg.config.setdefault("dialog_sizes", {})
        dlg_sizes["prompt_editor"] = (size.width(), size.height())
        try:
            self._cfg.save_config()
        except Exception:
            pass
        super().closeEvent(event)

class StreamingTextEdit(QtWidgets.QTextBrowser):
    """
    Custom QTextBrowser that supports streaming text updates and Markdown
    rendering with a dark theme suitable for code display.
    支持流式文本更新和 Markdown 渲染的定制 QTextBrowser，采用深色主题以便于显示代码。
    """
    def __init__(self, parent=None):
        """
        Initialize the streaming text widget and set default visual styles.
        初始化流式文本窗口组件，并设置默认显示样式。
        """
        super(StreamingTextEdit, self).__init__(parent)
        self.setReadOnly(True)
        self.setOpenExternalLinks(False)
        self.setOpenLinks(False)
        self.stream_start_block_number = -1
        self.stream_start_pos = -1
        font = QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.FixedFont)
        self.setFont(font)
        self.document().setDefaultStyleSheet("""
            body { color: #D4D4D4; background-color: #1E1E1E; }
            h1, h2, h3, h4, h5, h6 { color: #569CD6; }
            a { color: #4E94CE; }
            code { background-color: #2D2D2D; border: 1px solid #444; border-radius: 3px; padding: 2px; font-family: Consolas, 'Courier New', monospace; color: #CE9178; }
            pre { background-color: #1A1A1A; border: 1px solid #444; border-radius: 4px; padding: 10px; white-space: pre-wrap; }
            blockquote { border-left: 2px solid #555; padding-left: 10px; color: #999; }
            /* Pygments codehilite classes */
            .k { color: #569CD6; }        /* keyword */
            .kt { color: #4EC9B0; }       /* type */
            .s { color: #CE9178; }        /* string */
            .c1 { color: #6A9955; }       /* comment */
            .o { color: #D4D4D4; }
            .n { color: #9CDCFE; }
            .mi { color: color: #B5CEA8; }
            .p { color: #D4D4D4; }
        """)

    def append_stream_chunk(self, text):
        """
        Append a plain-text chunk at the end of the document during streaming.
        在流式输出过程中，将纯文本块追加到文档末尾。
        """
        cursor = self.textCursor()
        cursor.movePosition(QtGui.QTextCursor.End)
        cursor.insertText(text)
        self.ensureCursorVisible()

    def append_markdown_message(self, text):
        """
        Append a complete Markdown message, converting it to rich-text if the
        ``markdown`` library is available.
        追加完整的 Markdown 消息；若已安装 ``markdown`` 库，则转换为富文本格式。
        """
        cursor = self.textCursor()
        cursor.movePosition(QtGui.QTextCursor.End)

        if cursor.position() > 0:
            cursor.insertBlock(QtGui.QTextBlockFormat())

        if markdown:
            html = markdown.markdown(text, extensions=['fenced_code', 'codehilite', 'tables'])
            cursor.insertHtml(html)
        else:
            cursor.insertText(text)

        cursor.movePosition(QtGui.QTextCursor.End)
        cursor.insertBlock(QtGui.QTextBlockFormat())
        self.ensureCursorVisible()

    def mark_stream_start(self):
        """Record the current cursor position as the start of a stream. / 记录当前光标位置，作为流式输出的起始点。"""
        cursor = self.textCursor()
        cursor.movePosition(QtGui.QTextCursor.End)
        self.stream_start_pos = cursor.position()

    def replace_streamed_content_with_markdown(self, markdown_text):
        """
        Replace previously streamed plain text with rendered Markdown once the
        final content is available.
        当流式输出完成后，用渲染后的 Markdown 替换之前的纯文本。
        """
        if self.stream_start_pos == -1 or not markdown:
            self.append_markdown_message(markdown_text)
            return

        cursor = self.textCursor()
        cursor.setPosition(self.stream_start_pos)
        cursor.movePosition(QtGui.QTextCursor.End, QtGui.QTextCursor.KeepAnchor)
        cursor.removeSelectedText()

        html = markdown.markdown(markdown_text, extensions=['fenced_code', 'codehilite', 'tables'])
        cursor.insertHtml(html)

        cursor.movePosition(QtGui.QTextCursor.End)
        cursor.insertBlock(QtGui.QTextBlockFormat())

        self.setTextCursor(cursor)
        self.ensureCursorVisible()
        self.stream_start_pos = -1


class OutputView(idaapi.PluginForm):
    """
    Main output window of the NexusAI plugin.
    该类实现 NexusAI 的主输出窗口，包含富文本显示区、输入框以及与任务控制器交互的各类按钮。
    """
    def __init__(self, controller):
        """
        Create an OutputView bound to a task controller.
        创建 OutputView，并与任务控制器实例绑定。
        """
        super(OutputView, self).__init__()
        self.controller = controller
        self.parent = None
        self.output_widget = None
        self.input_widget = None
        self.comment_type_combo = None
        self.auto_comment_btn = None
        self.apply_comment_btn = None
        self.settings_dialog = None

        defaults = self.controller.config.config.get("context_defaults", {})

        self.context_options = {
            "data_flow_graph": defaults.get("data_flow_graph", False),
            "current_function": defaults.get("current_function", False),
            "decompiled_function": defaults.get("decompiled_function", False),
            "call_chain": defaults.get("call_chain", False),
            "dfg_depth": defaults.get("dfg_depth", 2),
            "dfg_max_chars": defaults.get("dfg_max_chars", 5000),
            "dfg_truncate": defaults.get("dfg_truncate", True),
        }
        self.modified_prompt = None
        get_event_bus().on("language_changed", self._update_language_texts)

    def _update_language_texts(self):
        """
        Refresh all static texts inside the window when language changes.
        当语言切换时，刷新窗口内所有静态文本。
        """
        import sip
        lang = self.controller.config.language

        # 若控件已被销毁或尚未创建，安全退出
        if not hasattr(self, "input_widget") or self.input_widget is None or sip.isdeleted(self.input_widget):
            return

        # 设置输入框占位符文本
        self.input_widget.setPlaceholderText(self.controller.config.get_message("chat_input_placeholder"))

        if lang == "en_US":
            base_text = "Start Auto Comment"
            items = [
                ("Function Comment", "function"),
                ("Line Comment", "line"),
                ("Repeatable Comment", "repeatable"),
                ("Anterior Comment", "anterior"),
            ]
        else:
            base_text = "自动注释"
            items = [
                ("函数注释", "function"),
                ("行注释", "line"),
                ("可重复注释", "repeatable"),
                ("前置注释", "anterior"),
            ]

        self.comment_type_combo.blockSignals(True)
        self.comment_type_combo.clear()
        for text, data in items:
            self.comment_type_combo.addItem(text, data)
        self.comment_type_combo.blockSignals(False)

        self.auto_comment_btn.setText(base_text)

        self._refresh_auto_comment_btn_label()

        if hasattr(self, "context_btn"):
            self.context_btn.setText("Context" if lang == "en_US" else "附加上下文")
        if hasattr(self, "view_prompt_btn"):
            self.view_prompt_btn.setText("View Prompt" if lang == "en_US" else "查看提示词")
        if hasattr(self, "aimcp_toggle_btn"):
            self.aimcp_toggle_btn.setText("AIMCP" if lang == "en_US" else "AIMCP")
        if hasattr(self, "history_btn"):
            self.history_btn.setText("History" if lang == "en_US" else "历史")

        tooltip_dict = self.controller.config.config.get("messages", {}).get(lang, {}).get("tooltip", {})
        self.auto_comment_btn.setToolTip(tooltip_dict.get("analyze_func", self.auto_comment_btn.toolTip()))

        if self.parent:
            self.parent.update()
        return

    def init_ui(self):
        """Build all UI widgets for the output window, then apply language texts."""
        # ---------------- Build Layout ----------------
        layout = QtWidgets.QVBoxLayout()

        self.output_widget = StreamingTextEdit(self.parent)
        self.output_widget.anchorClicked.connect(self.on_anchor_clicked)
        # 自定义右键菜单
        self.output_widget.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.output_widget.customContextMenuRequested.connect(self._show_output_context_menu)
        bottom_layout = QtWidgets.QHBoxLayout()
        
        self.comment_type_combo = QtWidgets.QComboBox()
        self.comment_type_combo.setSizeAdjustPolicy(QtWidgets.QComboBox.AdjustToContents)
        self.comment_type_combo.setMinimumContentsLength(20)
        self.comment_type_combo.currentIndexChanged.connect(self._refresh_auto_comment_btn_label)
        
        self.auto_comment_btn = QtWidgets.QPushButton()
        self.auto_comment_btn.clicked.connect(self.on_auto_comment_clicked)
        
        lang = self.controller.config.language
        settings_text = "Settings" if lang == "en_US" else "设置"
        settings_btn = QtWidgets.QPushButton(settings_text)
        settings_btn.clicked.connect(self.on_settings_clicked)
        
        bottom_layout.addWidget(self.comment_type_combo)
        bottom_layout.addWidget(self.auto_comment_btn)

        self.context_btn = QtWidgets.QPushButton()
        self.context_btn.clicked.connect(self.on_context_clicked)
        bottom_layout.addWidget(self.context_btn)

        self.view_prompt_btn = QtWidgets.QPushButton()
        self.view_prompt_btn.clicked.connect(self.on_view_prompt_clicked)
        bottom_layout.addWidget(self.view_prompt_btn)

        self.history_btn = QtWidgets.QPushButton("历史")
        self.history_btn.clicked.connect(self.on_history_clicked)
        bottom_layout.addWidget(self.history_btn)

        self.aimcp_toggle_btn = QtWidgets.QPushButton("AIMCP")
        self.aimcp_toggle_btn.setCheckable(True)
        cfg_enabled = self.controller.config.config.get("aimcp_enabled", False)
        self.aimcp_toggle_btn.setChecked(cfg_enabled)
        self.aimcp_toggle_btn.toggled.connect(self.on_aimcp_toggled)
        bottom_layout.addWidget(self.aimcp_toggle_btn)
        
        bottom_layout.addStretch(1)
        bottom_layout.addWidget(settings_btn)
        
        self.input_widget = QtWidgets.QLineEdit()
        self.input_widget.returnPressed.connect(self.on_input_submit)
        
        layout.addWidget(self.output_widget, 1)
        layout.addLayout(bottom_layout)
        layout.addWidget(self.input_widget)
        
        self.parent.setLayout(layout)

        self._update_language_texts()
        self._refresh_auto_comment_btn_label()

    def OnCreate(self, form):
        """
        Initialize UI components when the OutputView form is created.
        当 IDA Pro 创建本插件窗口时调用。
        """
        self.parent = self.FormToPyQtWidget(form)
        self.init_ui()
        self.controller.config.set_output_view(self)
        try:
            idaapi.set_dock_pos("NexusAI", None, idaapi.DP_RIGHT)
        except Exception as e:
            idaapi.msg(f"[NexusAI] 无法设置停靠位置: {e}\n")

    def on_settings_clicked(self):
        """
        Open the *Settings* dialog when the **Settings** button is pressed.
        当用户点击"设置"按钮时，弹出设置对话框。
        """
        if not self.settings_dialog:
            self.settings_dialog = SettingsDialog(self.parent, self.controller.config)
            
        def show_settings_dialog():
            result = self.settings_dialog.exec_()
            
            if result == QtWidgets.QDialog.Accepted:
                def update_ui():
                    self._update_language_texts()
                    for child in self.parent.findChildren(QtWidgets.QPushButton):
                        if child.text() in ["设置", "Settings"]:
                            lang = self.controller.config.language
                            settings_text = "Settings" if lang == "en_US" else "设置"
                            child.setText(settings_text)
                            break
                QtCore.QTimer.singleShot(0, update_ui)
        
        QtCore.QTimer.singleShot(0, show_settings_dialog)
        
    def on_auto_comment_clicked(self):
        """
        Start an automatic commenting task according to the selected comment
        type.
        当用户点击"自动注释"按钮时，根据下拉框中选择的注释类型启动对应的自动注释任务。
        """
        comment_type = self.comment_type_combo.currentData()
        
        current_ea = idaapi.get_screen_ea()
        if idc.get_func_attr(current_ea, idc.FUNCATTR_START) == idaapi.BADADDR:
            self.append_text(
                _t(
                    "❌ 当前位置不在任何函数内，无法生成注释",
                    "❌ Not inside any function, cannot generate comment",
                )
            )
            return
        
        self.controller.comment_applicator.is_comment_mode_active = True
        
        self.append_text(_t("ℹ️ 正在生成注释...", "ℹ️ Generating comment..."))
        
        if comment_type == "function":
            self.controller.start_task(TaskType.COMMENT_FUNCTION, "请生成这个函数的详细注释，包含功能描述、参数和返回值的解释，使用C语言风格的注释格式/* ... */")
        elif comment_type in ["line", "repeatable", "anterior"]:
            self.controller.start_task(TaskType.GENERATE_LINE_COMMENT, f"请为当前行生成一个简洁的{self.comment_type_combo.currentText()}，使用C语言风格的注释格式/* ... */")
            

    def on_input_submit(self):
        """
        Handle the <Return> key in the input box: dispatch the user question
        or comment request to the task controller.
        处理输入框中的回车事件，将用户的提问或注释请求发送给任务控制器。
        """
        question = self.input_widget.text()
        if not question or not question.strip():
            return
            
        self.append_text(f"<b>You:</b> {question}")
        self.controller.config.history.append(("text", f"<b>You:</b> {question}"))

        try:
            if self.controller.comment_applicator.is_comment_mode_active:
                comment_type = self.comment_type_combo.currentData()
                if comment_type == "function":
                    self.controller.start_task(TaskType.COMMENT_FUNCTION, question)
                elif comment_type in ["line", "repeatable", "anterior"]:
                    self.controller.start_task(TaskType.GENERATE_LINE_COMMENT, question)
            else:
                if self.controller.config.config.get("aimcp_enabled", False):
                    self.controller.start_task(TaskType.AIMCP, question)
                    self.input_widget.clear()
                    return

                use_ctx = any(self.context_options.values())

                if use_ctx:
                    final_prompt = self.modified_prompt if self.modified_prompt else self.build_full_prompt(question)
                    self.controller.start_task(TaskType.CUSTOM_QUERY, final_prompt)
                    self.modified_prompt = None
                else:
                    current_ea = idaapi.get_screen_ea()
                    if idc.get_func_attr(current_ea, idc.FUNCATTR_START) != idaapi.BADADDR:
                        self.controller.start_task(TaskType.CUSTOM_QUERY_WITH_CODE, question)
                    else:
                        self.controller.start_task(TaskType.CUSTOM_QUERY, question)
        except Exception as e:
            self.controller.config.show_message("task_start_error", str(e))

        self.input_widget.clear()

    def OnClose(self, form):
        """
        Deregister the current OutputView from :class:`ConfigManager` when the
        window is closed.
        窗口关闭时，从 ConfigManager 注销当前 OutputView 实例。
        """
        # 取消语言变更订阅，防止已销毁控件被访问
        try:
            get_event_bus().off("language_changed", self._update_language_texts)
        except Exception:
            pass
        self.controller.config.set_output_view(None)
        from ..Core.plugin import NexusAIPlugin
        instance = NexusAIPlugin.get_instance()
        if instance:
            instance.on_output_view_close()

    def Show(self):
        """
        Display the dockable **NexusAI** output window inside IDA Pro.
        在 IDA Pro 中显示可停靠的 NexusAI 输出窗口。
        """
        # 获取包含版本信息的标题
        try:
            from ..Utils.version_manager import get_version_manager
            version_manager = get_version_manager(self.controller.config)
            window_title = version_manager.get_version_title()
        except Exception as e:
            print(f"Error getting version title: {e}")
            window_title = "NexusAI"

        return idaapi.PluginForm.Show(self, window_title, options=idaapi.PluginForm.WOPN_DP_RIGHT | idaapi.PluginForm.WCLS_CLOSE_LATER)

    def append_text(self, text):
        """
        Append plain or simple HTML *text* to the output widget and scroll to
        the bottom.
        向输出区域追加纯文本或简单 HTML，并自动滚动到底部。
        """
        def _append():
            if self.output_widget:
                cursor = self.output_widget.textCursor()
                cursor.movePosition(QtGui.QTextCursor.End)
                
                cursor.insertBlock(QtGui.QTextBlockFormat())

                cursor.insertHtml(text)

                self.output_widget.ensureCursorVisible()
        idaapi.execute_sync(_append, idaapi.MFF_WRITE)
    
    def append_markdown(self, markdown_text):
        """
        Append a complete Markdown message, render it to rich text, and scroll
        to the bottom.
        追加完整 Markdown 消息，渲染为富文本并滚动至底部。
        """
        def _append_markdown():
            if self.output_widget:
                self.output_widget.append_markdown_message(markdown_text)
                self.output_widget.ensureCursorVisible()
        idaapi.execute_sync(_append_markdown, idaapi.MFF_WRITE)

    def mark_stream_start(self):
        """
        Mark the current cursor position so that incoming stream chunks can be
        replaced by the final Markdown later.
        记录当前位置，便于日后用最终的 Markdown 替换流式文本。
        """
        idaapi.execute_sync(lambda: self.output_widget and self.output_widget.mark_stream_start(), idaapi.MFF_WRITE)
            
    def finalize_stream(self, markdown_text):
        """
        Replace previously streamed plain text with the rendered Markdown and
        (if in comment mode) attempt to auto-apply the comment.
        用渲染后的 Markdown 替换流式文本；若处于注释模式则尝试自动应用注释。
        """
        idaapi.execute_sync(lambda: self.output_widget and self.output_widget.replace_streamed_content_with_markdown(markdown_text), idaapi.MFF_WRITE)
        
        if self.controller.comment_applicator.is_comment_mode_active:
            idaapi.execute_sync(lambda: self.try_auto_apply_comment(markdown_text), idaapi.MFF_WRITE)
            
    def force_refresh_pseudocode(self, ea):
        """
        Programmatically refresh the Hex-Rays pseudocode view for *ea* without
        closing the tab.
        强制刷新指定函数的反编译视图，效果等同于用户点击 "Refresh"。

        Args / 参数:
            ea: Function start address (函数起始地址)。
        """
        try:
            func_ea = idc.get_func_attr(ea, idc.FUNCATTR_START)
            if func_ea == idaapi.BADADDR:
                return False
                
            if not idaapi.init_hexrays_plugin():
                return False
                
            idaapi.mark_cfunc_dirty(func_ea)
                
            idaapi.refresh_idaview_anyway()
            
            for widget_title in ["Pseudocode-A", "Pseudocode-B", "Pseudocode-C"]:
                widget = idaapi.find_widget(widget_title)
                if widget:
                    idaapi.activate_widget(widget, True)
                    
                    vu = idaapi.get_widget_vdui(widget)
                    if vu and vu.cfunc and vu.cfunc.entry_ea == func_ea:
                        vu.refresh_view(True)
                        vu.refresh_ctext(True)
                        
                        idaapi.process_ui_action("hx:Refresh")
                        
                        log_message(_t(f"已通过模拟交互刷新 {widget_title} 视图", f"Refreshed {widget_title} view via simulated interaction"), "info")
            
            from ..Config.config import ConfigManager as _Cfg
            _LANG = _Cfg().language
            log_message("View refreshed" if _LANG == "en_US" else "已刷新视图", "info")
            return True
            
        except Exception as e:
            log_message(_t(f"刷新视图时出错: {str(e)}", f"Error refreshing view: {str(e)}"), "error")
            return False
            
    def try_auto_apply_comment(self, comment_text):
        """
        Attempt to automatically apply *comment_text* at the current location
        according to the selected comment type.

        若仍处于自动注释模式，依据所选注释类型把 *comment_text* 写入当前
        地址或函数。

        Args / 参数:
            comment_text: AI-generated comment string.
        """
        # 如果不是注释模式，直接返回
        if not self.controller.comment_applicator.is_comment_mode_active:
            return
            
        # 清理注释文本，移除C风格注释标记
        comment_text = comment_text.strip()
        # 移除开头的 /* 和结尾的 */
        if comment_text.startswith("/*"):
            comment_text = comment_text[2:].lstrip()
        if comment_text.endswith("*/"):
            comment_text = comment_text[:-2].rstrip()
            
        # 移除每行开头可能存在的 * 或 //
        lines = comment_text.split("\n")
        cleaned_lines = []
        for line in lines:
            line = line.strip()
            if line.startswith("* "):
                line = line[2:]
            elif line.startswith("//"):
                line = line[2:].lstrip()
            elif line.startswith("/*"):
                line = line[2:].lstrip()
            elif line.endswith("*/"):
                line = line[:-2].rstrip()
            cleaned_lines.append(line)
        
        comment_text = "\n".join(cleaned_lines)
            
        # 设置注释文本
        self.controller.comment_applicator.set_comment_text(comment_text)
        
        # 获取当前选择的注释类型
        comment_type = self.comment_type_combo.currentData()
        ea = idaapi.get_screen_ea()
        
        # 根据注释类型应用注释
        result = False
        if comment_type == "function":
            result = self.controller.comment_applicator.apply_function_comment(ea)
        elif comment_type == "line":
            result = self.controller.comment_applicator.apply_line_comment(ea)
        elif comment_type == "repeatable":
            result = self.controller.comment_applicator.apply_repeatable_comment(ea)
        elif comment_type == "anterior":
            result = self.controller.comment_applicator.apply_anterior_comment(ea)
        
        # 显示结果信息
        if result:
            self.append_text(
                _t(
                    f"✅ 已自动应用{self.comment_type_combo.currentText()}",
                    f"✅ Auto-applied {self.comment_type_combo.currentText()}",
                )
            )
        else:
            self.append_text(
                _t(
                    f"❌ 自动应用{self.comment_type_combo.currentText()}失败",
                    f"❌ Auto-apply {self.comment_type_combo.currentText()} failed",
                )
            )

    def append_stream_chunk(self, chunk):
        """
        Append a plain-text *chunk* received during streaming mode.

        在流式响应过程中追加纯文本块。
        """
        idaapi.execute_sync(lambda: self.output_widget and self.output_widget.append_stream_chunk(chunk), idaapi.MFF_WRITE)
            
    def clear(self):
        """
        Clear all contents of the output widget.

        清空输出窗口内容。
        """
        idaapi.execute_sync(lambda: self.output_widget and self.output_widget.clear(), idaapi.MFF_WRITE) 
    def on_anchor_clicked(self, url):
        """
        Handle hyperlink clicks. For ``ida:`` scheme jump inside IDA, else open with the system handler.
        处理超链接点击。如果url以 ``ida:`` 开头，则在IDA中跳转，否则使用系统处理程序打开。
        """
        try:
            if url.scheme() == "ida":
                addr_str = url.toString()[4:]
                ea = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str, 16)
                idaapi.jumpto(ea)
            else:
                QtGui.QDesktopServices.openUrl(url)
        except Exception as e:
            log_message(_t(f"跳转地址失败: {e}", f"Failed to jump to address: {e}"), "error") 

    def _show_output_context_menu(self, pos):
        """在输出区显示自定义上下文菜单。"""
        lang = self.controller.config.language
        menu = QtWidgets.QMenu(self.output_widget)

        # 动态文本
        stop_text = "Stop Task" if lang == "en_US" else "停止任务"
        clear_text = "Clear Output" if lang == "en_US" else "清空输出"
        copy_all_text = "Copy All" if lang == "en_US" else "复制全部"
        select_all_text = "Select All" if lang == "en_US" else "全选"

        act_stop = menu.addAction(stop_text)
        act_clear = menu.addAction(clear_text)
        menu.addSeparator()
        act_copy = menu.addAction(copy_all_text)
        act_select = menu.addAction(select_all_text)

        action = menu.exec_(self.output_widget.mapToGlobal(pos))
        if action == act_stop:
            self.controller.stop_task()
        elif action == act_clear:
            self.output_widget.clear()
        elif action == act_copy:
            self.output_widget.selectAll()
            self.output_widget.copy()
            self.output_widget.moveCursor(QtGui.QTextCursor.End)  # 取消选择
        elif action == act_select:
            self.output_widget.selectAll()

    def _refresh_auto_comment_btn_label(self):
        """
        Update the *Auto Comment* button label to include the configured shortcut key.
        更新"自动注释"按钮标签，以包含配置的快捷键。
        """
        shortcuts = self.controller.config.config.get("shortcuts", {})
        mapping = {
            "function": "comment_function",
            "line": "comment_line",
            "repeatable": "comment_repeatable",
            "anterior": "comment_anterior",
        }

        comment_type = self.comment_type_combo.currentData()
        sc_key = shortcuts.get(mapping.get(comment_type, ""), "")

        base = self.auto_comment_btn.text().split(" (")[0]
        if sc_key:
            self.auto_comment_btn.setText(f"{base} ({sc_key})")
        else:
            self.auto_comment_btn.setText(base)

    def on_context_clicked(self):
        """
        Show the context-selection dialog so the user can choose extra context (DFG, call-chain, etc.) for the next prompt.
        弹出上下文选择对话框，允许用户为下一个提示选择额外上下文（DFG、调用链等）。
        """
        dlg = ContextSelectionDialog(self.parent, self.context_options)
        if dlg.exec_() == QtWidgets.QDialog.Accepted:
            self.context_options = dlg.get_options()
            cfg = self.controller.config
            cfg.config.setdefault("context_defaults", self.context_options)
            cfg.config["context_defaults"] = self.context_options
            try:
                cfg.save_config()
            except Exception:
                pass

    def on_view_prompt_clicked(self):
        """
        Display the full prompt and allow the user to edit it before sending to the LLM.
        显示完整提示，并允许用户在发送到LLM之前对其进行编辑。
        """
        question = self.input_widget.text().strip()
        base_prompt = self.build_full_prompt(question)
        dlg = PromptEditorDialog(self.parent, base_prompt)
        if dlg.exec_() == QtWidgets.QDialog.Accepted:
            self.modified_prompt = dlg.get_prompt()

    def on_aimcp_toggled(self, state: bool):
        """
        Toggle AIMCP (Auto-Interactive Multi-Cycle Prompting) automation.
        切换 AIMCP（自动交互多周期提示）自动化。
        """
        self.controller.config.config["aimcp_enabled"] = bool(state)
        try:
            self.controller.config.save_config()
        except Exception:
            pass
        get_event_bus().emit("aimcp_toggle", state)
        self.append_text(
            f"<div style='color:#2ECC71;'>✅ AIMCP 自动化已{'启用' if state else '关闭'}</div>"
        )

    def build_full_prompt(self, question: str) -> str:
        """
        Construct the final prompt by combining *question* with the context options currently selected by the user.
        根据用户当前选择的上下文选项，构建最终的prompt。
        """
        parts = []

        if self.context_options.get("data_flow_graph"):
            try:
                GraphExporterCls = _get_graph_exporter_cls()
                if GraphExporterCls is None:
                    parts.append(_t("【提示】未能加载 GraphExporter，数据流图不可用。", "【Note】Failed to load GraphExporter, data flow graph is unavailable."))
                else:
                    current_ea = idaapi.get_screen_ea()
                    func = idaapi.get_func(current_ea)
                    if func:
                        exporter = GraphExporterCls()
                        depth_val = self.context_options.get("dfg_depth", 2)
                        _, data_path = exporter.export_subgraph(func.start_ea, depth=depth_val)
                        data_text = Path(data_path).read_text(encoding="utf-8")
                        max_chars = self.context_options.get("dfg_max_chars", 5000)
                        do_trunc = self.context_options.get("dfg_truncate", True)
                        if do_trunc and max_chars > 0 and len(data_text) > max_chars:
                            data_text = data_text[:max_chars] + "... (truncated)"
                        header = _t("以下是当前函数的数据流图 (JSON):", "Below is the data flow graph of the current function (JSON):")
                        parts.append(f"{header}\n```json\n{data_text}\n```")
            except Exception as e:
                log_message(_t(f"生成数据流图失败: {e}", f"Failed to generate data flow graph: {e}"), "error")

        if self.context_options.get("current_function"):
            try:
                current_ea = idaapi.get_screen_ea()
                func = idaapi.get_func(current_ea)
                if func:
                    code_snippet = self.controller.code_extractor._get_disassembly(func.start_ea)
                    header = _t("以下是当前函数汇编代码:", "Below is the current function assembly:")
                    parts.append(f"{header}\n```asm\n{code_snippet}\n```")
            except Exception as e:
                log_message(_t(f"提取当前函数汇编失败: {e}", f"Failed to extract current function assembly: {e}"), "error")

        if self.context_options.get("decompiled_function"):
            try:
                current_ea = idaapi.get_screen_ea()
                func = idaapi.get_func(current_ea)
                if func:
                    pseudocode = idaapi.decompile(func.start_ea)
                    if pseudocode:
                        header = _t("以下是当前函数的反编译代码:", "Below is the decompiled code of the current function:")
                        parts.append(f"{header}\n```c\n{str(pseudocode)}\n```")
            except Exception as e:
                log_message(_t(f"提取反编译代码失败: {e}", f"Failed to extract decompiled code: {e}"), "error")

        if self.context_options.get("call_chain"):
            try:
                depth = self.controller.config.analysis_depth
                chain_code = self.controller.code_extractor.extract_current_function_recursive(depth)
                header = _t(f"以下是函数调用链 (深度 {depth}) 代码:", f"Below is the call chain code (depth {depth}):")
                parts.append(f"{header}\n```c\n{chain_code}\n```")
            except Exception as e:
                log_message(_t(f"提取调用链代码失败: {e}", f"Failed to extract call chain code: {e}"), "error")

        context_text = "\n\n".join(parts)
        if context_text:
            return context_text + "\n\n" + question
        return question 

    def on_history_clicked(self):
        """打开历史对话管理面板"""
        dialog = HistoryDialog(self.parent, self.controller.config)
        dialog.exec_()

class HistoryDialog(QtWidgets.QDialog):
    """浏览、搜索并管理会话历史。"""

    def __init__(self, parent, cfg_manager):
        super().__init__(parent)
        self.setWindowTitle("对话历史")

        dlg_sizes = cfg_manager.config.setdefault("dialog_sizes", {})
        w, h = dlg_sizes.get("history_dialog", (900, 600))
        self.resize(w, h)

        self.cfg = cfg_manager
        self.history_mgr = cfg_manager.history_manager

        # 监听会话变更事件
        from ..Core.event_bus import get_event_bus
        get_event_bus().on("session_changed", self._refresh_list)

        left_box = QtWidgets.QVBoxLayout()

        self.search_line = QtWidgets.QLineEdit()
        self.search_line.setPlaceholderText("搜索会话…")
        left_box.addWidget(self.search_line)

        self.list_widget = QtWidgets.QListWidget()
        left_box.addWidget(self.list_widget, 1)

        btn_layout = QtWidgets.QHBoxLayout()
        self.btn_restore = QtWidgets.QPushButton("恢复")
        self.btn_delete = QtWidgets.QPushButton("删除")
        self.btn_rename = QtWidgets.QPushButton("重命名")
        self.btn_new = QtWidgets.QPushButton("新对话")
        for b in (self.btn_new, self.btn_restore, self.btn_rename, self.btn_delete):
            btn_layout.addWidget(b)
        left_box.addLayout(btn_layout)

        self.preview = QtWidgets.QTextBrowser()

        main_layout = QtWidgets.QHBoxLayout(self)
        left_container = QtWidgets.QWidget()
        left_container.setLayout(left_box)
        main_layout.addWidget(left_container, 1)
        main_layout.addWidget(self.preview, 2)

        self.search_line.textChanged.connect(self._refresh_list)
        self.list_widget.itemSelectionChanged.connect(self._on_sel_change)
        self.list_widget.itemDoubleClicked.connect(self._on_restore_clicked)
        self.btn_restore.clicked.connect(self._on_restore_clicked)
        self.btn_delete.clicked.connect(self._on_delete_clicked)
        self.btn_rename.clicked.connect(self._on_rename_clicked)
        self.btn_new.clicked.connect(self._on_new_clicked)

        self._refresh_list()

    def _session_display_text(self, sess_meta: dict) -> str:
        name = sess_meta.get("name", "")
        ts = sess_meta.get("timestamp", "")
        return f"{ts} | {name}"

    def _refresh_list(self, *args):
        keyword = self.search_line.text().strip().lower()
        self.list_widget.clear()
        sessions = self.history_mgr.list_sessions()
        for meta in sessions:
            text = self._session_display_text(meta)
            if keyword and keyword not in text.lower():
                continue
            item = QtWidgets.QListWidgetItem(text)
            item.setData(QtCore.Qt.UserRole, meta.get("name"))
            if meta.get("name") == self.history_mgr.current._meta.get("name"):
                f = item.font()
                f.setBold(True)
                item.setFont(f)
            self.list_widget.addItem(item)

    def _selected_name(self) -> str | None:
        sel = self.list_widget.selectedItems()
        if not sel:
            return None
        return sel[0].data(QtCore.Qt.UserRole)

    def _on_sel_change(self):
        name = self._selected_name()
        if not name:
            self.preview.clear()
            return
        path = self.history_mgr._session_file(name)
        if not path.exists():
            self.preview.clear()
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            html_parts = []
            for method, txt in data.get("messages", []):
                if method == "markdown":
                    html_parts.append(txt)
                else:
                    html_parts.append(f"<pre>{txt}</pre>")
            self.preview.setHtml("<hr/>".join(html_parts))
        except Exception:
            self.preview.setPlainText("无法加载会话内容")

    def _on_restore_clicked(self, *_):
        name = self._selected_name()
        if not name:
            return
        self.cfg.switch_session(name)
        self.accept()

    def _on_delete_clicked(self):
        name = self._selected_name()
        if not name:
            return
        if QtWidgets.QMessageBox.question(self, "确认", f"确定删除会话 {name} 吗？") != QtWidgets.QMessageBox.Yes:
            return
        self.history_mgr.delete_session(name)
        self._refresh_list()

    def _on_rename_clicked(self):
        name = self._selected_name()
        if not name:
            return
        new_name, ok = QtWidgets.QInputDialog.getText(self, "重命名", "输入新名称:", text=name)
        if not ok or not new_name.strip():
            return
        try:
            self.history_mgr.rename_session(name, new_name.strip())
            if name == self.cfg.config.get("last_session_name"):
                self.cfg.config["last_session_name"] = new_name.strip()
                self.cfg.save_config()
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "错误", str(e))
        self._refresh_list()

    def _on_new_clicked(self):
        self.cfg.create_new_session()
        # 刷新列表以显示新创建的会话
        self._refresh_list()
        # 选中新创建的会话
        current_session_name = self.cfg.config.get("last_session_name")
        if current_session_name:
            for i in range(self.list_widget.count()):
                item = self.list_widget.item(i)
                if item and item.data(QtCore.Qt.UserRole) == current_session_name:
                    self.list_widget.setCurrentItem(item)
                    break

    def closeEvent(self, event):
        # 取消事件订阅
        from ..Core.event_bus import get_event_bus
        get_event_bus().off("session_changed", self._refresh_list)
        
        size = self.size()
        dlg_sizes = self.cfg.config.setdefault("dialog_sizes", {})
        dlg_sizes["history_dialog"] = (size.width(), size.height())
        try:
            self.cfg.save_config()
        except Exception:
            pass
        super().closeEvent(event)

    def accept(self):
        pass

    def _closeEvent_duplicate(self, event):
        super().closeEvent(event)





