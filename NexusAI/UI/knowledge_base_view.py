"""
Knowledge Base Management UI for NexusAI
NexusAI知识库管理界面

Provides a graphical interface for managing Excel-based knowledge bases.
提供管理基于Excel的知识库的图形界面。
"""

import os
from pathlib import Path
from typing import Optional, Dict, Any, List

try:
    from PyQt5 import QtWidgets, QtCore, QtGui
    from PyQt5.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
        QPushButton, QLabel, QLineEdit, QTextEdit, QComboBox, QCheckBox,
        QFileDialog, QMessageBox, QDialog, QDialogButtonBox, QFormLayout,
        QGroupBox, QProgressBar, QTabWidget, QSplitter, QHeaderView
    )
    from PyQt5.QtCore import Qt, QThread, pyqtSignal
    from PyQt5.QtGui import QFont, QIcon
    QT_AVAILABLE = True
except ImportError:
    try:
        from PySide2 import QtWidgets, QtCore, QtGui
        from PySide2.QtWidgets import (
            QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
            QPushButton, QLabel, QLineEdit, QTextEdit, QComboBox, QCheckBox,
            QFileDialog, QMessageBox, QDialog, QDialogButtonBox, QFormLayout,
            QGroupBox, QProgressBar, QTabWidget, QSplitter, QHeaderView
        )
        from PySide2.QtCore import Qt, QThread, Signal as pyqtSignal
        from PySide2.QtGui import QFont, QIcon
        QT_AVAILABLE = True
    except ImportError:
        QT_AVAILABLE = False

if QT_AVAILABLE:
    import idaapi
    from ..KnowledgeBase import KnowledgeManager, ExcelReader


class KnowledgeBaseView(idaapi.PluginForm):
    """知识库管理界面 / Knowledge base management interface."""

    def __init__(self, config_manager=None):
        """初始化知识库管理界面 / Initialize knowledge base management interface."""
        if not QT_AVAILABLE:
            raise ImportError("Qt framework is not available")

        super(KnowledgeBaseView, self).__init__()
        self.config_manager = config_manager
        self.knowledge_manager = KnowledgeManager(config_manager)
        self.excel_reader = ExcelReader()
        self.parent = None

        # 本地化管理
        self._setup_localization()

        # Initialize UI components
        self.tab_widget = None
        self.kb_table = None
        self.file_path_edit = None
        self.kb_name_edit = None
        self.kb_description_edit = None
        self.preview_text = None
        self.search_edit = None
        self.search_results = None
        self.refresh_btn = None
        self.remove_btn = None
        self.preview_btn = None
        self.add_kb_btn = None
        self.clear_btn = None
        self.search_btn = None

    def _setup_localization(self):
        """设置本地化 / Setup localization."""
        if self.config_manager:
            current_lang = self.config_manager.language
            messages = self.config_manager.config.get("messages", {})
            lang_messages = messages.get(current_lang, {})
            self.strings = lang_messages.get("knowledge_base", {})
        else:
            # 默认使用中文
            self.strings = {
                "window_title": "NexusAI - 知识库管理器",
                "tab_list": "知识库列表",
                "tab_add": "添加知识库",
                "tab_search": "搜索测试",
                "refresh": "刷新",
                "remove": "删除",
                "name": "名称",
                "description": "描述",
                "records": "记录数",
                "status": "状态",
                "updated": "更新时间",
                "file_selection": "Excel文件选择",
                "file_path": "文件路径",
                "browse": "浏览",
                "kb_info": "知识库信息",
                "kb_name": "名称",
                "kb_description": "描述",
                "file_preview": "文件预览",
                "preview_file": "预览文件",
                "add_kb": "添加知识库",
                "clear": "清空",
                "search_query": "搜索查询",
                "search_placeholder": "输入搜索词...",
                "search": "搜索",
                "enabled": "启用",
                "disabled": "禁用",
                "confirm_removal": "确认删除",
                "confirm_removal_msg": "确定要删除 {0} 个知识库吗？",
                "warning": "警告",
                "error": "错误",
                "success": "成功",
                "provide_file_and_name": "请提供文件路径和知识库名称。",
                "missing_deps": "缺少依赖",
                "missing_deps_msg": "缺少一些必需的依赖项。是否要安装它们？",
                "install_deps_failed": "安装依赖项失败。",
                "no_results": "未找到结果。",
                "enter_search_query": "请输入搜索查询。",
                "search_results_for": "'{0}' 的搜索结果：",
                "kb_label": "知识库：",
                "sheet_label": "工作表：",
                "content_label": "内容：",
                "category_label": "类别：",
                "relevance_label": "相关性：",
                "refresh_failed": "刷新知识库失败：{0}",
                "remove_failed": "删除 '{0}' 失败：{1}",
                "search_error": "搜索错误：{0}"
            }

    def tr(self, key, *args):
        """翻译方法 / Translation method."""
        text = self.strings.get(key, key)
        if args:
            try:
                return text.format(*args)
            except:
                return text
        return text

    def OnCreate(self, form):
        """Called when the form is created."""
        try:
            self.parent = self.FormToPyQtWidget(form)
            self.setup_ui()
            self.refresh_knowledge_bases()
            # 尝试设置停靠位置
            try:
                idaapi.set_dock_pos("NexusAI Knowledge Base Manager", None, idaapi.DP_RIGHT)
            except Exception as e:
                print(f"[KnowledgeBase] Cannot set dock position: {e}")
        except Exception as e:
            print(f"Error in OnCreate: {e}")
            import traceback
            traceback.print_exc()

    def OnClose(self, form):
        """Called when the form is closed."""
        # 通知plugin窗口已关闭
        try:
            from ..Core.plugin import NexusAIPlugin
            instance = NexusAIPlugin.get_instance()
            if instance:
                instance.on_knowledge_base_view_close()
        except Exception:
            pass

        # 清理资源
        try:
            if hasattr(self, 'knowledge_manager'):
                del self.knowledge_manager
            if hasattr(self, 'excel_reader'):
                del self.excel_reader
        except Exception:
            pass

    def Show(self):
        """Show the knowledge base manager window."""
        window_title = self.tr("window_title")
        return idaapi.PluginForm.Show(self, window_title,
                                     options=idaapi.PluginForm.WOPN_DP_RIGHT | idaapi.PluginForm.WCLS_CLOSE_LATER)
    
    def setup_ui(self):
        """设置用户界面 / Setup user interface."""
        try:
            if not self.parent:
                print("Error: parent widget is None")
                return

            # 使用与OutputView相同的布局方式
            layout = QVBoxLayout()

            # 标题
            title_label = QLabel(self.tr("window_title"))
            title_label.setFont(QFont("Arial", 14, QFont.Bold))
            title_label.setAlignment(Qt.AlignCenter)
            layout.addWidget(title_label)

            # 创建标签页
            self.tab_widget = QTabWidget()
            layout.addWidget(self.tab_widget)

            # 知识库列表标签页
            self.setup_knowledge_base_tab()

            # 添加知识库标签页
            self.setup_add_knowledge_base_tab()

            # 搜索测试标签页
            self.setup_search_test_tab()

            # 设置布局到父窗口
            self.parent.setLayout(layout)

            print("UI setup completed successfully")

        except Exception as e:
            print(f"Error in setup_ui: {e}")
            import traceback
            traceback.print_exc()
    
    def setup_knowledge_base_tab(self):
        """设置知识库列表标签页 / Setup knowledge base list tab."""
        kb_widget = QtWidgets.QWidget()
        layout = QVBoxLayout(kb_widget)
        
        # 工具栏
        toolbar_layout = QHBoxLayout()

        self.refresh_btn = QPushButton(self.tr("refresh"))
        self.refresh_btn.clicked.connect(self.refresh_knowledge_bases)
        toolbar_layout.addWidget(self.refresh_btn)

        self.remove_btn = QPushButton(self.tr("remove"))
        self.remove_btn.clicked.connect(self.remove_selected_knowledge_base)
        self.remove_btn.setEnabled(False)
        toolbar_layout.addWidget(self.remove_btn)
        
        self.edit_btn = QPushButton("Edit / 编辑")
        self.edit_btn.clicked.connect(self.edit_selected_knowledge_base)
        self.edit_btn.setEnabled(False)
        toolbar_layout.addWidget(self.edit_btn)
        
        toolbar_layout.addStretch()
        layout.addLayout(toolbar_layout)
        
        # 知识库表格
        self.kb_table = QTableWidget()
        self.kb_table.setColumnCount(6)
        self.kb_table.setHorizontalHeaderLabels([
            self.tr("name"), self.tr("description"), self.tr("file_path"),
            self.tr("records"), self.tr("status"), self.tr("updated")
        ])
        
        # 设置表格属性
        header = self.kb_table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        
        self.kb_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.kb_table.setAlternatingRowColors(True)
        self.kb_table.itemSelectionChanged.connect(self.on_kb_selection_changed)
        
        layout.addWidget(self.kb_table)
        
        self.tab_widget.addTab(kb_widget, self.tr("tab_list"))
    
    def setup_add_knowledge_base_tab(self):
        """设置添加知识库标签页 / Setup add knowledge base tab."""
        add_widget = QtWidgets.QWidget()
        layout = QVBoxLayout(add_widget)
        
        # 文件选择组
        file_group = QGroupBox(self.tr("file_selection"))
        file_layout = QFormLayout(file_group)

        self.file_path_edit = QLineEdit()
        self.file_path_edit.setReadOnly(True)
        file_browse_btn = QPushButton(self.tr("browse"))
        file_browse_btn.clicked.connect(self.browse_excel_file)

        file_path_layout = QHBoxLayout()
        file_path_layout.addWidget(self.file_path_edit)
        file_path_layout.addWidget(file_browse_btn)

        file_layout.addRow(self.tr("file_path") + ":", file_path_layout)
        layout.addWidget(file_group)
        
        # 知识库信息组
        info_group = QGroupBox(self.tr("kb_info"))
        info_layout = QFormLayout(info_group)

        self.kb_name_edit = QLineEdit()
        self.kb_description_edit = QTextEdit()
        self.kb_description_edit.setMaximumHeight(80)

        info_layout.addRow(self.tr("kb_name") + ":", self.kb_name_edit)
        info_layout.addRow(self.tr("kb_description") + ":", self.kb_description_edit)
        layout.addWidget(info_group)
        
        # 预览组
        preview_group = QGroupBox(self.tr("file_preview"))
        preview_layout = QVBoxLayout(preview_group)

        self.preview_btn = QPushButton(self.tr("preview_file"))
        self.preview_btn.clicked.connect(self.preview_excel_file)
        self.preview_btn.setEnabled(False)
        preview_layout.addWidget(self.preview_btn)
        
        self.preview_text = QTextEdit()
        self.preview_text.setMaximumHeight(150)
        self.preview_text.setReadOnly(True)
        preview_layout.addWidget(self.preview_text)
        
        layout.addWidget(preview_group)
        
        # 按钮组
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        self.add_kb_btn = QPushButton(self.tr("add_kb"))
        self.add_kb_btn.clicked.connect(self.add_knowledge_base)
        self.add_kb_btn.setEnabled(False)
        button_layout.addWidget(self.add_kb_btn)

        self.clear_btn = QPushButton(self.tr("clear"))
        self.clear_btn.clicked.connect(self.clear_add_form)
        button_layout.addWidget(self.clear_btn)

        layout.addLayout(button_layout)
        layout.addStretch()

        self.tab_widget.addTab(add_widget, self.tr("tab_add"))
    
    def setup_search_test_tab(self):
        """设置搜索测试标签页 / Setup search test tab."""
        search_widget = QtWidgets.QWidget()
        layout = QVBoxLayout(search_widget)
        
        # 搜索输入
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel(self.tr("search_query") + ":"))

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText(self.tr("search_placeholder"))
        search_layout.addWidget(self.search_edit)

        self.search_btn = QPushButton(self.tr("search"))
        self.search_btn.clicked.connect(self.search_knowledge_base)
        search_layout.addWidget(self.search_btn)

        layout.addLayout(search_layout)

        # 搜索结果
        self.search_results = QTextEdit()
        self.search_results.setReadOnly(True)
        layout.addWidget(self.search_results)

        self.tab_widget.addTab(search_widget, self.tr("tab_search"))
    
    def browse_excel_file(self):
        """浏览Excel文件 / Browse Excel file."""
        try:
            file_path, _ = QFileDialog.getOpenFileName(
                self.parent,
                "Select Excel File / 选择Excel文件",
                "",
                "Excel Files (*.xlsx *.xls *.csv);;All Files (*)"
            )

            if file_path:
                self.file_path_edit.setText(file_path)
                self.preview_btn.setEnabled(True)

                # 自动生成知识库名称
                if not self.kb_name_edit.text():
                    file_name = Path(file_path).stem
                    self.kb_name_edit.setText(file_name)

                self.update_add_button_state()
        except Exception as e:
            print(f"Error in browse_excel_file: {e}")
            if hasattr(self, 'parent') and self.parent:
                QMessageBox.critical(self.parent, self.tr("error"), f"Failed to browse file: {str(e)}")
    
    def preview_excel_file(self):
        """预览Excel文件 / Preview Excel file."""
        file_path = self.file_path_edit.text()
        if not file_path:
            return
        
        try:
            preview_data = self.excel_reader.preview_file(file_path, max_rows=5)
            
            if 'error' in preview_data:
                self.preview_text.setText(f"Error: {preview_data['error']}")
                return
            
            # 格式化预览文本
            preview_text = f"File: {preview_data['metadata']['file_path']}\n"
            preview_text += f"Size: {preview_data['metadata']['file_size']} bytes\n"
            preview_text += f"Sheets: {preview_data['metadata']['sheet_count']}\n\n"
            
            for sheet_name, sheet_data in preview_data['sheets'].items():
                preview_text += f"Sheet: {sheet_name}\n"
                preview_text += f"Columns: {', '.join(sheet_data['columns'])}\n"
                preview_text += f"Total Rows: {sheet_data['total_rows']}\n"
                preview_text += f"Preview (first 5 rows):\n"
                
                for i, row in enumerate(sheet_data['data']):
                    preview_text += f"  Row {i+1}: {str(row)[:100]}...\n"
                
                preview_text += "\n"
            
            self.preview_text.setText(preview_text)
            
        except Exception as e:
            self.preview_text.setText(f"Error previewing file: {str(e)}")
    
    def update_add_button_state(self):
        """更新添加按钮状态 / Update add button state."""
        file_path = self.file_path_edit.text()
        kb_name = self.kb_name_edit.text().strip()
        
        self.add_kb_btn.setEnabled(bool(file_path and kb_name))

    def add_knowledge_base(self):
        """添加知识库 / Add knowledge base."""
        file_path = self.file_path_edit.text()
        kb_name = self.kb_name_edit.text().strip()
        description = self.kb_description_edit.toPlainText().strip()

        if not file_path or not kb_name:
            QMessageBox.warning(self.parent, self.tr("warning"), self.tr("provide_file_and_name"))
            return

        # 检查依赖
        deps = self.excel_reader.check_dependencies()
        if not all(deps.values()):
            # 显示依赖安装提示，不尝试自动安装
            QMessageBox.information(
                self.parent, self.tr("missing_deps"),
                self.tr("missing_deps_msg")
            )
            return

        # 添加知识库
        result = self.knowledge_manager.add_knowledge_base(kb_name, file_path, description)

        if result['success']:
            QMessageBox.information(self.parent, self.tr("success"), result['message'])
            self.clear_add_form()
            self.refresh_knowledge_bases()
            self.tab_widget.setCurrentIndex(0)  # 切换到知识库列表
        else:
            QMessageBox.critical(self.parent, self.tr("error"), result['error'])

    def clear_add_form(self):
        """清空添加表单 / Clear add form."""
        self.file_path_edit.clear()
        self.kb_name_edit.clear()
        self.kb_description_edit.clear()
        self.preview_text.clear()
        self.preview_btn.setEnabled(False)
        self.add_kb_btn.setEnabled(False)

    def refresh_knowledge_bases(self):
        """刷新知识库列表 / Refresh knowledge base list."""
        kb_list = self.knowledge_manager.list_knowledge_bases()

        self.kb_table.setRowCount(len(kb_list))

        for row, kb_info in enumerate(kb_list):
            # 名称
            name_item = QTableWidgetItem(kb_info['name'])
            self.kb_table.setItem(row, 0, name_item)

            # 描述
            desc_item = QTableWidgetItem(kb_info['description'][:50] + "..." if len(kb_info['description']) > 50 else kb_info['description'])
            self.kb_table.setItem(row, 1, desc_item)

            # 文件路径
            path_item = QTableWidgetItem(kb_info['file_path'])
            self.kb_table.setItem(row, 2, path_item)

            # 记录数
            records_item = QTableWidgetItem(str(kb_info['total_records']))
            self.kb_table.setItem(row, 3, records_item)

            # 状态
            status = self.tr("enabled") if kb_info['enabled'] else self.tr("disabled")
            status_item = QTableWidgetItem(status)
            self.kb_table.setItem(row, 4, status_item)

            # 更新时间
            updated_item = QTableWidgetItem(kb_info['updated_at'][:19] if kb_info['updated_at'] else "")
            self.kb_table.setItem(row, 5, updated_item)

    def on_kb_selection_changed(self):
        """知识库选择改变 / Knowledge base selection changed."""
        selected_rows = set(item.row() for item in self.kb_table.selectedItems())
        has_selection = len(selected_rows) > 0

        self.remove_btn.setEnabled(has_selection)
        self.edit_btn.setEnabled(len(selected_rows) == 1)

    def remove_selected_knowledge_base(self):
        """删除选中的知识库 / Remove selected knowledge base."""
        selected_rows = set(item.row() for item in self.kb_table.selectedItems())

        if not selected_rows:
            return

        # 获取选中的知识库名称
        kb_names = []
        for row in selected_rows:
            name_item = self.kb_table.item(row, 0)
            if name_item:
                kb_names.append(name_item.text())

        if not kb_names:
            return

        # 确认删除
        reply = QMessageBox.question(
            self.parent, self.tr("confirm_removal"),
            self.tr("confirm_removal_msg", len(kb_names)),
            QMessageBox.Yes | QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            for kb_name in kb_names:
                result = self.knowledge_manager.remove_knowledge_base(kb_name)
                if not result['success']:
                    QMessageBox.warning(self.parent, self.tr("warning"), self.tr("remove_failed", kb_name, result['error']))

            self.refresh_knowledge_bases()

    def edit_selected_knowledge_base(self):
        """编辑选中的知识库 / Edit selected knowledge base."""
        selected_rows = set(item.row() for item in self.kb_table.selectedItems())

        if len(selected_rows) != 1:
            return

        row = list(selected_rows)[0]
        name_item = self.kb_table.item(row, 0)

        if not name_item:
            return

        kb_name = name_item.text()
        kb_info = self.knowledge_manager.get_knowledge_base_info(kb_name)

        if not kb_info:
            QMessageBox.warning(self.parent, self.tr("warning"), f"Knowledge base '{kb_name}' not found.")
            return

        # 打开编辑对话框
        dialog = KnowledgeBaseEditDialog(kb_name, kb_info, self.knowledge_manager, self.parent)
        if dialog.exec_() == QDialog.Accepted:
            self.refresh_knowledge_bases()

    def search_knowledge_base(self):
        """搜索知识库 / Search knowledge base."""
        query = self.search_edit.text().strip()

        if not query:
            self.search_results.setText(self.tr("enter_search_query"))
            return

        try:
            results = self.knowledge_manager.search_knowledge(query, max_results=10)

            if not results:
                self.search_results.setText(self.tr("no_results"))
                return

            # 格式化搜索结果
            result_text = self.tr("search_results_for", query) + "\n"
            result_text += "=" * 50 + "\n\n"

            for i, result in enumerate(results, 1):
                result_text += f"{i}. {result['title']}\n"
                result_text += f"   {self.tr('kb_label')} {result['kb_name']}\n"
                result_text += f"   {self.tr('sheet_label')} {result['sheet_name']}\n"
                result_text += f"   {self.tr('content_label')} {result['content'][:200]}...\n"
                result_text += f"   {self.tr('category_label')} {result.get('category', 'N/A')}\n"
                result_text += f"   {self.tr('relevance_label')} {result['relevance_score']:.2f}\n"
                result_text += "-" * 30 + "\n\n"

            self.search_results.setText(result_text)

        except Exception as e:
            self.search_results.setText(self.tr("search_error", str(e)))


class KnowledgeBaseEditDialog(QDialog):
    """知识库编辑对话框 / Knowledge base edit dialog."""

    def __init__(self, kb_name: str, kb_info: Dict[str, Any],
                 knowledge_manager: KnowledgeManager, parent=None):
        super().__init__(parent)
        self.kb_name = kb_name
        self.kb_info = kb_info
        self.knowledge_manager = knowledge_manager

        # 简单的本地化支持
        self.strings = {
            "error": "Error" if hasattr(knowledge_manager, 'config_manager') and
                     knowledge_manager.config_manager and
                     knowledge_manager.config_manager.language == "en_US" else "错误"
        }

        self.setWindowTitle(f"Edit Knowledge Base: {kb_name}")
        self.setMinimumSize(400, 300)

        self.setup_ui()
        self.load_data()

    def tr(self, key):
        """简单翻译方法 / Simple translation method."""
        return self.strings.get(key, key)

    def setup_ui(self):
        """设置用户界面 / Setup user interface."""
        layout = QVBoxLayout(self)

        # 表单
        form_layout = QFormLayout()

        self.description_edit = QTextEdit()
        self.description_edit.setMaximumHeight(100)
        form_layout.addRow("Description / 描述:", self.description_edit)

        self.enabled_checkbox = QCheckBox("Enabled / 启用")
        form_layout.addRow("Status / 状态:", self.enabled_checkbox)

        self.file_path_edit = QLineEdit()
        self.file_path_edit.setReadOnly(True)

        file_layout = QHBoxLayout()
        file_layout.addWidget(self.file_path_edit)

        browse_btn = QPushButton("Browse / 浏览")
        browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(browse_btn)

        form_layout.addRow("File Path / 文件路径:", file_layout)

        layout.addLayout(form_layout)

        # 按钮
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def load_data(self):
        """加载数据 / Load data."""
        self.description_edit.setPlainText(self.kb_info.get('description', ''))
        self.enabled_checkbox.setChecked(self.kb_info.get('enabled', True))
        self.file_path_edit.setText(self.kb_info.get('file_path', ''))

    def browse_file(self):
        """浏览文件 / Browse file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Excel File / 选择Excel文件",
            self.file_path_edit.text(),
            "Excel Files (*.xlsx *.xls *.csv);;All Files (*)"
        )

        if file_path:
            self.file_path_edit.setText(file_path)

    def accept(self):
        """接受更改 / Accept changes."""
        try:
            # 更新知识库
            result = self.knowledge_manager.update_knowledge_base(
                self.kb_name,
                description=self.description_edit.toPlainText().strip(),
                enabled=self.enabled_checkbox.isChecked(),
                file_path=self.file_path_edit.text()
            )

            if result['success']:
                super().accept()
            else:
                QMessageBox.critical(self, self.tr("error"), result['error'])

        except Exception as e:
            QMessageBox.critical(self, self.tr("error"), str(e))
