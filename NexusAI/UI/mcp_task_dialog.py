"""
MCP Task Management Dialog for NexusAI
NexusAI的MCP任务管理对话框

Provides a comprehensive task management interface for MCP analysis tasks.
为MCP分析任务提供全面的任务管理界面。
"""

import json
from datetime import datetime
from typing import Optional, Dict, Any, List
from NexusAI.Config.config import ConfigManager  # type: ignore

# ---------------- 多语言文本 ----------------
_TEXTS = {
    "zh_CN": {
        "status_map": {
            "pending": "待处理",
            "running": "进行中",
            "done": "已完成",
            "error": "错误",
            "cancelled": "已取消",
        },
        "task_id": "任务ID",
        "theme": "主题",
        "status": "状态",
        "created": "创建时间",
        "updated": "更新时间",
        "iterations": "迭代次数",
        "error": "错误信息",
    },
    "en_US": {
        "status_map": {
            "pending": "Pending",
            "running": "Running",
            "done": "Done",
            "error": "Error",
            "cancelled": "Cancelled",
        },
        "task_id": "Task ID",
        "theme": "Theme",
        "status": "Status",
        "created": "Created",
        "updated": "Updated",
        "iterations": "Iterations",
        "error": "Error Message",
    },
}


def _t(key: str):
    lang = ConfigManager().language
    return _TEXTS.get(lang, _TEXTS["zh_CN"]).get(key, key)

def _status_text(status: str):
    lang = ConfigManager().language
    return _TEXTS.get(lang, _TEXTS["zh_CN"])["status_map"].get(status, status)

try:
    from PyQt5 import QtWidgets, QtCore, QtGui
    from PyQt5.QtWidgets import (
        QDialog, QVBoxLayout, QHBoxLayout, QListWidget, QListWidgetItem,
        QPushButton, QLabel, QTextBrowser, QLineEdit, QComboBox,
        QSplitter, QGroupBox, QMessageBox, QProgressBar
    )
    from PyQt5.QtCore import Qt, QTimer
    from PyQt5.QtGui import QFont
    QT_AVAILABLE = True
except ImportError:
    try:
        from PySide2 import QtWidgets, QtCore, QtGui
        from PySide2.QtWidgets import (
            QDialog, QVBoxLayout, QHBoxLayout, QListWidget, QListWidgetItem,
            QPushButton, QLabel, QTextBrowser, QLineEdit, QComboBox,
            QSplitter, QGroupBox, QMessageBox, QProgressBar
        )
        from PySide2.QtCore import Qt, QTimer
        from PySide2.QtGui import QFont
        QT_AVAILABLE = True
    except ImportError:
        QT_AVAILABLE = False

if QT_AVAILABLE:
    from ..Utils.mcp_task_manager import get_task_manager, MCPTaskRecord


class MCPTaskDialog(QDialog):
    """MCP历史管理对话框 / MCP History Management Dialog."""

    def __init__(self, parent, config_manager, mcp_controller):
        """初始化对话框 / Initialize dialog."""
        if not QT_AVAILABLE:
            raise ImportError("Qt framework is not available")

        super().__init__(parent)
        self.config_manager = config_manager
        self.mcp_controller = mcp_controller

        # 构建配置目录路径
        from pathlib import Path
        config_dir = Path(config_manager.script_dir) / "Config"
        self.task_manager = get_task_manager(config_dir)

        self.setWindowTitle("MCP历史管理器 / MCP History Manager")
        # 监听语言切换事件
        from ..Core.event_bus import get_event_bus as _evb
        _evb().on("language_changed", self._update_language_texts)
        self.setModal(False)
        
        # 设置对话框大小和限制
        dlg_sizes = config_manager.config.setdefault("dialog_sizes", {})
        w, h = dlg_sizes.get("mcp_task_dialog", (1000, 700))

        # 设置最小和最大尺寸，防止窗口过小或过大
        self.setMinimumSize(800, 500)
        self.setMaximumSize(1600, 1200)

        # 确保尺寸在合理范围内
        w = max(800, min(1600, w))
        h = max(500, min(1200, h))
        self.resize(w, h)
        
        self.current_task_id = None
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self._refresh_current_task)
        self.refresh_timer.start(2000)  # 每2秒刷新一次
        
        self.setup_ui()
        self._refresh_task_list()
        self._update_language_texts()
    
    def setup_ui(self):
        """设置用户界面 / Setup user interface."""
        main_layout = QHBoxLayout(self)
        
        # 创建分割器
        splitter = QSplitter(Qt.Horizontal)
        main_layout.addWidget(splitter)
        
        # 左侧：任务列表
        left_widget = self._create_task_list_widget()
        splitter.addWidget(left_widget)
        
        # 右侧：任务详情
        right_widget = self._create_task_detail_widget()
        splitter.addWidget(right_widget)
        
        # 设置分割器比例
        splitter.setSizes([300, 700])
    
    def _create_task_list_widget(self):
        """创建任务列表部件 / Create task list widget."""
        widget = QtWidgets.QWidget()
        layout = QVBoxLayout(widget)
        
        # 标题
        self.title_label = QLabel()
        self.title_label.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(self.title_label)
        
        # 搜索框
        self.search_line = QLineEdit()
        self.search_line.setPlaceholderText("搜索任务... / Search tasks...")
        self.search_line.textChanged.connect(self._refresh_task_list)
        layout.addWidget(self.search_line)
        
        # 状态过滤器
        filter_layout = QHBoxLayout()
        self.status_label = QLabel()
        filter_layout.addWidget(self.status_label)
        
        self.status_filter = QComboBox()
        self.status_filter.currentTextChanged.connect(self._refresh_task_list)
        filter_layout.addWidget(self.status_filter)
        
        layout.addLayout(filter_layout)
        
        # 任务列表
        self.task_list = QListWidget()
        self.task_list.itemSelectionChanged.connect(self._on_task_selection_changed)
        layout.addWidget(self.task_list)
        
        # 按钮组
        button_layout = QHBoxLayout()
        
        self.continue_btn = QPushButton()
        self.continue_btn.clicked.connect(self._on_continue_task)
        self.continue_btn.setEnabled(False)
        button_layout.addWidget(self.continue_btn)
        
        self.delete_btn = QPushButton()
        self.delete_btn.clicked.connect(self._on_delete_task)
        self.delete_btn.setEnabled(False)
        button_layout.addWidget(self.delete_btn)
        
        self.refresh_btn = QPushButton()
        self.refresh_btn.clicked.connect(self._refresh_task_list)
        button_layout.addWidget(self.refresh_btn)
        
        layout.addLayout(button_layout)
        
        return widget
    
    def _create_task_detail_widget(self):
        """创建任务详情部件 / Create task detail widget."""
        widget = QtWidgets.QWidget()
        layout = QVBoxLayout(widget)
        
        # 任务信息组
        self.info_group = QGroupBox()
        info_layout = QVBoxLayout(self.info_group)
        
        self.task_info_label = QLabel()
        info_layout.addWidget(self.task_info_label)

        # 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        # 对话历史
        self.history_group = QGroupBox()
        history_layout = QVBoxLayout(self.history_group)

        self.conversation_browser = QTextBrowser()
        self.conversation_browser.setFont(QFont("Consolas", 9))

        # 设置文本换行和宽度限制
        self.conversation_browser.setLineWrapMode(QTextBrowser.WidgetWidth)  # 按窗口宽度换行
        self.conversation_browser.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)  # 需要时显示水平滚动条
        self.conversation_browser.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)    # 需要时显示垂直滚动条

        # 设置最小和最大宽度，防止窗口被撑得太宽
        self.conversation_browser.setMinimumWidth(300)
        self.conversation_browser.setMaximumWidth(800)

        history_layout.addWidget(self.conversation_browser)
        
        # 添加到主布局
        layout.addWidget(self.info_group)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.history_group, 1)
        
        return widget
    
    def _refresh_task_list(self):
        """刷新任务列表 / Refresh task list."""
        if not self.task_manager:
            return
        
        search_text = self.search_line.text().strip().lower()
        status_filter = self.status_filter.currentText()
        
        # 获取任务列表
        if status_filter == "全部":
            tasks = self.task_manager.list_tasks()
        else:
            status_map = {
                "进行中": "running",
                "错误": "error", 
                "已完成": "done",
                "已取消": "cancelled"
            }
            filter_status = status_map.get(status_filter)
            tasks = self.task_manager.list_tasks(filter_status)
        
        # 应用搜索过滤
        if search_text:
            tasks = [task for task in tasks 
                    if search_text in task.display_name.lower() or 
                       search_text in task.theme.lower()]
        
        # 更新列表
        self.task_list.clear()
        for task in tasks:
            item_text = self._format_task_item(task)
            item = QListWidgetItem(item_text)
            item.setData(Qt.UserRole, task.id)
            
            # 设置状态颜色
            if task.status == "running":
                item.setBackground(QtGui.QColor(200, 255, 200))  # 浅绿色
            elif task.status == "error":
                item.setBackground(QtGui.QColor(255, 200, 200))  # 浅红色
            elif task.status == "done":
                item.setBackground(QtGui.QColor(220, 220, 220))  # 浅灰色
            
            self.task_list.addItem(item)
    
    def _format_task_item(self, task: MCPTaskRecord) -> str:
        """格式化任务列表项 / Format task list item."""
        status_text = _status_text(task.status)
        created_time = datetime.fromisoformat(task.created_at).strftime("%m-%d %H:%M")
        return f"[{status_text}] {task.display_name}\n{created_time} | {_t('iterations')}: {task.iterations}"
    
    def _on_task_selection_changed(self):
        """任务选择变化处理 / Handle task selection change."""
        selected_items = self.task_list.selectedItems()
        if not selected_items:
            self.current_task_id = None
            self._clear_task_detail()
            return
        
        task_id = selected_items[0].data(Qt.UserRole)
        self.current_task_id = task_id
        self._update_task_detail(task_id)
    
    def _update_task_detail(self, task_id: str):
        """更新任务详情 / Update task detail."""
        task = self.task_manager.get_task(task_id)
        if not task:
            self._clear_task_detail()
            return
        
        # 更新任务信息
        info_text = (
            f"{_t('task_id')}: {task.id}\n"
            f"{_t('theme')}: {task.theme}\n"
            f"{_t('status')}: {_status_text(task.status)}\n"
            f"{_t('created')}: {task.created_at}\n"
            f"{_t('updated')}: {task.updated_at}\n"
            f"{_t('iterations')}: {task.iterations} / {task.max_iterations}"
        )
        if task.error_message:
            info_text += f"\n{_t('error')}: {task.error_message}"
        
        self.task_info_label.setText(info_text)

        # 更新按钮状态
        can_continue = task.status in ["error", "running"]
        self.continue_btn.setEnabled(can_continue)
        self.delete_btn.setEnabled(True)
        
        # 显示进度条（如果任务正在运行）
        if task.status == "running":
            self.progress_bar.setVisible(True)
            if task.max_iterations > 0:
                progress = min(100, int(task.iterations * 100 / task.max_iterations))
                self.progress_bar.setValue(progress)
            else:
                self.progress_bar.setRange(0, 0)  # 无限进度条
        else:
            self.progress_bar.setVisible(False)
        
        # 更新对话历史
        self._update_conversation_history(task)
    
    def _update_conversation_history(self, task: MCPTaskRecord):
        """更新对话历史 / Update conversation history."""
        if not task.conversation_history:
            self.conversation_browser.setHtml("<p>暂无对话历史</p>")
            return

        # CSS样式，确保文本正确换行
        css_style = """
        <style>
        body {
            font-family: Consolas, monospace;
            font-size: 9pt;
            margin: 5px;
            word-wrap: break-word;
            overflow-wrap: break-word;
        }
        .entry {
            margin: 8px 0;
            padding: 5px;
            border-left: 3px solid #ccc;
            word-wrap: break-word;
            overflow-wrap: break-word;
            max-width: 100%;
        }
        .user-input { border-left-color: #007acc; color: #007acc; }
        .ai-response { border-left-color: #28a745; color: #28a745; }
        .action-result { border-left-color: #6f42c1; color: #6f42c1; }
        .error { border-left-color: #dc3545; color: #dc3545; }
        .system { border-left-color: #6c757d; color: #6c757d; }
        .timestamp { font-weight: bold; margin-bottom: 3px; }
        .content {
            margin-top: 3px;
            white-space: pre-wrap;
            word-wrap: break-word;
            overflow-wrap: break-word;
            max-width: 100%;
        }
        pre {
            white-space: pre-wrap;
            word-wrap: break-word;
            overflow-wrap: break-word;
            max-width: 100%;
            margin: 0;
            font-family: inherit;
        }
        </style>
        """

        html_parts = [css_style]
        for entry in task.conversation_history:
            timestamp = datetime.fromisoformat(entry["timestamp"]).strftime("%H:%M:%S")
            entry_type = entry["type"]
            content = self._escape_html(entry["content"])

            # 根据类型设置样式类
            type_class_map = {
                "user_input": "user-input",
                "ai_response": "ai-response",
                "action_result": "action-result",
                "error": "error",
                "system": "system"
            }

            css_class = type_class_map.get(entry_type, "system")
            type_name_map = {
                "user_input": "用户输入",
                "ai_response": "AI回复",
                "action_result": "动作结果",
                "error": "错误",
                "system": "系统"
            }
            type_name = type_name_map.get(entry_type, "未知")

            html_parts.append(f'''
            <div class="entry {css_class}">
                <div class="timestamp">[{timestamp}] {type_name}:</div>
                <div class="content">{content}</div>
            </div>
            ''')

        html_content = "<html><head>" + css_style + "</head><body>" + "".join(html_parts) + "</body></html>"
        self.conversation_browser.setHtml(html_content)

        # 滚动到底部
        scrollbar = self.conversation_browser.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def _escape_html(self, text: str) -> str:
        """转义HTML特殊字符 / Escape HTML special characters."""
        if not text:
            return ""

        # 基本HTML转义
        text = text.replace("&", "&amp;")
        text = text.replace("<", "&lt;")
        text = text.replace(">", "&gt;")
        text = text.replace('"', "&quot;")
        text = text.replace("'", "&#x27;")

        return text
    
    def _clear_task_detail(self):
        """清空任务详情 / Clear task detail."""
        self.task_info_label.setText("请选择一个任务 / Please select a task")
        self.conversation_browser.clear()
        self.continue_btn.setEnabled(False)
        self.delete_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
    
    def _refresh_current_task(self):
        """刷新当前任务（定时器调用） / Refresh current task (called by timer)."""
        if self.current_task_id:
            self._update_task_detail(self.current_task_id)
    
    def _on_continue_task(self):
        """继续任务处理 / Handle continue task."""
        if not self.current_task_id:
            return
        
        task = self.task_manager.get_task(self.current_task_id)
        if not task:
            QMessageBox.warning(self, "警告", "任务不存在")
            return
        
        # 获取对话上下文
        context = self.task_manager.get_task_conversation_context(self.current_task_id)
        
        # 继续任务
        try:
            self.mcp_controller.continue_task(self.current_task_id, task.theme, context)
            QMessageBox.information(self, "信息", "任务已继续执行")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"继续任务失败: {str(e)}")
    
    def _on_delete_task(self):
        """删除任务处理 / Handle delete task."""
        if not self.current_task_id:
            return
        
        reply = QMessageBox.question(self, "确认删除", "确定要删除这个任务吗？", 
                                   QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            if self.task_manager.delete_task(self.current_task_id):
                self.current_task_id = None
                self._refresh_task_list()
                self._clear_task_detail()
                QMessageBox.information(self, "信息", "任务已删除")
    

    def closeEvent(self, event):
        """关闭事件处理 / Handle close event."""
        # 保存对话框大小
        self.config_manager.config.setdefault("dialog_sizes", {})["mcp_task_dialog"] = (self.width(), self.height())
        self.config_manager.save_config()
        
        # 停止定时器
        if self.refresh_timer.isActive():
            self.refresh_timer.stop()

        super().closeEvent(event)

    # ----------------------------------------------
    #  语言切换处理
    # ----------------------------------------------
    def _update_language_texts(self, *_):
        """根据当前语言刷新对话框静态文本 / Refresh texts when language changes."""
        lang = self.config_manager.language
        if lang == "en_US":
            self.setWindowTitle("MCP History Manager")
            self.title_label.setText("Task List")
            self.status_label.setText("Status:")
            self.status_filter.blockSignals(True)
            self.status_filter.clear()
            self.status_filter.addItems(["All", "Running", "Error", "Done", "Cancelled"])
            self.status_filter.blockSignals(False)
            self.continue_btn.setText("Continue")
            self.delete_btn.setText("Delete")
            self.refresh_btn.setText("Refresh")
            self.info_group.setTitle("Task Information")
            self.history_group.setTitle("Conversation History")
            self.task_info_label.setText("Please select a task")
            status_map = {"running":"Running","error":"Error","done":"Done","cancelled":"Cancelled"}
        else:
            self.setWindowTitle("MCP历史管理器")
            self.title_label.setText("任务列表")
            self.status_label.setText("状态过滤:")
            self.status_filter.blockSignals(True)
            self.status_filter.clear()
            self.status_filter.addItems(["全部", "进行中", "错误", "已完成", "已取消"])
            self.status_filter.blockSignals(False)
            self.continue_btn.setText("继续")
            self.delete_btn.setText("删除")
            self.refresh_btn.setText("刷新")
            self.info_group.setTitle("任务信息")
            self.history_group.setTitle("对话历史")
            self.task_info_label.setText("请选择一个任务")
         
        # 刷新列表
        self._refresh_task_list()


# Qt不可用时的备用处理
if not QT_AVAILABLE:
    class MCPTaskDialog:
        """Qt不可用时的备用MCP任务管理对话框 / Fallback MCP Task Management Dialog when Qt is not available."""

        def __init__(self, parent, config_manager, mcp_controller):
            """初始化备用对话框 / Initialize fallback dialog."""
            raise ImportError("Qt framework is not available. Cannot create MCP Task Dialog.")
