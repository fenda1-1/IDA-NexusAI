from __future__ import annotations

"""FlatteningResultView - 结果表格窗口
FlatteningResultView - Result Table Window
"""

import idaapi
from PyQt5 import QtWidgets, QtCore
from NexusAI.Config.config import ConfigManager  # type: ignore
from NexusAI.Core.event_bus import get_event_bus  # type: ignore
import os
from pathlib import Path

from .flattening_detector import _CACHE_DIR

# ---------------------------------------------------------------------------
# 多语言支持
# ---------------------------------------------------------------------------

_TEXTS = {
    "zh_CN": {
        "window_title": "NexusAI - CFF 检测结果",
        "score_range": "分数区间:",
        "filter": "筛选",
        "cache_mgr": "缓存管理",
        "score": "分数",
        "address": "地址",
        "name": "名称",
        "cache_window": "NexusAI 缓存管理",
        "file": "文件名",
        "size": "大小 KB",
        "mtime": "修改时间",
        "delete": "删除选中",
        "close": "关闭",
    },
    "en_US": {
        "window_title": "NexusAI - CFF Detection Results",
        "score_range": "Score Range:",
        "filter": "Filter",
        "cache_mgr": "Cache Manager",
        "score": "Score",
        "address": "Address",
        "name": "Name",
        "cache_window": "NexusAI Cache Manager",
        "file": "File",
        "size": "Size KB",
        "mtime": "Modified",
        "delete": "Delete Selected",
        "close": "Close",
    },
}


def _t(key: str) -> str:
    lang = ConfigManager().language
    return _TEXTS.get(lang, _TEXTS["zh_CN"])[key]


class FlatteningResultView(idaapi.PluginForm):
    """使用 QTableWidget 显示函数地址 / 分数，可排序筛选。
    Display function address/score using QTableWidget, sortable and filterable.
    """

    def __init__(self, items: list[tuple[int, float]]):
        super().__init__()
        self._items = items
        self._min_score = 0.0
        self._max_score = 1.0

        # 监听语言切换事件
        get_event_bus().on("language_changed", self._update_language_texts)

    def OnCreate(self, form):  # noqa: N802
        """创建窗口时调用 - Called when the window is created"""
        self.parent = self.FormToPyQtWidget(form)
        self._build_ui()
        self._populate()

    def _build_ui(self):
        """构建UI界面 - Build the UI interface"""
        layout = QtWidgets.QVBoxLayout()
        self.parent.setLayout(layout)

        filter_layout = QtWidgets.QHBoxLayout()
        self.min_label = QtWidgets.QLabel()
        self.min_edit = QtWidgets.QDoubleSpinBox()
        self.min_edit.setRange(0.0, 1.0)
        self.min_edit.setSingleStep(0.1)
        self.min_edit.setValue(self._min_score)
        self.max_edit = QtWidgets.QDoubleSpinBox()
        self.max_edit.setRange(0.0, 1.0)
        self.max_edit.setSingleStep(0.1)
        self.max_edit.setValue(self._max_score)
        self.apply_btn = QtWidgets.QPushButton()
        self.cache_btn = QtWidgets.QPushButton()
        self.cache_btn.clicked.connect(self._open_cache_manager)
        filter_layout.addWidget(self.min_label)
        filter_layout.addWidget(self.min_edit)
        filter_layout.addWidget(QtWidgets.QLabel("-"))
        filter_layout.addWidget(self.max_edit)
        filter_layout.addWidget(self.apply_btn)
        filter_layout.addWidget(self.cache_btn)

        layout.addLayout(filter_layout)

        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(3)
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.table.cellDoubleClicked.connect(self._on_cell_double_clicked)
        layout.addWidget(self.table)

        # 最后更新语言文本
        self._update_language_texts()

    def _apply_filter(self):
        """应用过滤器 - Apply the filter"""
        self._min_score = self.min_edit.value()
        self._max_score = self.max_edit.value()
        self._populate()

    def _populate(self):
        """填充表格数据 - Populate the table data"""
        rows = [it for it in self._items if self._min_score <= it[1] <= self._max_score]
        self.table.setRowCount(len(rows))
        for row, (ea, score) in enumerate(sorted(rows, key=lambda x: x[1], reverse=True)):
            self.table.setItem(row, 0, QtWidgets.QTableWidgetItem(f"{score:.2f}"))
            addr_item = QtWidgets.QTableWidgetItem(hex(ea))
            addr_item.setData(QtCore.Qt.UserRole, ea)
            self.table.setItem(row, 1, addr_item)

            full_name = idaapi.get_func_name(ea)
            display_name = full_name if len(full_name) <= 10 else full_name[:10] + "..."
            name_item = QtWidgets.QTableWidgetItem(display_name)
            if len(full_name) > 10:
                name_item.setToolTip(full_name)
            self.table.setItem(row, 2, name_item)

    def _on_cell_double_clicked(self, row: int, column: int):
        """双击单元格事件 - Double click cell event"""
        addr_item = self.table.item(row, 1)
        if not addr_item:
            return
        ea = addr_item.data(QtCore.Qt.UserRole)
        if ea:
            idaapi.jumpto(ea)

    def Show(self):  # noqa: N802
        """显示窗口 - Show the window"""
        persist_flag = getattr(idaapi.PluginForm, "WOPN_PERSIST", 0)
        return idaapi.PluginForm.Show(self, _t("window_title"), options=persist_flag)

    # ----------------------------------------------
    #  语言切换处理
    # ----------------------------------------------
    def _update_language_texts(self, *_):
        """根据当前语言刷新所有静态文本"""
        self.parent.setWindowTitle(_t("window_title"))
        self.min_label.setText(_t("score_range"))
        self.apply_btn.setText(_t("filter"))
        self.cache_btn.setText(_t("cache_mgr"))
        self.table.setHorizontalHeaderLabels([
            _t("score"), _t("address"), _t("name")
        ])

        # 若存在缓存管理对话框已打开，亦尝试刷新其文本


    def _open_cache_manager(self):
        """打开缓存管理器 - Open the cache manager"""
        dlg = _CacheManagerDialog(self.parent)
        dlg.exec_()


class _CacheManagerDialog(QtWidgets.QDialog):
    """显示/管理 flattening 缓存文件列表。
    Display/manage flattening cache file list.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        # 监听语言切换
        from NexusAI.Core.event_bus import get_event_bus as _evb
        _evb().on("language_changed", self._update_language_texts)
        self.setWindowTitle(_t("cache_window"))
        self.resize(500, 300)
        vbox = QtWidgets.QVBoxLayout(self)

        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels([
            _t("file"), _t("size"), _t("mtime")
        ])
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        vbox.addWidget(self.table)

        btn_layout = QtWidgets.QHBoxLayout()
        self.del_btn = QtWidgets.QPushButton()
        self.del_btn.clicked.connect(self._delete_selected)
        self.close_btn = QtWidgets.QPushButton()
        self.close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(self.del_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(self.close_btn)
        vbox.addLayout(btn_layout)

        self._populate()

    def _populate(self):
        files = list(Path(_CACHE_DIR).glob("*.json"))
        self.table.setRowCount(len(files))
        for row, fp in enumerate(sorted(files, key=lambda p: p.stat().st_mtime, reverse=True)):
            size_kb = fp.stat().st_size // 1024
            mtime = QtCore.QDateTime.fromSecsSinceEpoch(int(fp.stat().st_mtime)).toString("yyyy-MM-dd HH:mm:ss")
            name_item = QtWidgets.QTableWidgetItem(fp.name)
            name_item.setData(QtCore.Qt.UserRole, str(fp))
            self.table.setItem(row, 0, name_item)
            self.table.setItem(row, 1, QtWidgets.QTableWidgetItem(str(size_kb)))
            self.table.setItem(row, 2, QtWidgets.QTableWidgetItem(mtime))

    def _delete_selected(self):
        rows = set(i.row() for i in self.table.selectedIndexes())
        if not rows:
            return
        for row in sorted(rows, reverse=True):
            item = self.table.item(row, 0)
            if not item:
                continue
            path = Path(item.data(QtCore.Qt.UserRole))
            try:
                path.unlink(missing_ok=True)
            except Exception as e:  # pragma: no cover
                idaapi.msg(f"[NexusAI] 删除缓存失败: {e}\n")
            self.table.removeRow(row)

    def _update_language_texts(self, *_):
        self.setWindowTitle(_t("cache_window"))
        self.table.setHorizontalHeaderLabels([
            _t("file"), _t("size"), _t("mtime")
        ])
        self.del_btn.setText(_t("delete"))
        self.close_btn.setText(_t("close"))