from __future__ import annotations

"""FlatteningResultView - 结果表格窗口
FlatteningResultView - Result Table Window
"""

import idaapi
from PyQt5 import QtWidgets, QtCore
import os
from pathlib import Path

from .flattening_detector import _CACHE_DIR

class FlatteningResultView(idaapi.PluginForm):
    """使用 QTableWidget 显示函数地址 / 分数，可排序筛选。
    Display function address/score using QTableWidget, sortable and filterable.
    """

    def __init__(self, items: list[tuple[int, float]]):
        super().__init__()
        self._items = items
        self._min_score = 0.0
        self._max_score = 1.0

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
        self.min_edit = QtWidgets.QDoubleSpinBox()
        self.min_edit.setRange(0.0, 1.0)
        self.min_edit.setSingleStep(0.1)
        self.min_edit.setValue(self._min_score)
        self.max_edit = QtWidgets.QDoubleSpinBox()
        self.max_edit.setRange(0.0, 1.0)
        self.max_edit.setSingleStep(0.1)
        self.max_edit.setValue(self._max_score)
        apply_btn = QtWidgets.QPushButton("筛选")
        cache_btn = QtWidgets.QPushButton("缓存管理")
        cache_btn.clicked.connect(self._open_cache_manager)
        filter_layout.addWidget(QtWidgets.QLabel("分数区间:"))
        filter_layout.addWidget(self.min_edit)
        filter_layout.addWidget(QtWidgets.QLabel("-"))
        filter_layout.addWidget(self.max_edit)
        filter_layout.addWidget(apply_btn)
        filter_layout.addWidget(cache_btn)

        layout.addLayout(filter_layout)

        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Score", "Address", "Name"])
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.table.cellDoubleClicked.connect(self._on_cell_double_clicked)
        layout.addWidget(self.table)

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
        return idaapi.PluginForm.Show(self, "NexusAI - CFF 检测结果", options=persist_flag)

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
        self.setWindowTitle("NexusAI 缓存管理")
        self.resize(500, 300)
        vbox = QtWidgets.QVBoxLayout(self)

        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["文件名", "大小 KB", "修改时间"])
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        vbox.addWidget(self.table)

        btn_layout = QtWidgets.QHBoxLayout()
        del_btn = QtWidgets.QPushButton("删除选中")
        del_btn.clicked.connect(self._delete_selected)
        close_btn = QtWidgets.QPushButton("关闭")
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(del_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(close_btn)
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