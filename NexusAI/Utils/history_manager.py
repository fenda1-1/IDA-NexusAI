from __future__ import annotations

"""History management for NexusAI sessions.

This module provides a persistent chat history mechanism.  Each chat
session is stored as a standalone JSON file under the *History* folder
in the plugin root directory.  A typical JSON file looks like::

    {
      "name": "session_20250715_040245",
      "timestamp": "2025-07-15 04:02:45",
      "messages": [
        ["markdown", "### 欢迎使用 NexusAI！\n\n……"]
      ]
    }

The :class:`HistoryManager` is responsible for creating, loading,
renaming and deleting sessions, while :class:`PersistentHistory` is a
``list`` subclass that synchronises every modification to the
affiliated JSON file so that user interactions are recorded in real
time.
"""

from pathlib import Path
import datetime as _dt
import json
from typing import List, Tuple, Iterable, Optional

MessageTuple = Tuple[str, str]  # (method, text)


class _SafeJsonFile:
    """Small helper for atomic JSON writes."""

    @staticmethod
    def write(path: Path, data: dict) -> None:
        tmp_path = path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp_path.replace(path)

    @staticmethod
    def read(path: Path) -> dict:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}


class PersistentHistory(list):
    """Session-scoped, auto-persisting history list.

    It behaves exactly like a normal ``list`` but automatically updates
    the underlying JSON file whenever its content changes (``append``,
    ``extend``, ``clear`` etc.).
    """

    def __init__(self, file_path: Path, preload: bool = True):
        self._file_path = file_path
        # load existing messages if possible
        if preload and file_path.exists():
            data = _SafeJsonFile.read(file_path)
            msgs: Iterable[MessageTuple] = data.get("messages", [])  # type: ignore[arg-type]
            super().__init__(msgs)
        else:
            super().__init__()
        # Ensure metadata is present
        self._meta = {
            "name": file_path.stem,
            "timestamp": _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        # Persist immediately (covers freshly created empty session)
        self._flush()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _flush(self) -> None:
        """Write current list + metadata to disk atomically."""
        data = {
            **self._meta,
            "messages": list(self),
        }
        _SafeJsonFile.write(self._file_path, data)

    # ------------------------------------------------------------------
    # Overridden mutating methods
    # ------------------------------------------------------------------
    def append(self, item: MessageTuple) -> None:  # type: ignore[override]
        super().append(item)
        self._flush()

    def extend(self, iterable: Iterable[MessageTuple]) -> None:  # type: ignore[override]
        super().extend(iterable)
        self._flush()

    def clear(self) -> None:  # type: ignore[override]
        super().clear()
        self._flush()

    # Deleting by slice/index also persists
    def __delitem__(self, key):  # type: ignore[override]
        super().__delitem__(key)
        self._flush()

    def pop(self, *args):  # type: ignore[override]
        value = super().pop(*args)
        self._flush()
        return value


class HistoryManager:
    """Facade providing high-level history operations."""

    def __init__(self, plugin_root: Path):
        self._history_dir: Path = plugin_root / "History"
        self._history_dir.mkdir(exist_ok=True)
        self.current: Optional[PersistentHistory] = None

    # ------------------------------------------------------------------
    # Session helpers
    # ------------------------------------------------------------------
    def _session_file(self, name: str) -> Path:
        if not name.endswith(".json"):
            name += ".json"
        return self._history_dir / name

    def list_sessions(self) -> List[dict]:
        """Return metadata for all sessions sorted by mtime desc."""
        files = sorted(self._history_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        sessions: List[dict] = []
        for fp in files:
            data = _SafeJsonFile.read(fp)
            # 始终使用文件名作为 name 的权威来源，避免旧文件中残留旧 name
            data["name"] = fp.stem
            if data:
                sessions.append(data)
        return sessions

    def create_new_session(self) -> PersistentHistory:
        ts = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        name = f"session_{ts}"
        return self.load_session(name, create_if_missing=True)

    def load_session(self, name: str, *, create_if_missing: bool = False) -> PersistentHistory:
        file_path = self._session_file(name)
        if not file_path.exists():
            if create_if_missing:
                file_path.touch()
            else:
                raise FileNotFoundError(f"Session '{name}' does not exist")
        self.current = PersistentHistory(file_path)
        return self.current

    def delete_session(self, name: str) -> None:
        path = self._session_file(name)
        if path.exists():
            path.unlink()

    def rename_session(self, old_name: str, new_name: str) -> None:
        old_path = self._session_file(old_name)
        new_path = self._session_file(new_name)
        if not old_path.exists():
            raise FileNotFoundError(old_name)
        if new_path.exists():
            raise FileExistsError(new_name)

        # 更新文件内容中的 name 字段
        data = _SafeJsonFile.read(old_path)
        data["name"] = new_path.stem
        # 写入到新文件后再删除旧文件，确保原子性
        _SafeJsonFile.write(new_path, data)
        old_path.unlink()

        # If current session was renamed, update reference & meta
        if self.current and self.current._file_path == old_path:
            self.current._file_path = new_path
            self.current._meta["name"] = new_path.stem
            self.current._flush()

    # Convenience wrappers ------------------------------------------------
    def append(self, item: MessageTuple) -> None:
        if not self.current:
            self.create_new_session()
        assert self.current is not None
        self.current.append(item)

    def replace_current_messages(self, messages: Iterable[MessageTuple]) -> None:
        if not self.current:
            self.create_new_session()
        assert self.current is not None
        self.current.clear()
        self.current.extend(messages) 