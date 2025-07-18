"""extension_loader
动态扫描并加载 `extensions/` 目录下的 Python 扩展。Dynamic loader that imports user/community extensions located in the ``extensions`` folder.
"""

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Dict, List, Optional

from .event_bus import get_event_bus


class ExtensionLoader:
    """扩展加载器 / Runtime extension loader."""

    def __init__(self, base_dir: Path):
        self.base_dir: Path = base_dir
        self._loaded: Dict[str, ModuleType] = {}
        self.event_bus = get_event_bus()

    def scan_files(self) -> List[Path]:
        """扫描扩展目录 / Recursively collect ``.py`` files."""
        if not self.base_dir.exists():
            self.base_dir.mkdir(parents=True, exist_ok=True)

        py_files: List[Path] = []
        for path in self.base_dir.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            if path.name.startswith("_"):
                continue
            py_files.append(path)
        py_files.sort(key=lambda p: p.name.endswith("_extension.py"))
        return py_files

    def load_extensions(self):
        """加载扩展 / Import new extensions."""
        for path in self.scan_files():
            rel_path = path.relative_to(self.base_dir).with_suffix("")
            mod_name = "nexusai_extensions." + ".".join(rel_path.parts)
            if mod_name in self._loaded:
                continue
            module = self._import_module_from_path(mod_name, path)
            if module is None:
                continue
            if getattr(module, "__nexus_extension__", True) is False:
                continue

            self._loaded[mod_name] = module

            init_fn = getattr(module, "init_extension", None)
            if callable(init_fn):
                try:
                    init_fn(self.event_bus)
                except Exception:
                    import traceback
                    traceback.print_exc()

    def reload_extensions(self):
        """热重载 / Reload extensions."""
        for mod in list(self._loaded.values()):
            deinit_fn = getattr(mod, "deinit_extension", None)
            if callable(deinit_fn):
                try:
                    deinit_fn()
                except Exception:
                    import traceback
                    traceback.print_exc()
            sys.modules.pop(mod.__name__, None)
        self._loaded.clear()
        self.load_extensions()

    @staticmethod
    def _import_module_from_path(fullname: str, path: Path) -> Optional[ModuleType]:
        try:
            spec = importlib.util.spec_from_file_location(fullname, path)
            if spec is None or spec.loader is None:
                return None
            module = importlib.util.module_from_spec(spec)
            sys.modules[fullname] = module
            spec.loader.exec_module(module)  # type: ignore[arg-type]
            return module
        except Exception:
            import traceback
            traceback.print_exc()
            return None


_loader_instance: Optional[ExtensionLoader] = None


def get_extension_loader() -> ExtensionLoader:
    """获取单例加载器 / Return singleton instance."""
    global _loader_instance  # pylint: disable=global-statement
    if _loader_instance is None:
        root = Path(__file__).resolve().parent.parent
        _loader_instance = ExtensionLoader(root / "extensions")
    return _loader_instance