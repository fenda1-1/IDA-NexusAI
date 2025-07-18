"""event_bus
轻量级同步事件总线 / Lightweight synchronous event bus.

提供 ``on / off / emit`` 基础 API，实现插件内部的松耦合通信。
Provides basic ``on / off / emit`` APIs for loosely coupled communication within plugins.
"""

import traceback
from collections import defaultdict
from typing import Callable, Dict, List


class EventBus:  # pylint: disable=too-few-public-methods
    """事件总线 / Simple synchronous event bus."""

    def __init__(self):
        self._handlers: Dict[str, List[Callable]] = defaultdict(list)

    def on(self, event: str, handler: Callable):
        """订阅事件 / Register handler."""
        if handler not in self._handlers[event]:
            self._handlers[event].append(handler)

    def off(self, event: str, handler: Callable):
        """取消订阅 / Unregister handler."""
        if handler in self._handlers[event]:
            self._handlers[event].remove(handler)
            if not self._handlers[event]:
                del self._handlers[event]

    def emit(self, event: str, *args, **kwargs):
        """触发事件 / Emit event.

        """
        for handler in list(self._handlers.get(event, [])):
            try:
                handler(*args, **kwargs)
            except Exception:  # pylint: disable=broad-except
                traceback.print_exc()


_event_bus = EventBus()


def get_event_bus() -> EventBus:
    """获取全局事件总线 / Return the singleton event bus instance."""
    return _event_bus