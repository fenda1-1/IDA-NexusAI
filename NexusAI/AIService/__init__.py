
from .base_service import BaseAIService, QueryStatus

"""AIService 包
提供统一的 *Provider Registry*，用于在运行时按名称（大小写不敏感）
检索或注册 AI 服务实现。

AIService package exposes a **provider registry** allowing new back-ends to be
added via ``@register_provider("name")`` decorator.  The helper
:pyfunc:`get_provider_class` returns the class by name; it is primarily used by
:pyclass:`Core.TaskController` when instantiating the desired engine.
"""

# ---------------------------------------------------------------------------
# Provider Registry
# ---------------------------------------------------------------------------

_PROVIDER_REGISTRY = {}


def register_provider(name: str):
    """注册 AI Provider / Decorator for registering providers.

    Example::

        @register_provider("openai")
        class OpenAIService(BaseAIService):
            pass
    """

    def _decorator(cls):
        key = name.lower().strip()
        _PROVIDER_REGISTRY[key] = cls
        return cls

    return _decorator


def get_provider_class(name: str):
    """按名称检索 Provider / Case-insensitive lookup."""
    return _PROVIDER_REGISTRY.get(name.lower().strip())

# ---------------------------------------------------------------------------
# 默认导出
# ---------------------------------------------------------------------------

from .openai_service import OpenAIService  # noqa: E402  (保持向后兼容的显式导入)

__all__ = [
    "BaseAIService",
    "QueryStatus",
    "OpenAIService",
    "register_provider",
    "get_provider_class",
]

