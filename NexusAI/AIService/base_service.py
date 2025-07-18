"""BaseAIService
抽象 AI 服务接口，统一不同模型后端的调用方式。

This module defines the common **abstract layer** for all concrete AI service
implementations (e.g. OpenAI, local LLMs).  By inheriting from
`BaseAIService`, every provider exposes a consistent set of **stream** and
**non-stream** query methods, allowing the rest of the plugin to remain engine
agnostic.
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import List, Dict, Any

class QueryStatus(Enum):
    """统一的查询状态。

    Unified status flags describing the lifecycle of an AI request.
    """
    SUCCESS = 1
    FAILED = 2
    STOPPED = 3

class BaseAIService(ABC):
    """AI 服务基类 / Base class for all concrete providers.

    子类需要实现 :py:meth:`query_stream`，并可视需要重写
    :py:meth:`create_prompt` 与 :py:meth:`query`（非流式）等辅助方法。
    """

    def __init__(self, config_manager):
        """保存配置管理器实例 / Keep a reference to :class:`ConfigManager`."""
        self.config = config_manager

    # === 公共核心方法 ===
    @abstractmethod
    def query_stream(self, prompt: str):
        """流式查询 / Stream-based request.

        子类应实现该方法，使用其后端的流接口将 **实时** 结果推送至
        :class:`UI.OutputView`。
        """
        raise NotImplementedError

    # === 可选通用方法（如有需要可被子类重写） ===
    def create_prompt(self, prompt_type: str, content: str) -> List[Dict[str, Any]]:
        """使用 :class:`ConfigManager` 构造 prompt / Build prompt list via ConfigManager."""
        return self.config.get_prompt_messages(prompt_type, content) if hasattr(self.config, "get_prompt_messages") else []

    def is_client_initialized(self) -> bool:
        """客户端是否已初始化 / Return ``True`` if backend client is ready."""
        return getattr(self.config, "client", None) is not None 