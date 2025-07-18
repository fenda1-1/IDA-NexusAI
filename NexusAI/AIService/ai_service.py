"""Deprecated: 保留旧路径以兼容早期引用。
直接从 openai_service 导入相同符号。
"""

from .openai_service import OpenAIService as AIService, QueryStatus  # noqa: F401 