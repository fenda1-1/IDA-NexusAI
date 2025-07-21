"""
NexusAI Knowledge Base Module
知识库模块

This module provides Excel-based knowledge base functionality for NexusAI.
该模块为NexusAI提供基于Excel的知识库功能。

Features:
- Excel file reading and parsing
- Knowledge base management
- AI integration with knowledge base data
- Search and query capabilities

功能特性：
- Excel文件读取和解析
- 知识库管理
- AI与知识库数据集成
- 搜索和查询功能
"""

from .excel_reader import ExcelReader
from .knowledge_manager import KnowledgeManager

__all__ = [
    "ExcelReader",
    "KnowledgeManager"
]
