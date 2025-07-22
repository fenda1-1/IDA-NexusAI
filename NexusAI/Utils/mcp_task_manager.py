"""
MCP Task Manager for NexusAI
NexusAI的MCP任务管理器

Manages persistent storage and tracking of MCP analysis tasks.
管理MCP分析任务的持久化存储和跟踪。
"""

import json
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict


@dataclass
class MCPTaskRecord:
    """MCP任务记录 / MCP Task Record."""
    
    id: str
    theme: str  # 用户提问
    display_name: str  # 显示名称（前几个字）
    status: str  # pending, running, done, error, cancelled
    created_at: str
    updated_at: str
    iterations: int = 0
    max_iterations: int = 999999
    conversation_history: List[Dict[str, Any]] = None
    error_message: str = ""
    result: str = ""
    model_config: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.conversation_history is None:
            self.conversation_history = []
        if self.model_config is None:
            self.model_config = {}


class MCPTaskManager:
    """MCP任务管理器 / MCP Task Manager."""
    
    def __init__(self, config_dir: Path):
        """初始化任务管理器 / Initialize task manager."""
        self.config_dir = Path(config_dir) if not isinstance(config_dir, Path) else config_dir
        self.tasks_dir = self.config_dir / "mcp_tasks"

        # 确保目录存在，包括父目录
        self.tasks_dir.mkdir(parents=True, exist_ok=True)

        self.tasks_index_file = self.tasks_dir / "tasks_index.json"
        self._tasks_cache: Dict[str, MCPTaskRecord] = {}
        self._load_tasks_index()
    
    def _load_tasks_index(self):
        """加载任务索引 / Load tasks index."""
        try:
            if self.tasks_index_file.exists():
                with open(self.tasks_index_file, 'r', encoding='utf-8') as f:
                    index_data = json.load(f)
                
                for task_id, task_data in index_data.items():
                    self._tasks_cache[task_id] = MCPTaskRecord(**task_data)
        except Exception as e:
            print(f"Error loading tasks index: {e}")
    
    def _save_tasks_index(self):
        """保存任务索引 / Save tasks index."""
        try:
            index_data = {}
            for task_id, task_record in self._tasks_cache.items():
                index_data[task_id] = asdict(task_record)
            
            with open(self.tasks_index_file, 'w', encoding='utf-8') as f:
                json.dump(index_data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"Error saving tasks index: {e}")
    
    def _generate_display_name(self, theme: str, max_length: int = 20) -> str:
        """生成显示名称 / Generate display name."""
        # 移除换行符和多余空格
        clean_theme = ' '.join(theme.strip().split())
        
        # 截取前几个字符
        if len(clean_theme) <= max_length:
            return clean_theme
        else:
            return clean_theme[:max_length] + "..."
    
    def create_task(self, theme: str, model_config: Dict[str, Any] = None) -> str:
        """创建新任务 / Create new task."""
        task_id = str(uuid.uuid4())
        current_time = datetime.now().isoformat()
        
        task_record = MCPTaskRecord(
            id=task_id,
            theme=theme,
            display_name=self._generate_display_name(theme),
            status="pending",
            created_at=current_time,
            updated_at=current_time,
            model_config=model_config or {}
        )
        
        self._tasks_cache[task_id] = task_record
        self._save_tasks_index()
        
        return task_id
    
    def update_task_status(self, task_id: str, status: str, error_message: str = ""):
        """更新任务状态 / Update task status."""
        if task_id in self._tasks_cache:
            task = self._tasks_cache[task_id]
            task.status = status
            task.updated_at = datetime.now().isoformat()
            if error_message:
                task.error_message = error_message
            self._save_tasks_index()
    
    def add_conversation_entry(self, task_id: str, entry_type: str, content: str, metadata: Dict[str, Any] = None):
        """添加对话记录 / Add conversation entry."""
        if task_id in self._tasks_cache:
            task = self._tasks_cache[task_id]
            
            entry = {
                "timestamp": datetime.now().isoformat(),
                "type": entry_type,  # "user_input", "ai_response", "action_result", "error", "system"
                "content": content,
                "metadata": metadata or {}
            }
            
            task.conversation_history.append(entry)
            task.updated_at = datetime.now().isoformat()
            self._save_tasks_index()
    
    def update_task_iterations(self, task_id: str, iterations: int):
        """更新任务迭代次数 / Update task iterations."""
        if task_id in self._tasks_cache:
            task = self._tasks_cache[task_id]
            task.iterations = iterations
            task.updated_at = datetime.now().isoformat()
            self._save_tasks_index()
    
    def get_task(self, task_id: str) -> Optional[MCPTaskRecord]:
        """获取任务记录 / Get task record."""
        return self._tasks_cache.get(task_id)
    
    def list_tasks(self, status_filter: Optional[str] = None) -> List[MCPTaskRecord]:
        """列出任务 / List tasks."""
        tasks = list(self._tasks_cache.values())
        
        if status_filter:
            tasks = [task for task in tasks if task.status == status_filter]
        
        # 按更新时间倒序排列
        tasks.sort(key=lambda x: x.updated_at, reverse=True)
        return tasks
    
    def get_incomplete_tasks(self) -> List[MCPTaskRecord]:
        """获取未完成的任务 / Get incomplete tasks."""
        incomplete_statuses = ["pending", "running", "error"]
        return [task for task in self._tasks_cache.values() 
                if task.status in incomplete_statuses]
    
    def delete_task(self, task_id: str) -> bool:
        """删除任务 / Delete task."""
        if task_id in self._tasks_cache:
            del self._tasks_cache[task_id]
            self._save_tasks_index()
            return True
        return False
    

    def get_task_conversation_context(self, task_id: str) -> str:
        """获取任务的对话上下文 / Get task conversation context."""
        task = self.get_task(task_id)
        if not task or not task.conversation_history:
            return ""
        
        # 构建对话上下文
        context_parts = []
        for entry in task.conversation_history:
            if entry["type"] == "ai_response":
                context_parts.append(entry["content"])
            elif entry["type"] == "action_result":
                context_parts.append(f"# Action Result:\n{entry['content']}")
        
        return "\n\n".join(context_parts)
    
    def cleanup_old_tasks(self, days: int = 30):
        """清理旧任务 / Cleanup old tasks."""
        cutoff_time = time.time() - (days * 24 * 3600)
        
        tasks_to_remove = []
        for task_id, task in self._tasks_cache.items():
            try:
                task_time = datetime.fromisoformat(task.created_at).timestamp()
                if task_time < cutoff_time and task.status in ["done", "cancelled"]:
                    tasks_to_remove.append(task_id)
            except Exception:
                continue
        
        for task_id in tasks_to_remove:
            del self._tasks_cache[task_id]
        
        if tasks_to_remove:
            self._save_tasks_index()
        
        return len(tasks_to_remove)


# 全局任务管理器实例
_task_manager = None

def get_task_manager(config_dir: Path = None) -> MCPTaskManager:
    """获取任务管理器实例 / Get task manager instance."""
    global _task_manager
    if _task_manager is None and config_dir is not None:
        _task_manager = MCPTaskManager(config_dir)
    return _task_manager
