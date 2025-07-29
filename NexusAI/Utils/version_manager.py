"""
Version Manager for NexusAI
NexusAI版本管理器

Handles version checking and GitHub API integration.
处理版本检查和GitHub API集成。
"""

import json
import threading
import time
from typing import Optional, Dict, Any
from pathlib import Path

try:
    import urllib.request
    import urllib.parse
    import ssl
    HTTP_AVAILABLE = True
except ImportError:
    HTTP_AVAILABLE = False


class VersionManager:
    """版本管理器 / Version manager."""
    
    # 当前版本
    CURRENT_VERSION = "1.0.4"
    
    # GitHub API配置
    GITHUB_API_URL = "https://api.github.com/repos/fenda1-1/IDA-NexusAI/tags"
    
    def __init__(self, config_manager=None):
        """初始化版本管理器 / Initialize version manager."""
        self.config_manager = config_manager
        self.latest_version = None
        self.version_check_time = None
        self.check_in_progress = False
        
        # 版本缓存文件
        if config_manager and hasattr(config_manager, 'config_dir'):
            self.cache_file = Path(config_manager.config_dir) / "version_cache.json"
        else:
            self.cache_file = Path(__file__).parent.parent / "Config" / "version_cache.json"
    
    def get_current_version(self) -> str:
        """获取当前版本 / Get current version."""
        return self.CURRENT_VERSION
    
    def get_latest_version(self) -> Optional[str]:
        """获取最新版本（从缓存或API） / Get latest version (from cache or API)."""
        # 如果已经有内存中的版本，优先使用
        if self.latest_version:
            return self.latest_version

        # 先尝试从缓存读取
        cached_version = self._load_cached_version()
        if cached_version:
            self.latest_version = cached_version
            return cached_version

        # 如果没有缓存，启动后台检查
        if not self.check_in_progress:
            self._start_background_check()

        return None
    
    def get_version_title(self) -> str:
        """获取包含版本信息的标题 / Get title with version info."""
        current = self.get_current_version()
        latest = self.get_latest_version()
        
        if latest and latest != current:
            return f"NexusAI v{current} (latest: v{latest})"
        elif latest:
            return f"NexusAI v{current} (latest: v{latest})"
        else:
            return f"NexusAI v{current}"
    
    def _load_cached_version(self) -> Optional[str]:
        """从缓存文件加载版本信息 / Load version info from cache file."""
        try:
            if not self.cache_file.exists():
                return None
            
            with open(self.cache_file, 'r', encoding='utf-8') as f:
                cache_data = json.load(f)
            
            # 检查缓存是否过期（24小时）
            cache_time = cache_data.get('timestamp', 0)
            current_time = time.time()
            
            if current_time - cache_time > 24 * 3600:  # 24小时过期
                return None
            
            return cache_data.get('latest_version')
            
        except Exception as e:
            print(f"Error loading version cache: {e}")
            return None
    
    def _save_cached_version(self, version: str):
        """保存版本信息到缓存 / Save version info to cache."""
        try:
            cache_data = {
                'latest_version': version,
                'timestamp': time.time()
            }
            
            # 确保目录存在
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, indent=2)
                
        except Exception as e:
            print(f"Error saving version cache: {e}")
    
    def _start_background_check(self):
        """启动后台版本检查 / Start background version check."""
        if not HTTP_AVAILABLE:
            return
        
        self.check_in_progress = True
        thread = threading.Thread(target=self._check_latest_version_async, daemon=True)
        thread.start()
    
    def _check_latest_version_async(self):
        """异步检查最新版本 / Async check latest version."""
        try:
            latest = self._fetch_latest_version_from_github()
            if latest:
                self.latest_version = latest
                self._save_cached_version(latest)
                
        except Exception as e:
            print(f"Error checking latest version: {e}")
        finally:
            self.check_in_progress = False
    
    def _fetch_latest_version_from_github(self) -> Optional[str]:
        """从GitHub API获取最新版本 / Fetch latest version from GitHub API."""
        try:
            # 创建SSL上下文
            ssl_context = ssl.create_default_context()
            
            # 创建请求
            request = urllib.request.Request(
                self.GITHUB_API_URL,
                headers={
                    'User-Agent': 'NexusAI-Plugin/1.0',
                    'Accept': 'application/vnd.github.v3+json'
                }
            )
            
            # 发送请求（设置超时）
            with urllib.request.urlopen(request, context=ssl_context, timeout=10) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode('utf-8'))
                    
                    # 获取最新的tag
                    if data and len(data) > 0:
                        latest_tag = data[0]['name']
                        
                        # 清理版本号（移除v前缀）
                        if latest_tag.startswith('v'):
                            latest_tag = latest_tag[1:]
                        
                        return latest_tag
                        
        except Exception as e:
            print(f"Error fetching version from GitHub: {e}")
            
        return None
    
    def check_for_updates(self) -> Dict[str, Any]:
        """检查更新 / Check for updates."""
        current = self.get_current_version()
        latest = self.get_latest_version()
        
        if not latest:
            return {
                'has_update': False,
                'current_version': current,
                'latest_version': None,
                'message': 'Unable to check for updates'
            }
        
        # 简单的版本比较（假设使用语义版本）
        has_update = self._compare_versions(current, latest) < 0
        
        return {
            'has_update': has_update,
            'current_version': current,
            'latest_version': latest,
            'message': f'Update available: v{latest}' if has_update else 'You are using the latest version'
        }
    
    def _compare_versions(self, version1: str, version2: str) -> int:
        """比较版本号 / Compare version numbers."""
        try:
            # 将版本号分割为数字列表
            v1_parts = [int(x) for x in version1.split('.')]
            v2_parts = [int(x) for x in version2.split('.')]
            
            # 补齐长度
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            # 逐位比较
            for v1, v2 in zip(v1_parts, v2_parts):
                if v1 < v2:
                    return -1
                elif v1 > v2:
                    return 1
            
            return 0
            
        except Exception:
            # 如果比较失败，使用字符串比较
            if version1 < version2:
                return -1
            elif version1 > version2:
                return 1
            else:
                return 0
    
    def force_check_update(self) -> Optional[str]:
        """强制检查更新（同步） / Force check update (synchronous)."""
        if not HTTP_AVAILABLE:
            return None
        
        try:
            latest = self._fetch_latest_version_from_github()
            if latest:
                self.latest_version = latest
                self._save_cached_version(latest)
                return latest
        except Exception as e:
            print(f"Error in force check update: {e}")
        
        return None


# 全局版本管理器实例
_version_manager = None

def get_version_manager(config_manager=None) -> VersionManager:
    """获取版本管理器实例 / Get version manager instance."""
    global _version_manager
    if _version_manager is None:
        _version_manager = VersionManager(config_manager)
    return _version_manager
