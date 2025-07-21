"""
Knowledge Base Manager for NexusAI
NexusAI知识库管理器

Manages knowledge base data, provides search and query capabilities.
管理知识库数据，提供搜索和查询功能。
"""

import os
import json
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Tuple
from datetime import datetime
import threading
import traceback

from .excel_reader import ExcelReader


class KnowledgeManager:
    """知识库管理器 / Knowledge base manager."""
    
    def __init__(self, config_manager=None):
        """初始化知识库管理器 / Initialize knowledge manager."""
        self.config_manager = config_manager
        self.excel_reader = ExcelReader()
        self.knowledge_bases = {}
        self.search_index = {}
        self._lock = threading.Lock()
        
        # 设置知识库存储目录
        if config_manager and hasattr(config_manager, 'config_dir'):
            self.kb_dir = Path(config_manager.config_dir) / "knowledge_base"
        else:
            self.kb_dir = Path(__file__).parent.parent / "Config" / "knowledge_base"
        
        self.kb_dir.mkdir(parents=True, exist_ok=True)
        self.kb_config_file = self.kb_dir / "knowledge_bases.json"
        
        # 加载已有的知识库
        self.load_knowledge_bases()
    
    def add_knowledge_base(self, name: str, file_path: Union[str, Path], 
                          description: str = "", 
                          sheet_mapping: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        添加知识库 / Add knowledge base.
        
        Args:
            name: 知识库名称 / Knowledge base name
            file_path: Excel文件路径 / Excel file path
            description: 描述 / Description
            sheet_mapping: 工作表映射配置 / Sheet mapping configuration
            
        Returns:
            操作结果 / Operation result
        """
        try:
            with self._lock:
                # 检查名称是否已存在
                if name in self.knowledge_bases:
                    return {
                        'success': False,
                        'error': f"Knowledge base '{name}' already exists"
                    }
                
                # 读取Excel文件
                excel_data = self.excel_reader.read_excel_file(file_path)
                
                # 验证格式
                validation = self.excel_reader.validate_knowledge_base_format(excel_data)
                
                # 处理工作表映射
                processed_data = self._process_excel_data(excel_data, sheet_mapping)
                
                # 创建知识库条目
                kb_entry = {
                    'name': name,
                    'description': description,
                    'file_path': str(file_path),
                    'created_at': datetime.now().isoformat(),
                    'updated_at': datetime.now().isoformat(),
                    'sheet_mapping': sheet_mapping or {},
                    'data': processed_data,
                    'metadata': excel_data['metadata'],
                    'validation': validation,
                    'enabled': True
                }
                
                # 添加到内存
                self.knowledge_bases[name] = kb_entry
                
                # 构建搜索索引
                self._build_search_index(name, processed_data)
                
                # 保存配置
                self.save_knowledge_bases()
                
                return {
                    'success': True,
                    'message': f"Knowledge base '{name}' added successfully",
                    'validation': validation
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc()
            }
    
    def remove_knowledge_base(self, name: str) -> Dict[str, Any]:
        """移除知识库 / Remove knowledge base."""
        try:
            with self._lock:
                if name not in self.knowledge_bases:
                    return {
                        'success': False,
                        'error': f"Knowledge base '{name}' not found"
                    }
                
                # 从内存中移除
                del self.knowledge_bases[name]
                
                # 从搜索索引中移除
                if name in self.search_index:
                    del self.search_index[name]
                
                # 保存配置
                self.save_knowledge_bases()
                
                return {
                    'success': True,
                    'message': f"Knowledge base '{name}' removed successfully"
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def update_knowledge_base(self, name: str, **kwargs) -> Dict[str, Any]:
        """更新知识库 / Update knowledge base."""
        try:
            with self._lock:
                if name not in self.knowledge_bases:
                    return {
                        'success': False,
                        'error': f"Knowledge base '{name}' not found"
                    }
                
                kb_entry = self.knowledge_bases[name]
                
                # 更新字段
                for key, value in kwargs.items():
                    if key in ['description', 'enabled', 'sheet_mapping']:
                        kb_entry[key] = value
                
                # 如果文件路径改变，重新读取数据
                if 'file_path' in kwargs:
                    excel_data = self.excel_reader.read_excel_file(kwargs['file_path'])
                    processed_data = self._process_excel_data(excel_data, kb_entry.get('sheet_mapping'))
                    
                    kb_entry['file_path'] = str(kwargs['file_path'])
                    kb_entry['data'] = processed_data
                    kb_entry['metadata'] = excel_data['metadata']
                    
                    # 重建搜索索引
                    self._build_search_index(name, processed_data)
                
                kb_entry['updated_at'] = datetime.now().isoformat()
                
                # 保存配置
                self.save_knowledge_bases()
                
                return {
                    'success': True,
                    'message': f"Knowledge base '{name}' updated successfully"
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def search_knowledge(self, query: str, kb_names: Optional[List[str]] = None,
                        max_results: int = 10) -> List[Dict[str, Any]]:
        """
        搜索知识库 / Search knowledge base.
        
        Args:
            query: 搜索查询 / Search query
            kb_names: 指定搜索的知识库名称列表 / Specific knowledge base names to search
            max_results: 最大结果数 / Maximum number of results
            
        Returns:
            搜索结果列表 / List of search results
        """
        try:
            results = []
            query_lower = query.lower()
            
            # 确定要搜索的知识库
            search_kbs = kb_names if kb_names else list(self.knowledge_bases.keys())
            
            for kb_name in search_kbs:
                if kb_name not in self.knowledge_bases:
                    continue
                
                kb_entry = self.knowledge_bases[kb_name]
                if not kb_entry.get('enabled', True):
                    continue
                
                # 搜索数据
                kb_results = self._search_in_knowledge_base(kb_name, query_lower, kb_entry['data'])
                results.extend(kb_results)
            
            # 按相关性排序
            results.sort(key=lambda x: x['relevance_score'], reverse=True)
            
            return results[:max_results]
            
        except Exception as e:
            print(f"Error searching knowledge base: {e}")
            return []
    
    def get_knowledge_base_info(self, name: str) -> Optional[Dict[str, Any]]:
        """获取知识库信息 / Get knowledge base info."""
        if name in self.knowledge_bases:
            kb_entry = self.knowledge_bases[name].copy()
            # 不返回完整数据，只返回元信息
            if 'data' in kb_entry:
                del kb_entry['data']
            return kb_entry
        return None
    
    def list_knowledge_bases(self) -> List[Dict[str, Any]]:
        """列出所有知识库 / List all knowledge bases."""
        kb_list = []
        for name, kb_entry in self.knowledge_bases.items():
            info = {
                'name': name,
                'description': kb_entry.get('description', ''),
                'file_path': kb_entry.get('file_path', ''),
                'created_at': kb_entry.get('created_at', ''),
                'updated_at': kb_entry.get('updated_at', ''),
                'enabled': kb_entry.get('enabled', True),
                'sheet_count': len(kb_entry.get('data', {})),
                'total_records': sum(len(sheet_data) for sheet_data in kb_entry.get('data', {}).values())
            }
            kb_list.append(info)
        
        return kb_list
    
    def get_relevant_knowledge(self, context: str, max_items: int = 5) -> str:
        """
        获取与上下文相关的知识 / Get knowledge relevant to context.

        Args:
            context: 上下文信息 / Context information
            max_items: 最大返回项目数 / Maximum number of items to return

        Returns:
            格式化的相关知识文本 / Formatted relevant knowledge text
        """
        try:
            print(f"[DEBUG] Searching knowledge for context: {context[:100]}...")

            # 搜索相关知识
            results = self.search_knowledge(context, max_results=max_items)

            print(f"[DEBUG] Found {len(results)} knowledge results")

            if not results:
                return ""

            # 格式化知识内容
            knowledge_text = "## 相关知识库信息 / Relevant Knowledge Base Information:\n\n"

            for i, result in enumerate(results, 1):
                print(f"[DEBUG] Knowledge item {i}: {result.get('title', 'No title')} (score: {result['relevance_score']:.2f})")
                knowledge_text += f"### {i}. {result.get('title', 'Knowledge Item')}\n"
                knowledge_text += f"**来源 / Source**: {result['kb_name']}\n"
                knowledge_text += f"**内容 / Content**: {result['content']}\n"
                if result.get('category'):
                    knowledge_text += f"**分类 / Category**: {result['category']}\n"
                knowledge_text += f"**相关性 / Relevance**: {result['relevance_score']:.2f}\n\n"

            return knowledge_text

        except Exception as e:
            print(f"[DEBUG] Error getting relevant knowledge: {e}")
            return ""

    def _process_excel_data(self, excel_data: Dict[str, Any],
                           sheet_mapping: Optional[Dict[str, str]] = None) -> Dict[str, List[Dict[str, Any]]]:
        """处理Excel数据 / Process Excel data."""
        processed_data = {}

        for sheet_name, sheet_data in excel_data['sheets'].items():
            if not sheet_data.get('data'):
                continue

            # 应用工作表映射
            mapped_name = sheet_mapping.get(sheet_name, sheet_name) if sheet_mapping else sheet_name

            # 处理每行数据
            processed_rows = []
            for row in sheet_data['data']:
                processed_row = self._process_row_data(row, sheet_data['columns'])
                if processed_row:
                    processed_rows.append(processed_row)

            processed_data[mapped_name] = processed_rows

        return processed_data

    def _process_row_data(self, row: Dict[str, Any], columns: List[str]) -> Optional[Dict[str, Any]]:
        """处理单行数据 / Process single row data."""
        # 跳过空行
        if not any(str(value).strip() for value in row.values()):
            return None

        processed_row = {}

        # 标准化列名映射
        column_mapping = {
            'keyword': ['keyword', 'key', 'name', 'title', '关键词', '名称', '标题'],
            'description': ['description', 'desc', 'detail', 'info', '描述', '说明', '详情'],
            'category': ['category', 'type', 'class', 'group', '分类', '类型', '类别'],
            'content': ['content', 'text', 'body', 'data', '内容', '正文', '数据'],
            'tags': ['tags', 'tag', 'label', 'labels', '标签', '标记'],
            'priority': ['priority', 'weight', 'importance', '优先级', '权重', '重要性']
        }

        # 映射列数据
        for standard_key, possible_names in column_mapping.items():
            for col in columns:
                col_lower = col.lower()
                if any(name in col_lower for name in possible_names):
                    value = row.get(col, '')
                    if value and str(value).strip():
                        processed_row[standard_key] = str(value).strip()
                    break

        # 如果没有找到标准字段，使用原始数据
        if not processed_row:
            processed_row = {k: str(v) for k, v in row.items() if v and str(v).strip()}

        # 确保有基本的搜索字段
        if 'keyword' not in processed_row and 'content' not in processed_row:
            # 使用第一个非空字段作为关键词
            for key, value in row.items():
                if value and str(value).strip():
                    processed_row['keyword'] = str(value).strip()
                    break

        return processed_row if processed_row else None

    def _build_search_index(self, kb_name: str, data: Dict[str, List[Dict[str, Any]]]):
        """构建搜索索引 / Build search index."""
        if kb_name not in self.search_index:
            self.search_index[kb_name] = {}

        index = self.search_index[kb_name]
        index.clear()

        for sheet_name, rows in data.items():
            for row_idx, row in enumerate(rows):
                # 为每个字段建立索引
                for field, value in row.items():
                    if not value:
                        continue

                    # 分词并建立索引
                    words = self._tokenize(str(value))
                    for word in words:
                        if word not in index:
                            index[word] = []

                        index[word].append({
                            'sheet': sheet_name,
                            'row_idx': row_idx,
                            'field': field,
                            'value': value
                        })

    def _tokenize(self, text: str) -> List[str]:
        """分词 / Tokenize text."""
        # 简单的分词实现
        text = text.lower()
        # 移除标点符号，保留中英文和数字
        text = re.sub(r'[^\w\s\u4e00-\u9fff]', ' ', text)
        # 分割单词
        words = text.split()

        # 对于中文，也尝试按字符分割
        chinese_chars = re.findall(r'[\u4e00-\u9fff]', text)
        words.extend(chinese_chars)

        # 过滤短词和停用词
        stop_words = {'的', '了', '在', '是', '和', 'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for'}
        words = [word for word in words if len(word) > 1 and word not in stop_words]

        return list(set(words))  # 去重

    def _search_in_knowledge_base(self, kb_name: str, query: str,
                                 data: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """在知识库中搜索 / Search in knowledge base."""
        results = []
        query_words = self._tokenize(query)

        if not query_words:
            return results

        # 使用索引搜索
        if kb_name in self.search_index:
            index = self.search_index[kb_name]
            matched_items = {}

            for word in query_words:
                if word in index:
                    for item in index[word]:
                        key = f"{item['sheet']}_{item['row_idx']}"
                        if key not in matched_items:
                            matched_items[key] = {
                                'sheet': item['sheet'],
                                'row_idx': item['row_idx'],
                                'matches': [],
                                'score': 0
                            }

                        matched_items[key]['matches'].append({
                            'field': item['field'],
                            'value': item['value'],
                            'word': word
                        })
                        matched_items[key]['score'] += 1

            # 转换为结果格式
            for key, match_info in matched_items.items():
                sheet_name = match_info['sheet']
                row_idx = match_info['row_idx']

                if sheet_name in data and row_idx < len(data[sheet_name]):
                    row_data = data[sheet_name][row_idx]

                    result = {
                        'kb_name': kb_name,
                        'sheet_name': sheet_name,
                        'title': row_data.get('keyword', row_data.get('title', 'Unknown')),
                        'content': row_data.get('content', row_data.get('description', '')),
                        'category': row_data.get('category', ''),
                        'raw_data': row_data,
                        'matches': match_info['matches'],
                        'relevance_score': self._calculate_relevance_score(query_words, match_info['matches'], row_data)
                    }
                    results.append(result)

        return results

    def _calculate_relevance_score(self, query_words: List[str],
                                  matches: List[Dict[str, Any]],
                                  row_data: Dict[str, Any]) -> float:
        """计算相关性分数 / Calculate relevance score."""
        score = 0.0

        # 基础匹配分数
        score += len(matches) * 0.1

        # 字段权重
        field_weights = {
            'keyword': 1.0,
            'title': 0.9,
            'content': 0.7,
            'description': 0.6,
            'category': 0.5,
            'tags': 0.4
        }

        for match in matches:
            field = match['field']
            weight = field_weights.get(field, 0.3)
            score += weight

        # 查询词覆盖率
        matched_words = set(match['word'] for match in matches)
        coverage = len(matched_words) / len(query_words) if query_words else 0
        score += coverage * 0.5

        # 优先级加权
        if 'priority' in row_data:
            try:
                priority = float(row_data['priority'])
                score += priority * 0.1
            except (ValueError, TypeError):
                pass

        return min(score, 1.0)  # 限制最大分数为1.0

    def save_knowledge_bases(self):
        """保存知识库配置 / Save knowledge base configuration."""
        try:
            # 准备保存的数据（不包含完整的数据内容）
            save_data = {}
            for name, kb_entry in self.knowledge_bases.items():
                save_entry = kb_entry.copy()
                # 移除大数据字段，只保存配置信息
                if 'data' in save_entry:
                    del save_entry['data']
                save_data[name] = save_entry

            with open(self.kb_config_file, 'w', encoding='utf-8') as f:
                json.dump(save_data, f, ensure_ascii=False, indent=2)

        except Exception as e:
            print(f"Error saving knowledge base configuration: {e}")

    def load_knowledge_bases(self):
        """加载知识库配置 / Load knowledge base configuration."""
        try:
            if not self.kb_config_file.exists():
                return

            with open(self.kb_config_file, 'r', encoding='utf-8') as f:
                saved_data = json.load(f)

            # 重新加载每个知识库的数据
            for name, kb_config in saved_data.items():
                try:
                    file_path = kb_config.get('file_path')
                    if file_path and Path(file_path).exists():
                        # 重新读取Excel数据
                        excel_data = self.excel_reader.read_excel_file(file_path)
                        processed_data = self._process_excel_data(excel_data, kb_config.get('sheet_mapping'))

                        # 恢复完整的知识库条目
                        kb_config['data'] = processed_data
                        kb_config['metadata'] = excel_data['metadata']

                        self.knowledge_bases[name] = kb_config

                        # 重建搜索索引
                        self._build_search_index(name, processed_data)

                    else:
                        print(f"Warning: Knowledge base file not found: {file_path}")

                except Exception as e:
                    print(f"Error loading knowledge base '{name}': {e}")
                    continue

        except Exception as e:
            print(f"Error loading knowledge base configuration: {e}")
