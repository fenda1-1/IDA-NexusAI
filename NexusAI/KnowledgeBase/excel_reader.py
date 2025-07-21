"""
Excel Reader for NexusAI Knowledge Base
NexusAI知识库Excel读取器

Provides functionality to read and parse Excel files for knowledge base data.
提供读取和解析Excel文件作为知识库数据的功能。
"""

import os
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
import traceback

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

try:
    import openpyxl
    OPENPYXL_AVAILABLE = True
except ImportError:
    OPENPYXL_AVAILABLE = False


class ExcelReader:
    """Excel文件读取器 / Excel file reader for knowledge base."""
    
    def __init__(self):
        """初始化Excel读取器 / Initialize Excel reader."""
        self.supported_formats = ['.xlsx', '.xls', '.csv']
        self.encoding_options = ['utf-8', 'gbk', 'gb2312', 'utf-8-sig']
    
    def check_dependencies(self) -> Dict[str, bool]:
        """检查依赖库是否可用 / Check if required dependencies are available."""
        return {
            'pandas': PANDAS_AVAILABLE,
            'openpyxl': OPENPYXL_AVAILABLE
        }
    
    def install_dependencies(self) -> bool:
        """尝试安装缺失的依赖 / Try to install missing dependencies."""
        try:
            import subprocess
            import sys
            
            missing_deps = []
            if not PANDAS_AVAILABLE:
                missing_deps.append('pandas')
            if not OPENPYXL_AVAILABLE:
                missing_deps.append('openpyxl')
            
            if not missing_deps:
                return True
            
            for dep in missing_deps:
                print(f"Installing {dep}...")
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', dep])
            
            return True
        except Exception as e:
            print(f"Failed to install dependencies: {e}")
            return False
    
    def read_excel_file(self, file_path: Union[str, Path], 
                       sheet_name: Optional[str] = None,
                       header_row: int = 0) -> Dict[str, Any]:
        """
        读取Excel文件 / Read Excel file.
        
        Args:
            file_path: Excel文件路径 / Path to Excel file
            sheet_name: 工作表名称，None表示读取所有工作表 / Sheet name, None for all sheets
            header_row: 标题行索引 / Header row index
            
        Returns:
            包含数据和元信息的字典 / Dictionary containing data and metadata
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        if file_path.suffix.lower() not in self.supported_formats:
            raise ValueError(f"Unsupported file format: {file_path.suffix}")
        
        try:
            if file_path.suffix.lower() == '.csv':
                return self._read_csv_file(file_path, header_row)
            else:
                return self._read_excel_file(file_path, sheet_name, header_row)
        except Exception as e:
            raise Exception(f"Failed to read file {file_path}: {str(e)}")
    
    def _read_csv_file(self, file_path: Path, header_row: int = 0) -> Dict[str, Any]:
        """读取CSV文件 / Read CSV file."""
        if not PANDAS_AVAILABLE:
            raise ImportError("pandas is required to read CSV files")
        
        # Try different encodings
        for encoding in self.encoding_options:
            try:
                df = pd.read_csv(file_path, encoding=encoding, header=header_row)
                break
            except UnicodeDecodeError:
                continue
        else:
            raise UnicodeDecodeError("Failed to decode CSV file with any supported encoding")
        
        return {
            'sheets': {
                'Sheet1': {
                    'data': df.fillna('').to_dict('records'),
                    'columns': df.columns.tolist(),
                    'shape': df.shape
                }
            },
            'metadata': {
                'file_path': str(file_path),
                'file_size': file_path.stat().st_size,
                'sheet_count': 1,
                'encoding': encoding
            }
        }
    
    def _read_excel_file(self, file_path: Path, 
                        sheet_name: Optional[str] = None,
                        header_row: int = 0) -> Dict[str, Any]:
        """读取Excel文件 / Read Excel file."""
        if not PANDAS_AVAILABLE:
            raise ImportError("pandas is required to read Excel files")
        
        if not OPENPYXL_AVAILABLE and file_path.suffix.lower() == '.xlsx':
            raise ImportError("openpyxl is required to read .xlsx files")
        
        # Read Excel file
        if sheet_name:
            # Read specific sheet
            df = pd.read_excel(file_path, sheet_name=sheet_name, header=header_row)
            sheets_data = {
                sheet_name: {
                    'data': df.fillna('').to_dict('records'),
                    'columns': df.columns.tolist(),
                    'shape': df.shape
                }
            }
        else:
            # Read all sheets
            excel_file = pd.ExcelFile(file_path)
            sheets_data = {}
            
            for sheet in excel_file.sheet_names:
                try:
                    df = pd.read_excel(file_path, sheet_name=sheet, header=header_row)
                    sheets_data[sheet] = {
                        'data': df.fillna('').to_dict('records'),
                        'columns': df.columns.tolist(),
                        'shape': df.shape
                    }
                except Exception as e:
                    print(f"Warning: Failed to read sheet '{sheet}': {e}")
                    continue
        
        return {
            'sheets': sheets_data,
            'metadata': {
                'file_path': str(file_path),
                'file_size': file_path.stat().st_size,
                'sheet_count': len(sheets_data),
                'sheet_names': list(sheets_data.keys())
            }
        }
    
    def preview_file(self, file_path: Union[str, Path], 
                    max_rows: int = 10) -> Dict[str, Any]:
        """
        预览Excel文件内容 / Preview Excel file content.
        
        Args:
            file_path: 文件路径 / File path
            max_rows: 最大预览行数 / Maximum rows to preview
            
        Returns:
            预览数据 / Preview data
        """
        try:
            data = self.read_excel_file(file_path)
            
            # Limit preview data
            preview_data = {}
            for sheet_name, sheet_data in data['sheets'].items():
                preview_data[sheet_name] = {
                    'columns': sheet_data['columns'],
                    'data': sheet_data['data'][:max_rows],
                    'total_rows': sheet_data['shape'][0],
                    'total_columns': sheet_data['shape'][1]
                }
            
            return {
                'sheets': preview_data,
                'metadata': data['metadata']
            }
        except Exception as e:
            return {
                'error': str(e),
                'traceback': traceback.format_exc()
            }
    
    def validate_knowledge_base_format(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        验证知识库格式 / Validate knowledge base format.
        
        Args:
            data: Excel数据 / Excel data
            
        Returns:
            验证结果 / Validation result
        """
        validation_result = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'suggestions': []
        }
        
        if 'sheets' not in data or not data['sheets']:
            validation_result['valid'] = False
            validation_result['errors'].append("No sheets found in the file")
            return validation_result
        
        for sheet_name, sheet_data in data['sheets'].items():
            if not sheet_data.get('columns'):
                validation_result['warnings'].append(f"Sheet '{sheet_name}' has no columns")
                continue
            
            if not sheet_data.get('data'):
                validation_result['warnings'].append(f"Sheet '{sheet_name}' has no data")
                continue
            
            # Check for recommended columns
            columns = [col.lower() for col in sheet_data['columns']]
            recommended_columns = ['keyword', 'description', 'category', 'content']
            
            missing_recommended = []
            for rec_col in recommended_columns:
                if not any(rec_col in col for col in columns):
                    missing_recommended.append(rec_col)
            
            if missing_recommended:
                validation_result['suggestions'].append(
                    f"Sheet '{sheet_name}' could benefit from these columns: {', '.join(missing_recommended)}"
                )
        
        return validation_result
