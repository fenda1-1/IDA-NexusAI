# 为NexusAI做贡献

感谢您对为NexusAI做贡献的兴趣！本文档为贡献者提供指南和信息。

## 🤝 如何贡献

### 报告问题
- 使用 [GitHub Issues](https://github.com/your-repo/NexusAI/issues) 页面
- 在创建新问题之前搜索现有问题
- 提供详细信息，包括：
  - IDA Pro版本
  - Python版本
  - 操作系统
  - 重现步骤
  - 预期与实际行为
  - 错误消息或日志

### 建议功能
- 打开 [GitHub讨论](https://github.com/your-repo/NexusAI/discussions)
- 描述功能及其用例
- 解释它如何使用户受益
- 考虑实现复杂性

### 代码贡献
1. **Fork** 仓库
2. **创建** 功能分支：`git checkout -b feature/amazing-feature`
3. **进行** 更改
4. **彻底测试**
5. **提交** 清晰的消息：`git commit -m 'Add amazing feature'`
6. **推送** 到您的分支：`git push origin feature/amazing-feature`
7. **打开** 拉取请求

## 🏗️ 开发设置

### 先决条件
- IDA Pro 7.x、8.x或9.x
- Python 3.8+
- Git

### 环境设置
```bash
# 克隆您的fork
git clone https://github.com/your-username/NexusAI.git
cd NexusAI

# 安装开发依赖
pip install -r requirements.txt
pip install -r requirements-dev.txt  # 如果可用

# 以开发模式安装
python install.py --dev --ida-dir /path/to/ida
```

### 项目结构
```
NexusAI/
├── NexusAI.py              # 插件入口点
├── NexusAI/                # 主插件包
│   ├── __init__.py
│   ├── Core/               # 核心功能
│   │   ├── plugin.py       # 主插件类
│   │   ├── task_controller.py
│   │   ├── mcp_controller.py
│   │   └── ...
│   ├── AIService/          # AI服务提供商
│   │   ├── base_service.py
│   │   ├── openai_service.py
│   │   └── ...
│   ├── UI/                 # 用户界面
│   │   └── ui_view.py
│   ├── Utils/              # 工具
│   │   ├── code_extractor.py
│   │   ├── comment_applicator.py
│   │   └── ...
│   ├── Config/             # 配置
│   │   ├── config.py
│   │   └── NexusAI.json
│   └── extensions/         # 插件扩展
│       ├── graph_export_extension/
│       └── flattening_detection_extension/
├── requirements.txt        # Python依赖
├── install.py             # 安装脚本
├── README_CN.md           # 中文文档
└── docs/                  # 附加文档
```

## 📝 编码标准

### Python风格
- 遵循 [PEP 8](https://pep8.org/) 风格指南
- 在适当的地方使用类型提示
- 最大行长度：100字符
- 使用有意义的变量和函数名

### 代码质量
- 为所有公共函数和类编写文档字符串
- 为复杂逻辑添加注释
- 适当处理异常
- 避免硬编码值

### 示例代码风格
```python
"""描述目的的模块文档字符串。"""

from typing import Optional, List
import idaapi


class ExampleClass:
    """解释目的和用法的类文档字符串。"""
    
    def __init__(self, config_manager: ConfigManager):
        """使用配置管理器初始化类。
        
        Args:
            config_manager: 配置管理器实例
        """
        self.config = config_manager
        self._private_var = None
    
    def public_method(self, param: str) -> Optional[str]:
        """具有清晰文档的公共方法。
        
        Args:
            param: 参数的描述
            
        Returns:
            返回值的描述，如果失败则为None
            
        Raises:
            ValueError: 当参数无效时
        """
        if not param:
            raise ValueError("参数不能为空")
        
        try:
            # 处理参数
            result = self._process_param(param)
            return result
        except Exception as e:
            self.config.show_message("error_occurred", str(e))
            return None
    
    def _process_param(self, param: str) -> str:
        """用于内部处理的私有方法。"""
        return param.upper()
```

## 🧪 测试

### 手动测试
- 使用不同的IDA Pro版本测试
- 使用各种二进制类型测试（PE、ELF、Mach-O）
- 测试不同的AI模型和提供商
- 验证UI响应性和错误处理

### 测试清单
- [ ] 插件加载无错误
- [ ] 所有菜单项和热键工作
- [ ] AI分析产生合理结果
- [ ] 配置更改持久化
- [ ] 错误消息有帮助
- [ ] 无内存泄漏或崩溃

### 测试环境
为以下情况创建测试用例：
- 不同架构（x86、x64、ARM）
- 各种文件格式
- 边缘情况（空函数、大型二进制文件）
- 网络问题（超时、代理错误）
- 无效配置

## 📚 文档

### 代码文档
- 使用清晰、描述性的文档字符串
- 记录参数、返回值和异常
- 为复杂函数包含使用示例
- 保持文档与代码更改同步

### 用户文档
- 为新功能更新README_CN.md
- 添加配置示例
- 包含故障排除信息
- 提供清晰的安装说明

## 🔧 扩展开发

### 创建扩展
扩展应遵循此结构：
```python
# extensions/my_extension/my_extension.py

def init_extension():
    """初始化扩展。"""
    # 注册操作、钩子等
    pass

def deinit_extension():
    """清理扩展。"""
    # 取消注册操作，清理资源
    pass

class MyExtensionAction(idaapi.action_handler_t):
    """扩展操作处理程序。"""
    
    def activate(self, ctx):
        # 实现
        return 1
    
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
```

### 扩展指南
- 保持扩展专注于特定功能
- 使用事件总线进行通信
- 优雅地处理错误
- 提供配置选项
- 包含文档和示例

## 🚀 发布流程

### 版本编号
- 遵循 [语义版本控制](https://semver.org/)
- 格式：MAJOR.MINOR.PATCH
- 在 `NexusAI/__init__.py` 中更新版本

### 发布清单
- [ ] 更新版本号
- [ ] 更新CHANGELOG_CN.md
- [ ] 在多个IDA Pro版本上测试
- [ ] 更新文档
- [ ] 创建发布说明
- [ ] 标记发布

## 🐛 调试

### 调试模式
在配置中启用调试日志记录：
```json
{
  "log_chain_of_thought": true,
  "debug": {
    "log_level": "DEBUG",
    "log_api_requests": true
  }
}
```

### 常见问题
- **导入错误**：检查Python路径和依赖项
- **API错误**：验证API密钥和网络连接
- **UI问题**：检查PyQt5安装和兼容性
- **性能**：监控内存使用和API速率限制

### 调试工具
- IDA Pro Python控制台
- 插件输出窗口
- 系统日志
- 网络监控工具

## 📋 拉取请求指南

### 提交前
- [ ] 代码遵循风格指南
- [ ] 所有测试通过
- [ ] 文档已更新
- [ ] 提交消息清晰
- [ ] 无合并冲突

### PR描述模板
```markdown
## 描述
更改的简要描述

## 更改类型
- [ ] 错误修复
- [ ] 新功能
- [ ] 破坏性更改
- [ ] 文档更新

## 测试
- [ ] 在IDA Pro X.X上测试
- [ ] 手动测试完成
- [ ] 未发现回归

## 截图（如适用）
为UI更改添加截图

## 附加说明
任何附加信息
```

### 审查流程
1. 自动检查运行
2. 维护者代码审查
3. 在不同环境中测试
4. 批准和合并

## 🏆 认可

贡献者将在以下位置得到认可：
- README_CN.md贡献者部分
- 发布说明
- GitHub贡献者页面

## 📞 获取帮助

- **问题**：使用 [GitHub讨论](https://github.com/your-repo/NexusAI/discussions)
- **问题**：使用 [GitHub Issues](https://github.com/your-repo/NexusAI/issues)
- **聊天**：加入我们的社区聊天（如果可用）

## 📄 许可证

通过贡献，您同意您的贡献将根据MIT许可证授权。

---

感谢您为NexusAI做贡献！🚀
