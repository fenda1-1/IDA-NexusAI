# Contributing to NexusAI

Thank you for your interest in contributing to NexusAI! This document provides guidelines and information for contributors.

## 🤝 How to Contribute

### Reporting Issues
- Use the [GitHub Issues](https://github.com/fenda1-1/IDA-NexusAI/issues) page
- Search existing issues before creating a new one
- Provide detailed information including:
  - IDA Pro version
  - Python version
  - Operating system
  - Steps to reproduce
  - Expected vs actual behavior
  - Error messages or logs

### Suggesting Features
- Open a [GitHub Discussion](https://github.com/fenda1-1/IDA-NexusAI/discussions)
- Describe the feature and its use case
- Explain how it would benefit users
- Consider implementation complexity

### Code Contributions
1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/amazing-feature`
3. **Make** your changes
4. **Test** thoroughly
5. **Commit** with clear messages: `git commit -m 'Add amazing feature'`
6. **Push** to your branch: `git push origin feature/amazing-feature`
7. **Open** a Pull Request

## 🏗️ Development Setup

### Prerequisites
- IDA Pro 7.x, 8.x, or 9.x
- Python 3.8+
- Git

### Environment Setup
```bash
# Clone your fork
git clone https://github.com/your-username/NexusAI.git
cd NexusAI

# Install development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # If available

# Install in development mode
python install.py --dev --ida-dir /path/to/ida
```

### Project Structure
```
NexusAI/
├── NexusAI.py              # Plugin entry point
├── NexusAI/                # Main plugin package
│   ├── __init__.py
│   ├── Core/               # Core functionality
│   │   ├── plugin.py       # Main plugin class
│   │   ├── task_controller.py
│   │   ├── mcp_controller.py
│   │   └── ...
│   ├── AIService/          # AI service providers
│   │   ├── base_service.py
│   │   ├── openai_service.py
│   │   └── ...
│   ├── UI/                 # User interface
│   │   └── ui_view.py
│   ├── Utils/              # Utilities
│   │   ├── code_extractor.py
│   │   ├── comment_applicator.py
│   │   └── ...
│   ├── Config/             # Configuration
│   │   ├── config.py
│   │   └── NexusAI.json
│   └── extensions/         # Plugin extensions
│       ├── graph_export_extension/
│       └── flattening_detection_extension/
├── requirements.txt        # Python dependencies
├── install.py             # Installation script
├── README.md              # Main documentation
└── docs/                  # Additional documentation
```

## 📝 Coding Standards

### Python Style
- Follow [PEP 8](https://pep8.org/) style guide
- Use type hints where appropriate
- Maximum line length: 100 characters
- Use meaningful variable and function names

### Code Quality
- Write docstrings for all public functions and classes
- Add comments for complex logic
- Handle exceptions appropriately
- Avoid hardcoded values

### Example Code Style
```python
"""Module docstring describing the purpose."""

from typing import Optional, List
import idaapi


class ExampleClass:
    """Class docstring explaining the purpose and usage."""
    
    def __init__(self, config_manager: ConfigManager):
        """Initialize the class with configuration manager.
        
        Args:
            config_manager: Configuration manager instance
        """
        self.config = config_manager
        self._private_var = None
    
    def public_method(self, param: str) -> Optional[str]:
        """Public method with clear documentation.
        
        Args:
            param: Description of the parameter
            
        Returns:
            Description of return value or None if failed
            
        Raises:
            ValueError: When param is invalid
        """
        if not param:
            raise ValueError("Parameter cannot be empty")
        
        try:
            # Process the parameter
            result = self._process_param(param)
            return result
        except Exception as e:
            self.config.show_message("error_occurred", str(e))
            return None
    
    def _process_param(self, param: str) -> str:
        """Private method for internal processing."""
        return param.upper()
```

## 🧪 Testing

### Manual Testing
- Test with different IDA Pro versions
- Test with various binary types (PE, ELF, Mach-O)
- Test different AI models and providers
- Verify UI responsiveness and error handling

### Test Checklist
- [ ] Plugin loads without errors
- [ ] All menu items and hotkeys work
- [ ] AI analysis produces reasonable results
- [ ] Configuration changes persist
- [ ] Error messages are helpful
- [ ] No memory leaks or crashes

### Testing Environment
Create test cases for:
- Different architectures (x86, x64, ARM)
- Various file formats
- Edge cases (empty functions, large binaries)
- Network issues (timeouts, proxy errors)
- Invalid configurations

## 📚 Documentation

### Code Documentation
- Use clear, descriptive docstrings
- Document parameters, return values, and exceptions
- Include usage examples for complex functions
- Keep documentation up to date with code changes

### User Documentation
- Update README.md for new features
- Add configuration examples
- Include troubleshooting information
- Provide clear installation instructions

## 🔧 Extension Development

### Creating Extensions
Extensions should follow this structure:
```python
# extensions/my_extension/my_extension.py

def init_extension():
    """Initialize the extension."""
    # Register actions, hooks, etc.
    pass

def deinit_extension():
    """Clean up the extension."""
    # Unregister actions, clean up resources
    pass

class MyExtensionAction(idaapi.action_handler_t):
    """Extension action handler."""
    
    def activate(self, ctx):
        # Implementation
        return 1
    
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
```

### Extension Guidelines
- Keep extensions focused on specific functionality
- Use the event bus for communication
- Handle errors gracefully
- Provide configuration options
- Include documentation and examples

## 🚀 Release Process

### Version Numbering
- Follow [Semantic Versioning](https://semver.org/)
- Format: MAJOR.MINOR.PATCH
- Update version in `NexusAI/__init__.py`

### Release Checklist
- [ ] Update version number
- [ ] Update CHANGELOG.md
- [ ] Test on multiple IDA Pro versions
- [ ] Update documentation
- [ ] Create release notes
- [ ] Tag the release

## 🐛 Debugging

### Debug Mode
Enable debug logging in configuration:
```json
{
  "log_chain_of_thought": true,
  "debug": {
    "log_level": "DEBUG",
    "log_api_requests": true
  }
}
```

### Common Issues
- **Import errors**: Check Python path and dependencies
- **API errors**: Verify API keys and network connectivity
- **UI issues**: Check PyQt5 installation and compatibility
- **Performance**: Monitor memory usage and API rate limits

### Debugging Tools
- IDA Pro Python console
- Plugin output window
- System logs
- Network monitoring tools

## 📋 Pull Request Guidelines

### Before Submitting
- [ ] Code follows style guidelines
- [ ] All tests pass
- [ ] Documentation is updated
- [ ] Commit messages are clear
- [ ] No merge conflicts

### PR Description Template
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Tested on IDA Pro X.X
- [ ] Manual testing completed
- [ ] No regressions found

## Screenshots (if applicable)
Add screenshots for UI changes

## Additional Notes
Any additional information
```

### Review Process
1. Automated checks run
2. Code review by maintainers
3. Testing on different environments
4. Approval and merge

## 🏆 Recognition

Contributors will be recognized in:
- README.md contributors section
- Release notes
- GitHub contributors page

## 📞 Getting Help

- **Questions**: Use [GitHub Discussions](https://github.com/fenda1-1/IDA-NexusAI/discussions)
- **Issues**: Use [GitHub Issues](https://github.com/fenda1-1/IDA-NexusAI/issues)
- **Chat**: Join our community chat (if available)

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to NexusAI! 🚀
