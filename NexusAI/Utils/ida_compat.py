"""
Cross-version compatibility helpers for IDA Pro SDK and Hex-Rays.

This module allows projects to be executed or unit-tested outside of IDA by
injecting lightweight stub modules when real SDK components are missing.

IDA Pro 多版本兼容工具，旨在在缺失 Hex-Rays 等组件的环境（如单元测试）中
通过向 ``sys.modules`` 注入存根模块来保证代码可运行。
"""
import sys
import types

# ---------------------------------------------------------------------------
# IDA SDK 版本检测
# ---------------------------------------------------------------------------

try:
    import idaapi  # pragma: no cover
    IDA_SDK_VERSION = getattr(idaapi, "IDA_SDK_VERSION", "unknown")
    IDA_VERSION = getattr(idaapi, "get_kernel_version", lambda: (0, 0))( )  # returns tuple
except ImportError:  # Running outside IDA (unit tests etc.)
    idaapi = None
    IDA_SDK_VERSION = "unknown"
    IDA_VERSION = (0, 0)


# ---------------------------------------------------------------------------
# 兼容导入辅助
# ---------------------------------------------------------------------------

def _create_stub(module_name: str, extra_attrs: dict | None = None):
    """Create and register an empty *stub* module inside ``sys.modules``.

    在 ``sys.modules`` 中创建并注册一个空的存根模块，避免导入错误。
    """
    stub = types.ModuleType(module_name)
    if extra_attrs:
        for key, value in extra_attrs.items():
            setattr(stub, key, value)
    sys.modules[module_name] = stub
    return stub


def ensure_module(module_name: str, extra_attrs: dict | None = None):
    """Attempt to import *module_name* and fall back to a stub if not present.

    尝试导入指定模块；如果失败则创建存根并返回，以保持接口一致。
    """
    try:
        return __import__(module_name)
    except ImportError:
        return _create_stub(module_name, extra_attrs)


# ---------------------------------------------------------------------------
# 处理 Hex-Rays 可能缺失的情况
# ---------------------------------------------------------------------------

# Hex-Rays 仅在安装反编译器且已授权时可用。
# 在 IDA 8.x/9.x 或无 Hex-Rays 环境下，导入可能失败。
ida_hexrays = ensure_module(
    "ida_hexrays",
    {"decompile": lambda ea: None, "__doc__": "Hex-Rays stub"},
)

# 将 stub 暴露为顶级名称，以便 `import ida_hexrays` 成功
globals()["ida_hexrays"] = ida_hexrays

__all__ = [
    "IDA_SDK_VERSION",
    "IDA_VERSION",
    "ida_hexrays",
    "ensure_module",
] 