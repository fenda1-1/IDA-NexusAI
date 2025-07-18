# NexusAI Release Guide

本指南说明如何使用 GitHub Actions 创建多平台 release。

## 🚀 自动化构建系统

我们设置了两个 GitHub Actions 工作流：

### 1. 测试构建 (test-build.yml)
- **触发条件**: 推送到 main/develop 分支，或创建 PR
- **功能**: 测试在所有平台上的构建是否成功
- **输出**: 构建产物作为 artifacts 上传（仅用于测试）

### 2. 发布构建 (build-release.yml)
- **触发条件**: 推送版本标签 (如 v1.0.0) 或手动触发
- **功能**: 构建所有平台的可执行文件并创建 GitHub Release
- **输出**: 正式的 GitHub Release，包含所有平台的下载文件

## 📦 支持的平台

| 平台 | 文件名 | 说明 |
|------|--------|------|
| Windows | `NexusAI-Installer-GUI-windows.exe` | Windows 可执行文件 |
| macOS | `NexusAI-Installer-GUI-macos.app` | macOS 应用程序包 |
| Linux | `NexusAI-Installer-GUI-linux-x86_64` | Linux x86_64 二进制文件 |

## 🎯 如何创建 Release

### 方法 1: 使用 Git 标签 (推荐)

1. **确保代码已提交并推送到 main 分支**
   ```bash
   git add .
   git commit -m "准备发布 v1.2.0"
   git push origin main
   ```

2. **创建并推送版本标签**
   ```bash
   git tag v1.2.0
   git push origin v1.2.0
   ```

3. **等待自动构建完成**
   - GitHub Actions 会自动开始构建
   - 可以在 GitHub 的 Actions 页面查看进度
   - 构建完成后会自动创建 Release

### 方法 2: 手动触发

1. **访问 GitHub Actions 页面**
   - 进入您的仓库
   - 点击 "Actions" 标签
   - 选择 "Build Multi-Platform Release" 工作流

2. **手动运行工作流**
   - 点击 "Run workflow"
   - 输入标签名称 (如 v1.2.0)
   - 点击 "Run workflow"

## 🔍 监控构建过程

1. **查看构建状态**
   - 访问 GitHub Actions 页面
   - 查看正在运行的工作流

2. **构建矩阵**
   - Windows: 在 `windows-latest` 上构建
   - macOS: 在 `macos-latest` 上构建  
   - Linux: 在 `ubuntu-latest` 上构建

3. **构建步骤**
   - 检出代码
   - 设置 Python 环境
   - 安装依赖
   - 运行 `build_gui.py`
   - 验证构建输出
   - 上传构建产物

## 📋 Release 内容

每个 Release 包含：

- **发布说明**: 自动生成的版本信息和功能列表
- **下载文件**: 三个平台的可执行文件
- **安装说明**: 如何下载和使用

## 🛠️ 本地测试

在推送标签之前，可以本地测试构建：

```bash
# 测试当前平台的构建
python build_gui.py

# 检查生成的文件
ls -la NexusAI-Installer-GUI*
```

## ⚠️ 注意事项

1. **标签命名**: 使用语义化版本号 (如 v1.0.0, v2.1.3)
2. **构建时间**: 多平台构建大约需要 10-15 分钟
3. **文件大小**: 每个可执行文件约 10-15 MB
4. **权限**: 确保有仓库的写权限来创建 Release

## 🔧 故障排除

### 构建失败
- 检查 `requirements.txt` 是否包含所有依赖
- 确保 `build_gui.py` 在所有平台上都能正常运行
- 查看 Actions 日志了解具体错误

### Release 创建失败
- 确保标签名称唯一
- 检查是否有足够的仓库权限
- 验证 GITHUB_TOKEN 权限

### 文件上传失败
- 检查文件路径是否正确
- 确保构建产物确实生成了
- 查看文件大小是否超过限制

## 📞 获取帮助

如果遇到问题：
1. 查看 GitHub Actions 的详细日志
2. 检查本地构建是否成功
3. 确认所有依赖都已正确安装
