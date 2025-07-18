# NexusAI Installation Guide

This guide provides detailed instructions for installing NexusAI using the new graphical installation wizard.

## 🖥️ Graphical Installation Wizard

The NexusAI installer now features a modern graphical interface that guides you through the installation process step by step.

### Features

- **Bilingual Support**: Choose between English and Chinese interface
- **Visual Directory Selection**: Browse and select IDA Pro installation directory
- **Automatic Detection**: Auto-detect IDA Pro installations on your system
- **Python Detection**: Automatically find Python installations including IDA Pro's bundled Python
- **Real-time Progress**: See installation progress with detailed logging
- **Validation**: Verify selections before proceeding with installation

### Step-by-Step Installation

#### Step 1: Launch the Installer

**Option A: Using Python directly**
```bash
python install.py
```

**Option B: Using platform scripts**
```bash
# Windows
install.bat

# Linux/macOS
./install.sh
```

#### Step 2: Language Selection

The installer will open with a language selection screen:
- Select **English** for English interface
- Select **中文** for Chinese interface
- Click **Next** to continue

#### Step 3: IDA Pro Directory Selection

- **Browse**: Click "Browse..." to manually select your IDA Pro installation directory
- **Auto Detect**: Click "Auto Detect" to automatically find IDA Pro installations
- The installer will validate your selection and show a green checkmark for valid directories

**Common IDA Pro Locations:**
- Windows: `C:\Program Files\IDA Pro 9.x\`
- macOS: `/Applications/IDA Pro 9.x/ida64.app/Contents/MacOS/`
- Linux: `/opt/ida-9.x/` or `/usr/local/ida/`

#### Step 4: Python Selection

The installer will detect available Python installations:

1. **System Python**: Your system's default Python installation
2. **IDA Pro Python**: Python bundled with IDA Pro (recommended)
3. **Custom Python**: Browse for a specific Python executable

**Recommendation**: Use IDA Pro's bundled Python if available, as it ensures compatibility.

#### Step 5: Installation Options

- **Development Mode**: Check this option if you're developing or modifying the plugin
  - Creates symbolic links instead of copying files
  - Allows real-time updates without reinstalling

#### Step 6: Installation Summary

Review your selections:
- IDA Pro Directory
- Python Path
- Installation Mode

Click **Next** to begin installation.

#### Step 7: Installation Progress

Watch the real-time installation progress:
- Dependency installation
- Plugin file copying/linking
- Configuration setup

The log window shows detailed information about each step.

#### Step 8: Completion

Upon successful installation:
- You'll see a success message
- Follow the next steps to configure NexusAI in IDA Pro

## 🖱️ Command Line Installation

For advanced users or automated installations:

### Quick Commands

```bash
# English interface, auto-detect IDA Pro
python install.py --lang en

# Chinese interface, specify IDA Pro directory
python install.py --lang zh --ida-dir "C:\Program Files\IDA Pro 9.1"

# Development mode with symbolic links
python install.py --dev

# Force command line interface
python install.py --cli
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `--lang en/zh` | Set interface language |
| `--ida-dir PATH` | Specify IDA Pro directory |
| `--dev` | Enable development mode (symbolic links) |
| `--cli` | Force command line interface |
| `--gui` | Force graphical interface (default) |

## 🔧 Troubleshooting

### GUI Won't Start

If the graphical installer fails to start:

1. **Check Python/Tkinter**: Ensure tkinter is installed
   ```bash
   python -c "import tkinter; print('Tkinter available')"
   ```

2. **Use Command Line**: Fall back to CLI mode
   ```bash
   python install.py --cli
   ```

3. **Check Dependencies**: Ensure all required packages are available

### IDA Pro Not Detected

If auto-detection fails:

1. **Manual Selection**: Use the "Browse..." button to manually select your IDA Pro directory
2. **Verify Installation**: Ensure IDA Pro is properly installed
3. **Check Permissions**: Ensure you have read access to the IDA Pro directory

### Python Issues

If Python detection fails:

1. **Check Python Installation**: Verify Python 3.8+ is installed
2. **Use Custom Path**: Select "Custom Python Path" and browse to your Python executable
3. **IDA Pro Python**: Look for Python in your IDA Pro installation directory (e.g., `IDA Pro 9.1\python312\python.exe`)

### Installation Fails

If installation fails:

1. **Check Permissions**: Ensure write access to IDA Pro plugins directory
2. **Close IDA Pro**: Make sure IDA Pro is not running during installation
3. **Check Disk Space**: Ensure sufficient disk space
4. **Review Logs**: Check the installation log for specific error messages

## 📁 Installation Locations

After installation, you'll find:

- **Plugin Entry Point**: `{IDA_DIR}\plugins\NexusAI.py`
- **Plugin Package**: `{IDA_DIR}\plugins\NexusAI\`
- **Configuration**: `{IDA_DIR}\plugins\NexusAI\Config\NexusAI.json`

## ✅ Verification

To verify successful installation:

1. **Start IDA Pro**
2. **Open any binary file**
3. **Check Menu**: Look for "NexusAI" in the Edit menu
4. **Test Hotkey**: Press `Ctrl+Shift+K` to open the NexusAI output window

## 🔄 Updating

To update NexusAI:

1. **Download Latest Version**: Get the latest release
2. **Run Installer**: The installer will detect and update existing installations
3. **Restart IDA Pro**: Restart to load the updated plugin

## 🗑️ Uninstallation

To uninstall NexusAI:

1. **Delete Plugin Files**:
   - Remove `{IDA_DIR}\plugins\NexusAI.py`
   - Remove `{IDA_DIR}\plugins\NexusAI\` directory

2. **Clean Configuration** (optional):
   - Remove configuration files if desired

---

For more help, see the main [README](README.md) or [open an issue](https://github.com/your-repo/NexusAI/issues).
