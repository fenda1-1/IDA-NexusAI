#!/usr/bin/env python3
"""
NexusAI Installation Script / NexusAI 安装脚本
============================================

This script automates the installation of NexusAI plugin for IDA Pro.
It handles dependency installation, plugin file copying, and configuration setup.

此脚本自动化NexusAI插件的IDA Pro安装。
它处理依赖安装、插件文件复制和配置设置。

Usage / 使用方法:
    python install.py [--ida-dir IDA_DIRECTORY] [--lang LANGUAGE]

Options / 选项:
    --ida-dir    Specify IDA Pro installation directory / 指定IDA Pro安装目录
    --lang       Language preference (en/zh) / 语言偏好 (en/zh)
    --help       Show this help message / 显示帮助信息
"""

import os
import sys
import shutil
import subprocess
import argparse
from pathlib import Path
import platform
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import tempfile
import zipfile


class InstallationWizard:
    """Graphical installation wizard for NexusAI."""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("NexusAI Installation Wizard")
        self.root.geometry("600x500")
        self.root.resizable(False, False)

        # Center the window
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (600 // 2)
        y = (self.root.winfo_screenheight() // 2) - (500 // 2)
        self.root.geometry(f"600x500+{x}+{y}")

        self.language = None
        self.ida_dir = None
        self.python_path = None

        self.current_step = 0
        self.steps = []

        self.setup_ui()

    def setup_ui(self):
        """Setup the main UI."""
        # Main frame
        self.main_frame = ttk.Frame(self.root, padding="20")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        self.title_label = ttk.Label(
            self.main_frame,
            text="NexusAI Installation Wizard",
            font=("Arial", 16, "bold")
        )
        self.title_label.pack(pady=(0, 20))

        # Content frame
        self.content_frame = ttk.Frame(self.main_frame)
        self.content_frame.pack(fill=tk.BOTH, expand=True)

        # Button frame
        self.button_frame = ttk.Frame(self.main_frame)
        self.button_frame.pack(fill=tk.X, pady=(20, 0))

        # Buttons
        self.back_button = ttk.Button(
            self.button_frame,
            text="Back",
            command=self.go_back,
            state=tk.DISABLED
        )
        self.back_button.pack(side=tk.LEFT)

        self.next_button = ttk.Button(
            self.button_frame,
            text="Next",
            command=self.go_next
        )
        self.next_button.pack(side=tk.RIGHT)

        self.cancel_button = ttk.Button(
            self.button_frame,
            text="Cancel",
            command=self.cancel_installation
        )
        self.cancel_button.pack(side=tk.RIGHT, padx=(0, 10))

        # Initialize steps
        self.init_steps()
        self.show_current_step()

    def init_steps(self):
        """Initialize installation steps."""
        self.steps = [
            self.step_language_selection,
            self.step_ida_directory,
            self.step_python_selection,
            self.step_installation_options,
            self.step_installation_progress,
            self.step_completion
        ]

    def show_current_step(self):
        """Show the current installation step."""
        # Clear content frame
        for widget in self.content_frame.winfo_children():
            widget.destroy()

        # Show current step
        if 0 <= self.current_step < len(self.steps):
            self.steps[self.current_step]()

        # Update button states
        self.back_button.config(state=tk.NORMAL if self.current_step > 0 else tk.DISABLED)

        if self.current_step == len(self.steps) - 1:
            self.next_button.config(text="Finish", command=self.finish_installation)
        elif self.current_step == len(self.steps) - 2:  # Installation progress step
            self.next_button.config(state=tk.DISABLED)
        else:
            self.next_button.config(text="Next", command=self.go_next, state=tk.NORMAL)

    def step_language_selection(self):
        """Step 1: Language selection."""
        ttk.Label(
            self.content_frame,
            text="Please select your language / 请选择您的语言:",
            font=("Arial", 12)
        ).pack(pady=(20, 10))

        self.language_var = tk.StringVar(value="en")

        ttk.Radiobutton(
            self.content_frame,
            text="English",
            variable=self.language_var,
            value="en"
        ).pack(pady=5, anchor=tk.W, padx=50)

        ttk.Radiobutton(
            self.content_frame,
            text="中文",
            variable=self.language_var,
            value="zh"
        ).pack(pady=5, anchor=tk.W, padx=50)

    def step_ida_directory(self):
        """Step 2: IDA Pro directory selection."""
        messages = self.get_messages()

        ttk.Label(
            self.content_frame,
            text=messages.get('select_ida_dir', "Select IDA Pro Installation Directory:"),
            font=("Arial", 12)
        ).pack(pady=(20, 10))

        # Directory selection frame
        dir_frame = ttk.Frame(self.content_frame)
        dir_frame.pack(fill=tk.X, padx=20, pady=10)

        self.ida_dir_var = tk.StringVar()
        ida_entry = ttk.Entry(dir_frame, textvariable=self.ida_dir_var, width=50)
        ida_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        ttk.Button(
            dir_frame,
            text=messages.get('browse', "Browse..."),
            command=self.browse_ida_directory
        ).pack(side=tk.RIGHT, padx=(10, 0))

        # Auto-detect button
        ttk.Button(
            self.content_frame,
            text=messages.get('auto_detect', "Auto Detect"),
            command=self.auto_detect_ida
        ).pack(pady=10)

        # Status label
        self.ida_status_label = ttk.Label(self.content_frame, text="", foreground="gray")
        self.ida_status_label.pack(pady=5)

    def step_python_selection(self):
        """Step 3: Python selection."""
        messages = self.get_messages()

        ttk.Label(
            self.content_frame,
            text=messages.get('select_python', "Select Python Installation:"),
            font=("Arial", 12)
        ).pack(pady=(20, 10))

        # Loading message
        self.python_loading_label = ttk.Label(
            self.content_frame,
            text=messages.get('scanning_python', "正在检测Python安装..."),
            foreground="blue"
        )
        self.python_loading_label.pack(pady=10)

        # Python options frame
        self.python_frame = ttk.Frame(self.content_frame)
        self.python_frame.pack(fill=tk.BOTH, expand=True, padx=20)

        self.python_var = tk.StringVar()

        # Custom path option (always available)
        custom_frame = ttk.Frame(self.python_frame)
        custom_frame.pack(fill=tk.X, pady=(10, 0))

        ttk.Radiobutton(
            custom_frame,
            text=messages.get('custom_python', "Custom Python Path:"),
            variable=self.python_var,
            value="custom"
        ).pack(anchor=tk.W)

        custom_path_frame = ttk.Frame(custom_frame)
        custom_path_frame.pack(fill=tk.X, padx=20, pady=5)

        self.custom_python_var = tk.StringVar()
        custom_entry = ttk.Entry(custom_path_frame, textvariable=self.custom_python_var, width=40)
        custom_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        ttk.Button(
            custom_path_frame,
            text=messages.get('browse', "Browse..."),
            command=self.browse_python_path
        ).pack(side=tk.RIGHT, padx=(10, 0))

        # Start Python detection in background
        self.start_python_detection_async()

    def start_python_detection_async(self):
        """Start Python detection in background thread to avoid UI freezing."""
        def detect_in_background():
            try:
                python_options = self.detect_python_installations()
                # Update UI from main thread
                self.root.after(0, lambda: self.update_python_options_ui(python_options))
            except Exception as e:
                # Handle errors in main thread
                self.root.after(0, lambda: self.handle_python_detection_error_ui(str(e)))

        # Start detection in background thread
        import threading
        detection_thread = threading.Thread(target=detect_in_background)
        detection_thread.daemon = True
        detection_thread.start()

    def update_python_options_ui(self, python_options):
        """Update Python options in the UI (called from main thread)."""
        # Hide loading message
        if hasattr(self, 'python_loading_label'):
            self.python_loading_label.pack_forget()

        # Create options frame for detected pythons
        options_frame = ttk.Frame(self.python_frame)
        options_frame.pack(fill=tk.X, pady=(0, 10))

        # Add Python options
        for i, (path, description) in enumerate(python_options):
            ttk.Radiobutton(
                options_frame,
                text=description,
                variable=self.python_var,
                value=path
            ).pack(pady=5, anchor=tk.W)

            if i == 0:  # Select first option by default
                self.python_var.set(path)

    def handle_python_detection_error_ui(self, error_message):
        """Handle Python detection errors (called from main thread)."""
        # Hide loading message
        if hasattr(self, 'python_loading_label'):
            self.python_loading_label.pack_forget()

        # Show error message
        error_label = ttk.Label(
            self.python_frame,
            text=f"Python检测失败: {error_message}",
            foreground="red"
        )
        error_label.pack(pady=10)

        # Add fallback option
        fallback_name = f"Default Python\n    Path: {sys.executable}"
        ttk.Radiobutton(
            self.python_frame,
            text=fallback_name,
            variable=self.python_var,
            value=sys.executable
        ).pack(pady=5, anchor=tk.W)
        self.python_var.set(sys.executable)

    def step_installation_options(self):
        """Step 4: Installation options."""
        messages = self.get_messages()

        ttk.Label(
            self.content_frame,
            text=messages.get('installation_options', "Installation Options:"),
            font=("Arial", 12)
        ).pack(pady=(20, 10))

        # Summary frame
        summary_frame = ttk.LabelFrame(self.content_frame, text=messages.get('summary', "Summary"), padding=10)
        summary_frame.pack(fill=tk.X, padx=20, pady=20)

        # Summary content
        ida_dir = self.ida_dir_var.get() if hasattr(self, 'ida_dir_var') else "Not selected"
        python_path = self.get_selected_python_path()

        ttk.Label(summary_frame, text=f"IDA Pro Directory: {ida_dir}").pack(anchor=tk.W)
        ttk.Label(summary_frame, text=f"Python Path: {python_path}").pack(anchor=tk.W)

    def step_installation_progress(self):
        """Step 5: Installation progress."""
        messages = self.get_messages()

        ttk.Label(
            self.content_frame,
            text=messages.get('installing', "Installing NexusAI..."),
            font=("Arial", 12)
        ).pack(pady=(20, 10))

        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            self.content_frame,
            variable=self.progress_var,
            maximum=100,
            length=400
        )
        self.progress_bar.pack(pady=20)

        # Status label
        self.status_label = ttk.Label(self.content_frame, text="")
        self.status_label.pack(pady=10)

        # Log text
        log_frame = ttk.LabelFrame(self.content_frame, text=messages.get('log', "Installation Log"), padding=5)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        self.log_text = tk.Text(log_frame, height=10, wrap=tk.WORD)
        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)

        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Start installation in background thread
        self.installation_thread = threading.Thread(target=self.run_installation_process)
        self.installation_thread.daemon = True
        self.installation_thread.start()

    def step_completion(self):
        """Step 6: Installation completion."""
        messages = self.get_messages()

        if hasattr(self, 'installation_success') and self.installation_success:
            # Success
            ttk.Label(
                self.content_frame,
                text=messages.get('install_success', "Installation completed successfully!"),
                font=("Arial", 14, "bold"),
                foreground="green"
            ).pack(pady=(20, 10))

            # Next steps
            steps_frame = ttk.LabelFrame(self.content_frame, text=messages.get('next_steps', "Next Steps"), padding=10)
            steps_frame.pack(fill=tk.X, padx=20, pady=20)

            steps = [
                messages.get('step1', "1. Restart IDA Pro"),
                messages.get('step2', "2. Open any binary file"),
                messages.get('step3', "3. Go to Edit → NexusAI → Settings to configure your API key"),
                messages.get('step4', "4. Press Ctrl+Shift+K to open the NexusAI output window")
            ]

            for step in steps:
                ttk.Label(steps_frame, text=step).pack(anchor=tk.W, pady=2)
        else:
            # Failure
            ttk.Label(
                self.content_frame,
                text=messages.get('install_failed', "Installation failed!"),
                font=("Arial", 14, "bold"),
                foreground="red"
            ).pack(pady=(20, 10))

            if hasattr(self, 'installation_error'):
                ttk.Label(
                    self.content_frame,
                    text=f"Error: {self.installation_error}",
                    foreground="red"
                ).pack(pady=10)

    def get_messages(self):
        """Get localized messages."""
        if not hasattr(self, 'language') or not self.language:
            return {}

        messages = {
            'en': {
                'select_ida_dir': "Select IDA Pro Installation Directory:",
                'browse': "Browse...",
                'auto_detect': "Auto Detect",
                'scanning_drives': "Scanning drives for IDA Pro installations...",
                'ida_not_found': "IDA Pro not found automatically",
                'select_python': "Select Python Installation:",
                'scanning_python': "Detecting Python installations...",
                'custom_python': "Custom Python Path:",
                'installation_options': "Installation Options:",
                'summary': "Summary",
                'installing': "Installing NexusAI...",
                'log': "Installation Log",
                'install_success': "Installation completed successfully!",
                'install_failed': "Installation failed!",
                'next_steps': "Next Steps:",
                'step1': "1. Restart IDA Pro",
                'step2': "2. Open any binary file",
                'step3': "3. Go to Edit → NexusAI → Settings to configure your API key",
                'step4': "4. Press Ctrl+Shift+K to open the NexusAI output window"
            },
            'zh': {
                'select_ida_dir': "选择IDA Pro安装目录:",
                'browse': "浏览...",
                'auto_detect': "自动检测",
                'scanning_drives': "正在扫描磁盘查找IDA Pro安装...",
                'ida_not_found': "未自动找到IDA Pro",
                'select_python': "选择Python安装:",
                'scanning_python': "正在检测Python安装...",
                'custom_python': "自定义Python路径:",
                'installation_options': "安装选项:",
                'summary': "摘要",
                'installing': "正在安装NexusAI...",
                'log': "安装日志",
                'install_success': "安装成功完成！",
                'install_failed': "安装失败！",
                'next_steps': "下一步:",
                'step1': "1. 重启IDA Pro",
                'step2': "2. 打开任何二进制文件",
                'step3': "3. 转到 编辑 → NexusAI → 设置 配置您的API密钥",
                'step4': "4. 按Ctrl+Shift+K打开NexusAI输出窗口"
            }
        }
        return messages.get(self.language, messages['en'])

    def browse_ida_directory(self):
        """Browse for IDA Pro directory."""
        directory = filedialog.askdirectory(
            title="Select IDA Pro Installation Directory"
        )
        if directory:
            self.ida_dir_var.set(directory)
            self.validate_ida_directory(directory)

    def auto_detect_ida(self):
        """Auto-detect IDA Pro installation with progress indication."""
        messages = self.get_messages()

        # Show scanning status
        self.ida_status_label.config(
            text=messages.get('scanning_drives', "Scanning drives for IDA Pro..."),
            foreground="blue"
        )
        self.root.update()  # Update UI to show scanning message

        # Run detection in background to avoid freezing UI
        def detect_in_background():
            installer = NexusAIInstaller(self.language)
            ida_dirs = installer._get_default_ida_dirs()

            # Find first existing directory
            for ida_dir in ida_dirs:
                if ida_dir.exists():
                    # Update UI from main thread
                    self.root.after(0, lambda: self._on_ida_found(str(ida_dir)))
                    return

            # No IDA found
            self.root.after(0, lambda: self._on_ida_not_found())

        # Start detection in background thread
        import threading
        detection_thread = threading.Thread(target=detect_in_background)
        detection_thread.daemon = True
        detection_thread.start()

    def _on_ida_found(self, ida_dir):
        """Called when IDA Pro is found."""
        self.ida_dir_var.set(ida_dir)
        self.validate_ida_directory(ida_dir)

    def _on_ida_not_found(self):
        """Called when IDA Pro is not found."""
        messages = self.get_messages()
        self.ida_status_label.config(
            text=messages.get('ida_not_found', "IDA Pro not found automatically"),
            foreground="red"
        )

    def validate_ida_directory(self, directory):
        """Validate IDA Pro directory."""
        ida_path = Path(directory)
        if ida_path.exists() and ((ida_path / "ida64.exe").exists() or (ida_path / "ida.exe").exists() or (ida_path / "ida64").exists()):
            self.ida_status_label.config(text="✅ Valid IDA Pro directory", foreground="green")
            return True
        else:
            self.ida_status_label.config(text="❌ Invalid IDA Pro directory", foreground="red")
            return False

    def detect_python_installations(self):
        """Detect available Python installations using comprehensive search."""
        python_options = []

        # Create installer instance for Python detection
        installer = NexusAIInstaller(self.language)

        # Get all Python installations
        all_pythons = installer.find_all_python_installations()

        # Check for IDA Pro Python if IDA directory is selected
        ida_pythons = []
        if hasattr(self, 'ida_dir_var') and self.ida_dir_var.get():
            ida_dir = Path(self.ida_dir_var.get())
            ida_pythons = self._find_ida_pro_pythons(ida_dir)

        # Create a set to track unique paths and avoid duplicates
        seen_paths = set()
        final_pythons = []

        # Add IDA Pro pythons first (highest priority)
        for ida_python in ida_pythons:
            if ida_python['path'] not in seen_paths:
                seen_paths.add(ida_python['path'])
                final_pythons.append(ida_python)

        # Add other pythons if they're not already added
        for python_info in all_pythons:
            if python_info['path'] not in seen_paths:
                seen_paths.add(python_info['path'])
                final_pythons.append(python_info)

        # Convert to format expected by GUI with better display
        for python_info in final_pythons:
            # Create a more informative display name with path
            display_name = f"{python_info['name']}\n    Path: {python_info['path']}"
            python_options.append((python_info['path'], display_name))

        # Fallback if no Python found
        if not python_options:
            fallback_name = f"Default Python\n    Path: {sys.executable}"
            python_options.append((sys.executable, fallback_name))

        return python_options

    def _find_ida_pro_pythons(self, ida_dir):
        """Find Python installations within IDA Pro directory."""
        ida_pythons = []

        if not ida_dir.exists():
            return ida_pythons

        try:
            # Look for Python directories in IDA Pro directory
            # Common patterns: python, python3, python312, python311, etc.
            python_patterns = ['python*', 'Python*']

            for pattern in python_patterns:
                for python_dir in ida_dir.glob(pattern):
                    if python_dir.is_dir():
                        # Look for python.exe in this directory
                        python_exe = python_dir / "python.exe"
                        if python_exe.exists():
                            # Validate this is a working Python
                            installer = NexusAIInstaller(self.language)
                            if installer._validate_python(python_exe):
                                version = installer._get_python_version(python_exe)
                                ida_pythons.append({
                                    'name': f'IDA Pro Python {version} ({python_dir.name})',
                                    'path': str(python_exe),
                                    'type': 'ida'
                                })

        except (PermissionError, OSError):
            # Skip if we can't access the directory
            pass

        return ida_pythons

    def browse_python_path(self):
        """Browse for Python executable."""
        if platform.system().lower() == "windows":
            filetypes = [("Python Executable", "python.exe"), ("All Files", "*.*")]
        else:
            filetypes = [("Python Executable", "python*"), ("All Files", "*")]

        filename = filedialog.askopenfilename(
            title="Select Python Executable",
            filetypes=filetypes
        )
        if filename:
            self.custom_python_var.set(filename)
            self.python_var.set("custom")

    def get_selected_python_path(self):
        """Get the selected Python path."""
        if hasattr(self, 'python_var'):
            selected = self.python_var.get()
            if selected == "custom":
                return self.custom_python_var.get() if hasattr(self, 'custom_python_var') else ""
            return selected
        return sys.executable

    def go_next(self):
        """Go to next step."""
        # Validate current step
        if self.current_step == 0:  # Language selection
            self.language = self.language_var.get()
        elif self.current_step == 1:  # IDA directory
            if not self.ida_dir_var.get() or not self.validate_ida_directory(self.ida_dir_var.get()):
                messagebox.showerror("Error", "Please select a valid IDA Pro directory")
                return
            self.ida_dir = self.ida_dir_var.get()
        elif self.current_step == 2:  # Python selection
            python_path = self.get_selected_python_path()
            if not python_path or not Path(python_path).exists():
                messagebox.showerror("Error", "Please select a valid Python installation")
                return
            self.python_path = python_path

        self.current_step += 1
        self.show_current_step()

    def go_back(self):
        """Go to previous step."""
        if self.current_step > 0:
            self.current_step -= 1
            self.show_current_step()

    def cancel_installation(self):
        """Cancel installation."""
        if messagebox.askquestion("Cancel", "Are you sure you want to cancel the installation?") == "yes":
            self.root.quit()

    def finish_installation(self):
        """Finish installation."""
        self.root.quit()

    def run_installation_process(self):
        """Run the actual installation process in background."""
        try:
            self.installation_success = False

            # Update progress
            self.root.after(0, lambda: self.update_progress(10, "Initializing..."))

            # Create installer
            installer = NexusAIInstaller(self.language)

            # Install dependencies (silent mode for GUI)
            self.root.after(0, lambda: self.update_progress(30, "Installing dependencies..."))
            installer.install_dependencies(Path(self.python_path), silent=True)

            # Install plugin files
            self.root.after(0, lambda: self.update_progress(70, "Installing plugin files..."))
            success = installer.install_plugin_files(Path(self.ida_dir))

            if success:
                # Create config
                self.root.after(0, lambda: self.update_progress(90, "Creating configuration..."))
                installer.create_config_template(Path(self.ida_dir))

                self.root.after(0, lambda: self.update_progress(100, "Installation completed!"))
                self.installation_success = True
            else:
                self.installation_error = "Failed to install plugin files"

        except Exception as e:
            self.installation_error = str(e)

        # Move to completion step
        self.root.after(1000, lambda: self.go_to_completion())

    def update_progress(self, value, status):
        """Update progress bar and status."""
        self.progress_var.set(value)
        self.status_label.config(text=status)
        self.log_text.insert(tk.END, f"{status}\n")
        self.log_text.see(tk.END)

    def go_to_completion(self):
        """Go to completion step."""
        self.current_step = len(self.steps) - 1
        self.show_current_step()
        self.next_button.config(state=tk.NORMAL)

    def run(self):
        """Run the installation wizard."""
        self.root.mainloop()


class NexusAIInstaller:
    def __init__(self, language='en'):
        # Handle PyInstaller bundled executable path
        if getattr(sys, 'frozen', False):
            # Running as compiled executable
            self.script_dir = Path(sys.executable).parent.absolute()
            self.is_bundled = True
        else:
            # Running as Python script
            self.script_dir = Path(__file__).parent.absolute()
            self.is_bundled = False

        self.system = platform.system().lower()
        self.ida_dirs = self._get_default_ida_dirs()
        self.language = language
        self.messages = self._get_messages()
        self.temp_dir = None

    def _get_messages(self):
        """Get localized messages based on language preference."""
        messages = {
            'en': {
                'title': "NexusAI Installation Script",
                'searching_ida': "🔍 Searching for IDA Pro installation...",
                'found_ida': "✅ Found IDA Pro at: {}",
                'ida_not_found': "❌ Could not find IDA Pro installation automatically.",
                'specify_ida_dir': "Please specify the IDA Pro directory using --ida-dir option.",
                'python_found': "✅ Python found: {}",
                'python_not_found': "❌ ERROR: Python is not installed or not in PATH",
                'python_version_error': "❌ ERROR: Python {} found, but Python {} or higher is required",
                'install_python': "Please install Python 3.8+ and try again",
                'installing_deps': "📦 Installing Python dependencies...",
                'installing_package': "   Installing {}...",
                'package_success': "   ✅ {} installed successfully",
                'package_warning': "   ⚠️  Warning: Failed to install {}",
                'manual_install': "      You may need to install it manually: {} -m pip install {}",
                'deps_complete': "✅ Dependencies installation completed.",
                'running_installer': "🚀 Running NexusAI installer...",
                'installing_files': "📁 Installing plugin files...",
                'copying_files': "   Copying plugin files...",
                'files_success': "   ✅ Plugin files copied successfully",
                'files_error': "   ❌ Failed to install plugin files: {}",
                'config_exists': "   ℹ️  Configuration file already exists",
                'config_template': "   📝 Creating configuration template...",
                'config_success': "   ✅ Configuration will be created on first run",
                'install_success': "✅ Installation completed successfully!",
                'next_steps': "📋 Next steps:",
                'step1': "1. Restart IDA Pro",
                'step2': "2. Open any binary file",
                'step3': "3. Go to Edit → NexusAI → Settings to configure your API key",
                'step4': "4. Press Ctrl+Shift+K to open the NexusAI output window",
                'happy_reversing': "🎉 Happy reverse engineering with AI!",
                'install_failed': "❌ Installation failed. Please check the error messages above.",
                'manual_install_guide': "You can also try manual installation following the README.md"
            },
            'zh': {
                'title': "NexusAI 安装脚本",
                'searching_ida': "🔍 正在搜索IDA Pro安装...",
                'found_ida': "✅ 找到IDA Pro: {}",
                'ida_not_found': "❌ 无法自动找到IDA Pro安装。",
                'specify_ida_dir': "请使用--ida-dir选项指定IDA Pro目录。",
                'python_found': "✅ 找到Python: {}",
                'python_not_found': "❌ 错误: Python未安装或不在PATH中",
                'python_version_error': "❌ 错误: 找到Python {}，但需要Python {}或更高版本",
                'install_python': "请安装Python 3.8+后重试",
                'installing_deps': "📦 正在安装Python依赖...",
                'installing_package': "   正在安装 {}...",
                'package_success': "   ✅ {} 安装成功",
                'package_warning': "   ⚠️  警告: 安装 {} 失败",
                'manual_install': "      您可能需要手动安装: {} -m pip install {}",
                'deps_complete': "✅ 依赖安装完成。",
                'running_installer': "🚀 正在运行NexusAI安装程序...",
                'installing_files': "📁 正在安装插件文件...",
                'copying_files': "   正在复制插件文件...",
                'files_success': "   ✅插件文件复制成功",
                'files_error': "   ❌ 安装插件文件失败: {}",
                'config_exists': "   ℹ️  配置文件已存在",
                'config_template': "   📝 正在创建配置模板...",
                'config_success': "   ✅ 配置将在首次运行时创建",
                'install_success': "✅ 安装成功完成！",
                'next_steps': "📋 下一步:",
                'step1': "1. 重启IDA Pro",
                'step2': "2. 打开任何二进制文件",
                'step3': "3. 转到 编辑 → NexusAI → 设置 配置您的API密钥",
                'step4': "4. 按Ctrl+Shift+K打开NexusAI输出窗口",
                'happy_reversing': "🎉 用AI愉快地进行逆向工程！",
                'install_failed': "❌ 安装失败。请检查上面的错误消息。",
                'manual_install_guide': "您也可以尝试按照README.md进行手动安装"
            }
        }
        return messages.get(self.language, messages['en'])

    def _get_default_ida_dirs(self):
        """Get default IDA Pro installation directories for different platforms."""
        # First try common default locations
        default_dirs = []

        if self.system == "windows":
            default_dirs = [
                Path("C:/Program Files/IDA Pro 9.1"),
                Path("C:/Program Files/IDA Pro 9.0"),
                Path("C:/Program Files/IDA Pro 8.4"),
                Path("C:/Program Files/IDA Pro 8.3"),
                Path("C:/Program Files/IDA Pro 8.2"),
                Path("C:/Program Files/IDA Pro 8.1"),
                Path("C:/Program Files/IDA Pro 8.0"),
                Path("C:/Program Files/IDA Pro 7.7"),
                Path("C:/Program Files/IDA Pro 7.6"),
                Path("C:/Program Files/IDA Pro 7.5"),
                Path("C:/Program Files (x86)/IDA Pro 9.1"),
                Path("C:/Program Files (x86)/IDA Pro 9.0"),
                Path("C:/Program Files (x86)/IDA Pro 8.4"),
                Path("C:/Program Files (x86)/IDA Pro 8.3"),
            ]
        elif self.system == "darwin":  # macOS
            default_dirs = [
                Path("/Applications/IDA Pro 9.1/ida64.app/Contents/MacOS"),
                Path("/Applications/IDA Pro 9.0/ida64.app/Contents/MacOS"),
                Path("/Applications/IDA Pro 8.4/ida64.app/Contents/MacOS"),
                Path("/Applications/IDA Pro 8.3/ida64.app/Contents/MacOS"),
                Path("/Applications/IDA Pro 8.2/ida64.app/Contents/MacOS"),
                Path("/Applications/IDA Pro 8.1/ida64.app/Contents/MacOS"),
                Path("/Applications/IDA Pro 8.0/ida64.app/Contents/MacOS"),
                Path("/Applications/IDA Pro 7.7/ida64.app/Contents/MacOS"),
            ]
        else:  # Linux
            default_dirs = [
                Path("/opt/ida-9.1"),
                Path("/opt/ida-9.0"),
                Path("/opt/ida-8.4"),
                Path("/opt/ida-8.3"),
                Path("/opt/ida-8.2"),
                Path("/opt/ida-8.1"),
                Path("/opt/ida-8.0"),
                Path("/opt/ida-7.7"),
                Path("/usr/local/ida"),
                Path(os.path.expanduser("~/ida")),
            ]

        # Add smart scan results
        smart_scan_dirs = self._smart_scan_for_ida()

        # Combine and deduplicate
        all_dirs = default_dirs + smart_scan_dirs
        seen = set()
        unique_dirs = []
        for d in all_dirs:
            if d not in seen:
                seen.add(d)
                unique_dirs.append(d)

        return unique_dirs

    def _smart_scan_for_ida(self):
        """Smart scan for IDA Pro installations across drives."""
        found_dirs = []

        if self.system == "windows":
            # Scan common drives
            drives = ['C:', 'D:', 'E:', 'F:']
            for drive in drives:
                drive_path = Path(drive + '/')
                if drive_path.exists():
                    found_dirs.extend(self._scan_drive_for_ida(drive_path))
        elif self.system == "darwin":  # macOS
            # Scan common macOS locations
            locations = [Path("/Applications"), Path("/opt"), Path(os.path.expanduser("~/Applications"))]
            for location in locations:
                if location.exists():
                    found_dirs.extend(self._scan_directory_for_ida(location, max_depth=2))
        else:  # Linux
            # Scan common Linux locations
            locations = [Path("/opt"), Path("/usr/local"), Path("/home")]
            for location in locations:
                if location.exists():
                    found_dirs.extend(self._scan_directory_for_ida(location, max_depth=3))

        return found_dirs

    def _scan_drive_for_ida(self, drive_path):
        """Scan a Windows drive for IDA Pro installations."""
        found_dirs = []

        try:
            # Scan two levels deep for efficiency
            for first_level in drive_path.iterdir():
                if not first_level.is_dir():
                    continue

                # Skip system directories to speed up scan
                skip_dirs = {
                    'windows', 'system32', 'syswow64', '$recycle.bin',
                    'system volume information', 'recovery', 'boot',
                    'users', 'documents and settings', 'programdata'
                }
                if first_level.name.lower() in skip_dirs:
                    continue

                # Check if this directory itself is IDA Pro
                if self._is_ida_directory(first_level):
                    found_dirs.append(first_level)
                    continue

                # Scan second level
                try:
                    for second_level in first_level.iterdir():
                        if not second_level.is_dir():
                            continue

                        # Check if this is IDA Pro directory
                        if self._is_ida_directory(second_level):
                            found_dirs.append(second_level)

                        # Also check for IDA-like names
                        name_lower = second_level.name.lower()
                        if any(ida_name in name_lower for ida_name in ['ida', 'idapro', 'ida pro']):
                            if self._is_ida_directory(second_level):
                                found_dirs.append(second_level)

                except (PermissionError, OSError):
                    # Skip directories we can't access
                    continue

        except (PermissionError, OSError):
            # Skip drives we can't access
            pass

        return found_dirs

    def _scan_directory_for_ida(self, base_path, max_depth=2):
        """Scan a directory for IDA Pro installations with depth limit."""
        found_dirs = []

        def scan_recursive(path, current_depth):
            if current_depth > max_depth:
                return

            try:
                for item in path.iterdir():
                    if not item.is_dir():
                        continue

                    # Check if this is IDA Pro directory
                    if self._is_ida_directory(item):
                        found_dirs.append(item)

                    # Check for IDA-like names and scan deeper
                    name_lower = item.name.lower()
                    if any(ida_name in name_lower for ida_name in ['ida', 'idapro', 'ida pro']):
                        if self._is_ida_directory(item):
                            found_dirs.append(item)
                        else:
                            # Scan deeper if it might contain IDA
                            scan_recursive(item, current_depth + 1)
                    elif current_depth < max_depth:
                        # Scan common program directories
                        if any(prog_name in name_lower for prog_name in ['program', 'app', 'software', 'tool']):
                            scan_recursive(item, current_depth + 1)

            except (PermissionError, OSError):
                # Skip directories we can't access
                pass

        scan_recursive(base_path, 0)
        return found_dirs

    def _is_ida_directory(self, path):
        """Check if a directory is a valid IDA Pro installation."""
        try:
            # Check for IDA executables
            ida_executables = ['ida64.exe', 'ida.exe', 'ida64', 'ida']
            has_ida_exe = any((path / exe).exists() for exe in ida_executables)

            # Check for plugins directory
            has_plugins_dir = (path / 'plugins').exists()

            # Check for typical IDA files/directories
            ida_indicators = ['cfg', 'idc', 'python', 'loaders', 'procs']
            has_ida_files = any((path / indicator).exists() for indicator in ida_indicators)

            # Must have IDA executable and either plugins dir or other IDA files
            return has_ida_exe and (has_plugins_dir or has_ida_files)

        except (PermissionError, OSError):
            return False

    def _extract_bundled_files(self):
        """Extract bundled plugin files from executable."""
        if not self.is_bundled:
            # Not bundled, use files from script directory
            return self.script_dir

        # Create temporary directory for extracted files
        if self.temp_dir is None:
            self.temp_dir = Path(tempfile.mkdtemp(prefix="nexusai_"))

        # Check if files are already extracted
        nexus_py = self.temp_dir / "NexusAI.py"
        nexus_dir = self.temp_dir / "NexusAI"

        if nexus_py.exists() and nexus_dir.exists():
            return self.temp_dir

        # Extract from bundled resources
        try:
            # PyInstaller stores bundled files in sys._MEIPASS
            if hasattr(sys, '_MEIPASS'):
                bundle_dir = Path(sys._MEIPASS)

                # Copy NexusAI.py
                source_py = bundle_dir / "NexusAI.py"
                if source_py.exists():
                    shutil.copy2(source_py, nexus_py)

                # Copy NexusAI directory
                source_dir = bundle_dir / "NexusAI"
                if source_dir.exists():
                    shutil.copytree(source_dir, nexus_dir, dirs_exist_ok=True)

                if nexus_py.exists() and nexus_dir.exists():
                    return self.temp_dir

            # Fallback: try to extract from embedded zip
            return self._extract_from_embedded_zip()

        except Exception as e:
            print(f"Failed to extract bundled files: {e}")
            return None

    def _extract_from_embedded_zip(self):
        """Extract files from embedded zip archive."""
        try:
            # Look for embedded zip at end of executable
            exe_path = Path(sys.executable)

            with open(exe_path, 'rb') as f:
                # Read from end to find zip signature
                f.seek(-1024, 2)  # Go to 1KB from end
                data = f.read()

                # Look for zip central directory signature
                zip_sig = b'PK\x01\x02'
                if zip_sig in data:
                    # Found zip, try to extract
                    zip_start = data.rfind(zip_sig)
                    f.seek(-1024 + zip_start, 2)

                    # Extract zip content
                    with zipfile.ZipFile(f) as zf:
                        zf.extractall(self.temp_dir)

                    return self.temp_dir

        except Exception as e:
            print(f"Failed to extract from embedded zip: {e}")

        return None

    def _cleanup_temp_files(self):
        """Clean up temporary extracted files."""
        if self.temp_dir and self.temp_dir.exists():
            try:
                shutil.rmtree(self.temp_dir)
                self.temp_dir = None
            except Exception as e:
                print(f"Failed to cleanup temp files: {e}")

    def find_ida_installation(self, custom_dir=None):
        """Find IDA Pro installation directory."""
        if custom_dir:
            ida_dir = Path(custom_dir)
            if ida_dir.exists():
                return ida_dir
            else:
                print(f"❌ Specified IDA directory does not exist: {ida_dir}")
                return None

        print(self.messages['searching_ida'])
        for ida_dir in self.ida_dirs:
            if ida_dir.exists():
                print(self.messages['found_ida'].format(ida_dir))
                return ida_dir

        print(self.messages['ida_not_found'])
        print(self.messages['specify_ida_dir'])
        return None
    
    def get_python_executable(self, ida_dir):
        """Get the Python executable used by IDA Pro."""
        # Try to find IDA's Python executable with various naming patterns
        if self.system == "windows":
            # Common Python directory patterns in IDA Pro
            python_patterns = [
                "python/python.exe",
                "python3/python.exe",
                "python312/python.exe",
                "python311/python.exe",
                "python310/python.exe",
                "python39/python.exe",
                "python38/python.exe",
                "Python/python.exe",
                "Python312/python.exe",
                "Python311/python.exe",
            ]

            for pattern in python_patterns:
                python_exe = ida_dir / pattern
                if python_exe.exists():
                    return python_exe

            # Also try glob pattern for any python directory
            try:
                for python_dir in ida_dir.glob("python*"):
                    if python_dir.is_dir():
                        python_exe = python_dir / "python.exe"
                        if python_exe.exists():
                            return python_exe

                for python_dir in ida_dir.glob("Python*"):
                    if python_dir.is_dir():
                        python_exe = python_dir / "python.exe"
                        if python_exe.exists():
                            return python_exe
            except:
                pass

        elif self.system == "darwin":  # macOS
            python_patterns = [
                "python/python",
                "python3/python",
                "Python/python",
            ]

            for pattern in python_patterns:
                python_exe = ida_dir / pattern
                if python_exe.exists():
                    return python_exe

        else:  # Linux
            python_patterns = [
                "python/python",
                "python3/python",
            ]

            for pattern in python_patterns:
                python_exe = ida_dir / pattern
                if python_exe.exists():
                    return python_exe

        # Fallback to system Python
        return sys.executable

    def find_all_python_installations(self):
        """Find all Python installations on the system."""
        python_installations = []

        if self.system == "windows":
            python_installations = self._find_windows_python()
        elif self.system == "darwin":  # macOS
            python_installations = self._find_macos_python()
        else:  # Linux
            python_installations = self._find_linux_python()

        # Remove duplicates and validate
        unique_pythons = []
        seen_paths = set()

        for python_info in python_installations:
            path = python_info['path']
            if path not in seen_paths and self._validate_python(path):
                seen_paths.add(path)
                unique_pythons.append(python_info)

        return unique_pythons

    def _find_windows_python(self):
        """Find Python installations on Windows."""
        pythons = []

        # 1. System Python (current)
        try:
            current_python = Path(sys.executable)
            if current_python.exists():
                version = self._get_python_version(current_python)
                pythons.append({
                    'name': f'Current System Python {version}',
                    'path': str(current_python),
                    'type': 'system'
                })
        except:
            pass

        # 2. Registry-based search (Windows Store, official installer)
        pythons.extend(self._find_python_from_registry())

        # 3. Environment PATH search (fast)
        pythons.extend(self._find_python_in_path())

        # 4. Anaconda/Miniconda (common locations)
        pythons.extend(self._find_conda_python())

        # 5. Common installation paths with glob
        common_patterns = [
            "C:/Python*/python.exe",
            "C:/Program Files/Python*/python.exe",
            "C:/Program Files (x86)/Python*/python.exe",
            "D:/Python*/python.exe",
            "E:/Python*/python.exe",
            "F:/Python*/python.exe",
        ]

        for pattern in common_patterns:
            pythons.extend(self._find_python_by_pattern(pattern))

        # 6. User-specific locations
        user_patterns = [
            str(Path.home() / "AppData/Local/Programs/Python/Python*/python.exe"),
            str(Path.home() / "AppData/Local/Microsoft/WindowsApps/python.exe"),
            "C:/Users/*/AppData/Local/Programs/Python/Python*/python.exe",
        ]

        for pattern in user_patterns:
            pythons.extend(self._find_python_by_pattern(pattern))

        # 7. Development tools locations
        dev_patterns = [
            "C:/tools/python*/python.exe",
            "D:/tools/python*/python.exe",
            "C:/dev/python*/python.exe",
            "D:/dev/python*/python.exe",
            "C:/software/python*/python.exe",
            "D:/software/python*/python.exe",
        ]

        for pattern in dev_patterns:
            pythons.extend(self._find_python_by_pattern(pattern))

        # 8. Quick directory scan for missed installations
        pythons.extend(self._quick_scan_python())

        return pythons

    def _quick_scan_python(self):
        """Quick scan of common Python installation directories."""
        pythons = []

        # Common base directories to scan (limited depth for speed)
        scan_locations = [
            # Root drives
            (Path("C:/"), 1),
            (Path("D:/"), 1),
            (Path("E:/"), 1),
            # Program directories
            (Path("C:/Program Files"), 2),
            (Path("C:/Program Files (x86)"), 2),
            # User directories
            (Path.home() / "AppData/Local/Programs", 2),
            (Path.home(), 1),
            # Common dev directories
            (Path("C:/tools"), 2),
            (Path("D:/tools"), 2),
            (Path("C:/dev"), 2),
            (Path("D:/dev"), 2),
        ]

        for base_dir, max_depth in scan_locations:
            if not base_dir.exists():
                continue

            pythons.extend(self._scan_directory_for_python(base_dir, max_depth))

        return pythons

    def _scan_directory_for_python(self, directory, max_depth, current_depth=0):
        """Recursively scan directory for Python installations."""
        pythons = []

        if current_depth > max_depth:
            return pythons

        try:
            for item in directory.iterdir():
                if not item.is_dir():
                    continue

                name_lower = item.name.lower()

                # Check if directory name suggests Python
                python_indicators = ['python', 'py', 'anaconda', 'miniconda', 'conda']
                if any(indicator in name_lower for indicator in python_indicators):
                    # Look for python.exe in various subdirectories
                    python_candidates = [
                        item / "python.exe",
                        item / "Scripts" / "python.exe",
                        item / "bin" / "python.exe",
                        item / "python" / "python.exe",
                    ]

                    for candidate in python_candidates:
                        if candidate.exists():
                            version = self._get_python_version(candidate)
                            location_info = f"{item.parent.name}/{item.name}" if item.parent.name != directory.name else item.name
                            pythons.append({
                                'name': f'Python {version} ({location_info})',
                                'path': str(candidate),
                                'type': 'scan'
                            })
                            break  # Found one in this directory

                # Recurse into subdirectories if not too deep
                if current_depth < max_depth:
                    # Only recurse into likely directories to avoid scanning everything
                    if any(keyword in name_lower for keyword in ['python', 'program', 'tool', 'dev', 'software', 'app']):
                        pythons.extend(self._scan_directory_for_python(item, max_depth, current_depth + 1))

        except (PermissionError, OSError):
            # Skip directories we can't access
            pass

        return pythons

    def _find_python_from_registry(self):
        """Find Python installations from Windows registry."""
        pythons = []

        try:
            import winreg

            # Check different registry locations
            registry_paths = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Python\PythonCore"),
                (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Python\PythonCore"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Python\PythonCore"),
            ]

            for hkey, subkey in registry_paths:
                try:
                    with winreg.OpenKey(hkey, subkey) as key:
                        i = 0
                        while True:
                            try:
                                version = winreg.EnumKey(key, i)
                                try:
                                    with winreg.OpenKey(key, f"{version}\\InstallPath") as install_key:
                                        install_path, _ = winreg.QueryValueEx(install_key, "")
                                        python_exe = Path(install_path) / "python.exe"
                                        if python_exe.exists():
                                            pythons.append({
                                                'name': f'Python {version} (Registry)',
                                                'path': str(python_exe),
                                                'type': 'registry'
                                            })
                                except:
                                    pass
                                i += 1
                            except OSError:
                                break
                except:
                    pass
        except ImportError:
            pass  # winreg not available

        return pythons

    def _find_python_by_pattern(self, pattern):
        """Find Python installations by file pattern."""
        pythons = []

        try:
            import glob
            for python_exe in glob.glob(pattern, recursive=True):
                python_path = Path(python_exe)
                if python_path.exists() and python_path.is_file():
                    version = self._get_python_version(python_path)
                    # Create a more descriptive name
                    parent_name = python_path.parent.name
                    if parent_name.lower() in ['bin', 'scripts']:
                        parent_name = python_path.parent.parent.name

                    pythons.append({
                        'name': f'Python {version} ({parent_name})',
                        'path': str(python_path),
                        'type': 'path'
                    })
        except Exception as e:
            # Debug: print error for troubleshooting
            pass

        return pythons

    def _find_python_in_path(self):
        """Find Python installations in system PATH."""
        pythons = []

        try:
            # Check PATH environment variable
            path_env = os.environ.get('PATH', '')
            for path_dir in path_env.split(os.pathsep):
                path_dir = Path(path_dir.strip())
                if path_dir.exists():
                    for python_name in ['python.exe', 'python3.exe']:
                        python_exe = path_dir / python_name
                        if python_exe.exists():
                            version = self._get_python_version(python_exe)
                            pythons.append({
                                'name': f'Python {version} (PATH)',
                                'path': str(python_exe),
                                'type': 'path'
                            })
        except:
            pass

        return pythons

    def _find_conda_python(self):
        """Find Anaconda/Miniconda Python installations."""
        pythons = []

        # Common Anaconda/Miniconda locations
        conda_paths = [
            Path.home() / "anaconda3",
            Path.home() / "miniconda3",
            Path("C:/ProgramData/Anaconda3"),
            Path("C:/ProgramData/Miniconda3"),
            Path("C:/Anaconda3"),
            Path("C:/Miniconda3"),
        ]

        for conda_path in conda_paths:
            if conda_path.exists():
                # Base environment
                python_exe = conda_path / "python.exe"
                if python_exe.exists():
                    version = self._get_python_version(python_exe)
                    pythons.append({
                        'name': f'Anaconda/Miniconda {version} (base)',
                        'path': str(python_exe),
                        'type': 'conda'
                    })

                # Check environments
                envs_dir = conda_path / "envs"
                if envs_dir.exists():
                    for env_dir in envs_dir.iterdir():
                        if env_dir.is_dir():
                            env_python = env_dir / "python.exe"
                            if env_python.exists():
                                version = self._get_python_version(env_python)
                                pythons.append({
                                    'name': f'Conda Env: {env_dir.name} (Python {version})',
                                    'path': str(env_python),
                                    'type': 'conda_env'
                                })

        return pythons

    def _find_macos_python(self):
        """Find Python installations on macOS."""
        pythons = []

        # System Python
        try:
            current_python = Path(sys.executable)
            if current_python.exists():
                version = self._get_python_version(current_python)
                pythons.append({
                    'name': f'System Python {version}',
                    'path': str(current_python),
                    'type': 'system'
                })
        except:
            pass

        # Common macOS Python locations
        common_paths = [
            "/usr/bin/python*",
            "/usr/local/bin/python*",
            "/opt/homebrew/bin/python*",
            "/Library/Frameworks/Python.framework/Versions/*/bin/python*",
            str(Path.home() / "anaconda3/bin/python"),
            str(Path.home() / "miniconda3/bin/python"),
        ]

        for pattern in common_paths:
            pythons.extend(self._find_python_by_pattern(pattern))

        return pythons

    def _find_linux_python(self):
        """Find Python installations on Linux."""
        pythons = []

        # System Python
        try:
            current_python = Path(sys.executable)
            if current_python.exists():
                version = self._get_python_version(current_python)
                pythons.append({
                    'name': f'System Python {version}',
                    'path': str(current_python),
                    'type': 'system'
                })
        except:
            pass

        # Common Linux Python locations
        common_paths = [
            "/usr/bin/python*",
            "/usr/local/bin/python*",
            "/opt/python*/bin/python*",
            str(Path.home() / "anaconda3/bin/python"),
            str(Path.home() / "miniconda3/bin/python"),
        ]

        for pattern in common_paths:
            pythons.extend(self._find_python_by_pattern(pattern))

        return pythons

    def _get_python_version(self, python_exe):
        """Get Python version from executable."""
        try:
            result = subprocess.run([
                str(python_exe), "--version"
            ], capture_output=True, text=True, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW if platform.system().lower() == "windows" else 0)

            if result.returncode == 0:
                # Output format: "Python 3.9.7"
                version_line = result.stdout.strip() or result.stderr.strip()
                if "Python" in version_line:
                    return version_line.split()[-1]  # Get version number
            return "Unknown"
        except:
            return "Unknown"

    def _validate_python(self, python_exe):
        """Validate that Python executable is working."""
        try:
            result = subprocess.run([
                str(python_exe), "-c", "import sys; print(sys.version_info[:2])"
            ], capture_output=True, text=True, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW if platform.system().lower() == "windows" else 0)

            if result.returncode == 0:
                # Check if it's Python 3.8+
                version_output = result.stdout.strip()
                if "(" in version_output and ")" in version_output:
                    version_str = version_output.strip("()")
                    major, minor = map(int, version_str.split(", "))
                    return major >= 3 and (major > 3 or minor >= 8)
            return False
        except:
            return False

    def install_dependencies(self, python_exe, silent=False):
        """Install required Python dependencies."""
        if not silent:
            print(self.messages['installing_deps'])

        requirements = [
            "openai>=1.0.0",
            "markdown>=3.4.0",
            "httpx>=0.24.0"
        ]

        for requirement in requirements:
            if not silent:
                print(self.messages['installing_package'].format(requirement))
            try:
                # Always capture output to avoid terminal windows
                subprocess.run([
                    str(python_exe), "-m", "pip", "install", requirement
                ], check=True, capture_output=True, text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if platform.system().lower() == "windows" else 0)
                if not silent:
                    print(self.messages['package_success'].format(requirement))
            except subprocess.CalledProcessError as e:
                if not silent:
                    print(self.messages['package_warning'].format(requirement))
                    print(f"      Error: {e.stderr}")
                    print(self.messages['manual_install'].format(python_exe, requirement))
    
    def install_plugin_files(self, ida_dir):
        """Install plugin files to IDA Pro plugins directory."""
        plugins_dir = ida_dir / "plugins"
        plugins_dir.mkdir(exist_ok=True)

        # Extract bundled files if running from executable
        source_dir = self._extract_bundled_files()
        if source_dir is None:
            print("❌ Failed to extract plugin files")
            return False

        source_plugin_file = source_dir / "NexusAI.py"
        source_plugin_dir = source_dir / "NexusAI"

        target_plugin_file = plugins_dir / "NexusAI.py"
        target_plugin_dir = plugins_dir / "NexusAI"

        if not source_plugin_file.exists():
            print(f"❌ Plugin file not found: {source_plugin_file}")
            return False

        if not source_plugin_dir.exists():
            print(f"❌ Plugin directory not found: {source_plugin_dir}")
            return False
        
        print(self.messages['installing_files'])

        try:
            print(self.messages['copying_files'])

            # Remove existing files
            if target_plugin_file.exists():
                target_plugin_file.unlink()
            if target_plugin_dir.exists():
                shutil.rmtree(target_plugin_dir)

            # Copy files
            shutil.copy2(source_plugin_file, target_plugin_file)
            shutil.copytree(source_plugin_dir, target_plugin_dir)

            print(self.messages['files_success'])

            return True

        except Exception as e:
            print(self.messages['files_error'].format(e))
            return False
    
    def create_config_template(self, ida_dir):
        """Create a configuration template if it doesn't exist."""
        config_file = ida_dir / "plugins" / "NexusAI" / "Config" / "NexusAI.json"

        if config_file.exists():
            print(self.messages['config_exists'])
            return

        print(self.messages['config_template'])
        # The plugin will create its own default config, so we don't need to do anything here
        print(self.messages['config_success'])
    
    def run_installation(self, ida_dir_arg=None):
        """Run the complete installation process."""
        print(f"🚀 {self.messages['title']}")
        print("=" * 40)

        # Find IDA Pro installation
        ida_dir = self.find_ida_installation(ida_dir_arg)
        if not ida_dir:
            return False

        # Get Python executable
        python_exe = self.get_python_executable(ida_dir)
        print(f"🐍 Using Python: {python_exe}")

        # Install dependencies
        self.install_dependencies(python_exe)

        # Install plugin files
        if not self.install_plugin_files(ida_dir):
            return False

        # Create config template
        self.create_config_template(ida_dir)

        # Clean up temporary files
        self._cleanup_temp_files()

        print(f"\n{self.messages['install_success']}")
        print(f"\n{self.messages['next_steps']}")
        print(self.messages['step1'])
        print(self.messages['step2'])
        print(self.messages['step3'])
        print(self.messages['step4'])
        print(f"\n{self.messages['happy_reversing']}")

        return True


def select_language():
    """Interactive language selection if not specified."""
    print("=" * 50)
    print("NexusAI Installation Script / NexusAI 安装脚本")
    print("=" * 50)
    print()
    print("Please select your language / 请选择您的语言:")
    print("1. English")
    print("2. 中文")
    print()

    while True:
        try:
            choice = input("Enter your choice (1-2) / 输入您的选择 (1-2): ").strip()
            if choice == "1":
                return "en"
            elif choice == "2":
                return "zh"
            else:
                print("Invalid choice. Please enter 1 or 2. / 无效选择。请输入1或2。")
        except (KeyboardInterrupt, EOFError):
            print("\nInstallation cancelled. / 安装已取消。")
            sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="Install NexusAI plugin for IDA Pro / 安装NexusAI插件到IDA Pro",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument(
        "--ida-dir",
        help="Specify IDA Pro installation directory / 指定IDA Pro安装目录"
    )

    parser.add_argument(
        "--lang",
        choices=["en", "zh"],
        help="Language preference (en/zh) / 语言偏好 (en/zh)"
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        default=True,
        help="Use graphical interface (default) / 使用图形界面（默认）"
    )
    parser.add_argument(
        "--cli",
        action="store_true",
        help="Use command line interface / 使用命令行界面"
    )

    args = parser.parse_args()

    # Use CLI if explicitly requested or if GUI is not available
    use_cli = args.cli or (args.ida_dir and args.lang)

    try:
        # Try to import tkinter to check if GUI is available
        import tkinter
        gui_available = True
    except ImportError:
        gui_available = False
        use_cli = True

    if use_cli or not gui_available:
        # Command line installation
        language = args.lang if args.lang else select_language()
        installer = NexusAIInstaller(language)
        success = installer.run_installation(args.ida_dir)
        sys.exit(0 if success else 1)
    else:
        # Graphical installation
        try:
            # Redirect stdout/stderr to suppress print statements in GUI mode
            if getattr(sys, 'frozen', False):  # Only when running as executable
                import io
                sys.stdout = io.StringIO()
                sys.stderr = io.StringIO()

            wizard = InstallationWizard()
            wizard.run()
        except Exception as e:
            # Restore stdout/stderr for error reporting
            if getattr(sys, 'frozen', False):
                sys.stdout = sys.__stdout__
                sys.stderr = sys.__stderr__
            print(f"GUI failed to start: {e}")
            print("Falling back to command line interface...")
            language = args.lang if args.lang else select_language()
            installer = NexusAIInstaller(language)
            success = installer.run_installation(args.ida_dir, args.dev)
            sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
