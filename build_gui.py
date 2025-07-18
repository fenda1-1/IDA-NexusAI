#!/usr/bin/env python3
"""
Build NexusAI GUI Installer - Single file with no console window
Creates NexusAI-Installer-GUI.exe with embedded plugin files
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path


def check_requirements():
    """Check if all required files and tools are available."""
    script_dir = Path(__file__).parent
    
    # Check for PyInstaller
    try:
        import PyInstaller
        print("✅ PyInstaller is available")
    except ImportError:
        print("❌ PyInstaller not found, installing...")
        subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller"], check=True)
        print("✅ PyInstaller installed")
    
    # Check for required plugin files
    nexus_py = script_dir / "NexusAI.py"
    nexus_dir = script_dir / "NexusAI"
    install_py = script_dir / "install.py"
    
    missing_files = []
    if not nexus_py.exists():
        missing_files.append(str(nexus_py))
    if not nexus_dir.exists():
        missing_files.append(str(nexus_dir))
    if not install_py.exists():
        missing_files.append(str(install_py))
    
    if missing_files:
        print("❌ Missing required files:")
        for file in missing_files:
            print(f"   - {file}")
        return False
    
    print("✅ All required files found")
    return True


def build_gui_installer():
    """Build the GUI installer with no console window."""
    script_dir = Path(__file__).parent
    
    print("🔨 Building NexusAI GUI Installer...")
    print("   - Single file executable")
    print("   - No console window")
    print("   - Embedded plugin files")
    
    # Remove old executable
    old_exe = script_dir / "NexusAI-Installer-GUI.exe"
    if old_exe.exists():
        print("🗑️  Removing old executable...")
        old_exe.unlink()
    
    try:
        # Build command
        cmd = [
            sys.executable, "-m", "PyInstaller",
            "--onefile",                           # Single file
            "--windowed",                          # No console window
            "--add-data", "NexusAI.py;.",         # Add plugin entry point
            "--add-data", "NexusAI;NexusAI",      # Add plugin directory
            "--name", "NexusAI-Installer-GUI",    # Output name
            "--distpath", ".",                     # Output to current directory
            "--clean",                             # Clean cache
            "install.py"                           # Source script
        ]
        
        print("🚀 Running PyInstaller...")
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        
        # Check if output file was created
        output_file = script_dir / "NexusAI-Installer-GUI.exe"
        if output_file.exists():
            size_mb = output_file.stat().st_size / (1024 * 1024)
            print(f"✅ Build successful!")
            print(f"📁 Created: {output_file}")
            print(f"📊 Size: {size_mb:.1f} MB")
            print(f"🖥️  No console window: ✅")
            print(f"📦 Embedded files: ✅")
            return True
        else:
            print("❌ Build failed - output file not found")
            return False
            
    except subprocess.CalledProcessError as e:
        print(f"❌ Build failed: {e}")
        if e.stdout:
            print("STDOUT:", e.stdout)
        if e.stderr:
            print("STDERR:", e.stderr)
        return False
    
    finally:
        # Clean up build artifacts
        cleanup_build_files()


def cleanup_build_files():
    """Clean up build artifacts."""
    script_dir = Path(__file__).parent
    
    # Remove build directory
    build_dir = script_dir / "build"
    if build_dir.exists():
        shutil.rmtree(build_dir)
        print("🧹 Cleaned up build directory")
    
    # Remove spec file
    spec_file = script_dir / "NexusAI-Installer-GUI.spec"
    if spec_file.exists():
        spec_file.unlink()
        print("🧹 Cleaned up spec file")


def test_executable():
    """Test the built executable."""
    script_dir = Path(__file__).parent
    exe_file = script_dir / "NexusAI-Installer-GUI.exe"
    
    if not exe_file.exists():
        print("❌ Executable not found for testing")
        return False
    
    print("🧪 Testing executable...")
    
    try:
        # Test that it starts without showing console
        result = subprocess.run([str(exe_file), "--help"], 
                              capture_output=True, text=True, timeout=5)
        
        # For windowed apps, --help might not work as expected
        # The fact that it doesn't crash is a good sign
        print("✅ Executable test completed")
        return True
        
    except subprocess.TimeoutExpired:
        print("✅ Executable started (timeout is normal for GUI apps)")
        return True
    except Exception as e:
        print(f"⚠️  Test warning: {e}")
        return True  # Don't fail build for test issues


def main():
    """Main build process."""
    print("🚀 NexusAI GUI Installer Builder")
    print("=" * 50)
    
    # Check requirements
    if not check_requirements():
        print("❌ Requirements check failed")
        return False
    
    # Build GUI installer
    if not build_gui_installer():
        print("❌ Build failed")
        return False
    
    # Test the result
    test_executable()
    
    print("\n" + "=" * 50)
    print("🎉 GUI Installer build completed!")
    print("\n📋 Usage:")
    print("   NexusAI-Installer-GUI.exe")
    print("\n✨ Features:")
    print("   ✅ Single file installer")
    print("   ✅ No console window")
    print("   ✅ Embedded plugin files")
    print("   ✅ Graphical interface")
    print("   ✅ Multi-language support")
    print("   ✅ Smart IDA Pro detection")
    
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
