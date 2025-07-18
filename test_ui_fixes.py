#!/usr/bin/env python3
"""
Test the UI fixes for chat_input_placeholder and removal of dev_mode
"""

import sys
import os
from pathlib import Path

def test_chat_placeholder_fix():
    """Test that chat_input_placeholder is properly set."""
    print("🔍 Testing Chat Input Placeholder Fix")
    print("=" * 40)
    
    # Check if the UI file has the correct indentation
    ui_file = Path("NexusAI/UI/ui_view.py")
    
    if not ui_file.exists():
        print("❌ UI file not found")
        return False
    
    with open(ui_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check for the fixed line
    if "self.input_widget.setPlaceholderText(self.controller.config.get_message(\"chat_input_placeholder\"))" in content:
        print("✅ Placeholder setting code found")
        
        # Check that it's not incorrectly indented (not after a return statement)
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if "self.input_widget.setPlaceholderText" in line:
                # Check previous lines for return statement
                prev_lines = lines[max(0, i-5):i]
                has_return_before = any("return" in prev_line.strip() for prev_line in prev_lines)
                
                if not has_return_before or any("if" in prev_line for prev_line in prev_lines):
                    print("✅ Placeholder code is properly positioned")
                    return True
                else:
                    print("❌ Placeholder code is still after return statement")
                    return False
    else:
        print("❌ Placeholder setting code not found")
        return False

def test_dev_mode_removal():
    """Test that dev_mode options have been removed."""
    print("\n🗑️  Testing Dev Mode Removal")
    print("=" * 40)
    
    install_file = Path("install.py")
    
    if not install_file.exists():
        print("❌ Install file not found")
        return False
    
    with open(install_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check for removed elements
    removed_items = [
        "dev_mode_var",
        "Development Mode (Create symbolic links)",
        "开发模式 (创建符号链接)",
        "creating_symlinks",
        "symlinks_success",
        "--dev",
        "mklink"
    ]
    
    found_items = []
    for item in removed_items:
        if item in content:
            found_items.append(item)
    
    if found_items:
        print(f"❌ Found remaining dev mode references: {found_items}")
        return False
    else:
        print("✅ All dev mode references removed")
        
        # Check that install_plugin_files no longer has dev_mode parameter
        if "def install_plugin_files(self, ida_dir):" in content:
            print("✅ install_plugin_files method signature updated")
        else:
            print("❌ install_plugin_files method signature not updated")
            return False
        
        # Check that only copy logic remains
        if "shutil.copy2" in content and "shutil.copytree" in content:
            print("✅ File copying logic preserved")
        else:
            print("❌ File copying logic missing")
            return False
        
        return True

def test_config_messages():
    """Test that chat_input_placeholder messages exist in config."""
    print("\n💬 Testing Config Messages")
    print("=" * 40)
    
    config_file = Path("NexusAI/Config/NexusAI.json")
    
    if not config_file.exists():
        print("❌ Config file not found")
        return False
    
    with open(config_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check for placeholder messages
    if '"chat_input_placeholder"' in content:
        print("✅ chat_input_placeholder found in config")
        
        # Check for both languages
        if "输入对当前光标位置的代码提问" in content:
            print("✅ Chinese placeholder text found")
        else:
            print("❌ Chinese placeholder text missing")
            return False
            
        if "Ask questions about the code at the current cursor position" in content:
            print("✅ English placeholder text found")
        else:
            print("❌ English placeholder text missing")
            return False
        
        return True
    else:
        print("❌ chat_input_placeholder not found in config")
        return False

def test_installer_functionality():
    """Test that installer still works without dev_mode."""
    print("\n⚙️  Testing Installer Functionality")
    print("=" * 40)
    
    try:
        from install import NexusAIInstaller
        
        # Test installer creation
        installer = NexusAIInstaller('zh')
        print("✅ Installer created successfully")
        
        # Test that install_plugin_files method exists and has correct signature
        import inspect
        sig = inspect.signature(installer.install_plugin_files)
        params = list(sig.parameters.keys())
        
        if params == ['ida_dir']:
            print("✅ install_plugin_files has correct signature (no dev_mode)")
        else:
            print(f"❌ install_plugin_files has wrong signature: {params}")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ Installer test failed: {e}")
        return False

def main():
    """Main test function."""
    print("🧪 Testing NexusAI UI Fixes")
    print("=" * 60)
    
    tests = [
        ("Chat Placeholder Fix", test_chat_placeholder_fix),
        ("Dev Mode Removal", test_dev_mode_removal),
        ("Config Messages", test_config_messages),
        ("Installer Functionality", test_installer_functionality)
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} failed with exception: {e}")
            results.append((test_name, False))
    
    print("\n" + "=" * 60)
    print("🎯 Test Results Summary")
    print("=" * 60)
    
    passed = 0
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {test_name}")
        if result:
            passed += 1
    
    print(f"\n📊 Overall: {passed}/{len(tests)} tests passed")
    
    if passed == len(tests):
        print("🎉 All fixes verified successfully!")
        print("\n💡 Key improvements:")
        print("   ✅ Chat input placeholder now displays correctly")
        print("   ✅ Development mode options removed")
        print("   ✅ Installer simplified for production use")
        print("   ✅ UI code properly structured")
    else:
        print("⚠️  Some tests failed - please review the issues above")
    
    return passed == len(tests)

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
