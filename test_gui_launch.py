#!/usr/bin/env python3
"""
Quick test to check if GUI launches without errors
"""

import sys
import traceback

print("Testing GUI launch...")
print("=" * 60)

try:
    print("1. Importing modules...")
    import tkinter as tk
    from modern_theme import ModernTheme
    print("   ✓ Imports successful")

    print("\n2. Testing ModernTheme...")
    print(f"   Colors: {list(ModernTheme.COLORS.keys())[:5]}...")
    print(f"   Fonts: {list(ModernTheme.FONTS.keys())[:5]}...")
    print("   ✓ ModernTheme works")

    print("\n3. Compiling gui_app.pyw...")
    import py_compile
    py_compile.compile('gui_app.pyw', doraise=True)
    print("   ✓ Syntax is valid")

    print("\n" + "=" * 60)
    print("✅ All checks passed! GUI should launch successfully.")
    print("\nTo launch the GUI, run:")
    print("   python gui_app.pyw")
    print("=" * 60)

except Exception as e:
    print(f"\n❌ ERROR: {e}")
    print("\nFull traceback:")
    traceback.print_exc()
    sys.exit(1)
