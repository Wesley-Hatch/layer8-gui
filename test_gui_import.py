#!/usr/bin/env python3
"""Test GUI imports to identify issues"""

import sys
import traceback

print("Testing GUI imports...")
print("-" * 60)

try:
    print("1. Testing modern_theme import...")
    from modern_theme import ModernTheme, ModernButton, ModernEntry, ModernLabel, ModernFrame
    print("   ✓ modern_theme imported successfully")
    print(f"   - Colors available: {len(ModernTheme.COLORS)} colors")
    print(f"   - Fonts available: {len(ModernTheme.FONTS)} fonts")
except Exception as e:
    print(f"   ✗ FAILED: {e}")
    traceback.print_exc()
    sys.exit(1)

try:
    print("\n2. Testing tkinter import...")
    import tkinter as tk
    from tkinter import ttk, messagebox
    print("   ✓ tkinter imported successfully")
except Exception as e:
    print(f"   ✗ FAILED: {e}")
    traceback.print_exc()
    sys.exit(1)

try:
    print("\n3. Testing PIL import...")
    from PIL import Image, ImageTk
    print("   ✓ PIL imported successfully")
except Exception as e:
    print(f"   ✗ FAILED: {e}")
    traceback.print_exc()
    sys.exit(1)

try:
    print("\n4. Testing gui_app imports...")
    # Don't import the whole module, just check syntax
    import py_compile
    py_compile.compile('gui_app.pyw', doraise=True)
    print("   ✓ gui_app.pyw syntax is valid")
except Exception as e:
    print(f"   ✗ FAILED: {e}")
    traceback.print_exc()
    sys.exit(1)

print("\n" + "=" * 60)
print("All imports successful!")
print("=" * 60)
