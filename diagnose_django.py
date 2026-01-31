import sys
import os

print("--- Python Environment Diagnostics ---")
print(f"Python Executable: {sys.executable}")
print(f"Python Version: {sys.version}")
print(f"Current Directory: {os.getcwd()}")

try:
    import django
    print(f"Django Version: {django.get_version()}")
    print(f"Django Location: {django.__file__}")
except ImportError:
    print("Error: Django is NOT importable in this environment.")
except Exception as e:
    print(f"Error while importing Django: {e}")

print("\n--- sys.path ---")
for p in sys.path:
    print(p)
