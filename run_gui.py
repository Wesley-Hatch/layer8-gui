import sys
import traceback
import importlib.util

def load_module_from_path(module_name, file_path):
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module

try:
    print("Attempting to load gui_app.pyw...")
    gui_app = load_module_from_path("gui_app", "gui_app.pyw")
    print("Loading successful. Calling main()...")
    gui_app.main()
except Exception as e:
    print("An error occurred during GUI execution:")
    traceback.print_exc()
    with open("crash_report.txt", "w") as f:
        traceback.print_exc(file=f)
