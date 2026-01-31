import tkinter as tk
from tkinter import messagebox
import sys
import os
import importlib.util
import logging

def launch():
    """
    Simplified launcher that uses the unified DebugLauncher in gui_app.pyw
    """
    app_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'gui_app.pyw')
    
    if not os.path.exists(app_path):
        messagebox.showerror("Error", f"Could not find {app_path}")
        return

    try:
        # Import gui_app.pyw using importlib
        spec = importlib.util.spec_from_file_location("gui_app", app_path)
        gui_app = importlib.util.module_from_spec(spec)
        sys.modules["gui_app"] = gui_app
        spec.loader.exec_module(gui_app)
        
        # Call the main function. 
        # gui_app.main() will handle the launcher internally if called without arguments.
        if hasattr(gui_app, 'main'):
            gui_app.main()
        else:
            messagebox.showerror("Error", "gui_app.pyw has no main() function")
            
    except Exception as e:
        import traceback
        error_msg = traceback.format_exc()
        logging.error(f"Failed to launch: {error_msg}")
        messagebox.showerror("Launch Failed", f"An error occurred while launching the application:\n\n{str(e)}")

if __name__ == "__main__":
    launch()
