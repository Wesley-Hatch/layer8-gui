"""
Layer8 GUI Updater Integration

This module integrates the auto-updater with the Tkinter GUI,
providing user-friendly update dialogs and notifications.
"""

import tkinter as tk
from tkinter import messagebox, ttk
import threading
from pathlib import Path
from typing import Optional, Callable
from updater import Layer8Updater


class UpdaterGUI:
    """
    GUI wrapper for the Layer8Updater
    
    Provides:
    - Update notification dialog
    - Download progress window
    - Installation progress
    - Error handling
    """
    
    def __init__(
        self,
        parent: tk.Tk,
        current_version: str,
        update_url: str,
        on_restart_required: Optional[Callable] = None
    ):
        """
        Initialize the updater GUI
        
        Args:
            parent: Parent Tkinter window
            current_version: Current app version
            update_url: GitHub API URL for releases
            on_restart_required: Callback when restart is needed
        """
        self.parent = parent
        self.current_version = current_version
        self.update_url = update_url
        self.on_restart_required = on_restart_required
        
        self.updater = Layer8Updater(
            current_version=current_version,
            update_url=update_url,
            app_directory=Path(__file__).parent
        )
        
        self.progress_window: Optional[tk.Toplevel] = None
        self.progress_bar: Optional[ttk.Progressbar] = None
        self.progress_label: Optional[tk.Label] = None
    
    def check_for_updates_silent(self) -> bool:
        """
        Check for updates silently (no dialogs)
        
        Returns:
            bool: True if update available
        """
        return self.updater.check_for_updates()
    
    def check_for_updates_with_dialog(self):
        """Check for updates and show dialog if available"""
        # Show checking dialog
        checking_dialog = self._create_checking_dialog()
        
        def check_in_background():
            has_update = self.updater.check_for_updates(force=True)
            
            # Close checking dialog
            checking_dialog.destroy()
            
            if has_update:
                self._show_update_available_dialog()
            else:
                self._show_no_updates_dialog()
        
        thread = threading.Thread(target=check_in_background, daemon=True)
        thread.start()
    
    def _create_checking_dialog(self) -> tk.Toplevel:
        """Create 'checking for updates' dialog"""
        dialog = tk.Toplevel(self.parent)
        dialog.title("Checking for Updates")
        dialog.geometry("300x100")
        dialog.resizable(False, False)
        
        # Center on parent
        dialog.transient(self.parent)
        dialog.grab_set()
        
        # Content
        tk.Label(
            dialog,
            text="Checking for updates...",
            font=("Arial", 12)
        ).pack(pady=20)
        
        # Progress bar
        progress = ttk.Progressbar(dialog, mode='indeterminate', length=250)
        progress.pack(pady=10)
        progress.start(10)
        
        return dialog
    
    def _show_update_available_dialog(self):
        """Show dialog when update is available"""
        message = f"""A new version of Layer8 is available!

Current version: {self.current_version}
New version: {self.updater.latest_version}

Would you like to download and install it now?

The application will restart after the update."""
        
        response = messagebox.askyesno(
            "Update Available",
            message,
            icon='info'
        )
        
        if response:
            self._start_update_process()
    
    def _show_no_updates_dialog(self):
        """Show dialog when no updates are available"""
        messagebox.showinfo(
            "No Updates",
            f"You're already running the latest version ({self.current_version}).",
            icon='info'
        )
    
    def _start_update_process(self):
        """Start the download and installation process"""
        # Create progress window
        self.progress_window = tk.Toplevel(self.parent)
        self.progress_window.title("Updating Layer8")
        self.progress_window.geometry("400x150")
        self.progress_window.resizable(False, False)
        
        # Prevent closing during update
        self.progress_window.protocol("WM_DELETE_WINDOW", lambda: None)
        
        # Center on parent
        self.progress_window.transient(self.parent)
        self.progress_window.grab_set()
        
        # Status label
        self.progress_label = tk.Label(
            self.progress_window,
            text="Downloading update...",
            font=("Arial", 11)
        )
        self.progress_label.pack(pady=20)
        
        # Progress bar
        self.progress_bar = ttk.Progressbar(
            self.progress_window,
            mode='determinate',
            length=350
        )
        self.progress_bar.pack(pady=10)
        
        # Details label
        self.details_label = tk.Label(
            self.progress_window,
            text="0%",
            font=("Arial", 9),
            fg="#666666"
        )
        self.details_label.pack()
        
        # Start download in background
        thread = threading.Thread(target=self._download_and_install, daemon=True)
        thread.start()
    
    def _download_and_install(self):
        """Download and install update (runs in background thread)"""
        try:
            # Download phase
            def progress_callback(downloaded, total):
                if total > 0:
                    percent = (downloaded / total) * 100
                    
                    # Update UI on main thread
                    self.parent.after(0, lambda: self._update_progress(
                        percent,
                        f"Downloading... {percent:.1f}%"
                    ))
            
            if not self.updater.download_update(progress_callback):
                self._show_error("Download failed. Please try again later.")
                return
            
            # Installation phase
            self.parent.after(0, lambda: self._update_progress(
                0,
                "Installing update..."
            ))
            
            if not self.updater.install_update():
                self._show_error("Installation failed. The application has not been modified.")
                return
            
            # Success
            self.parent.after(0, self._show_success)
        
        except Exception as e:
            self._show_error(f"Update failed: {str(e)}")
    
    def _update_progress(self, percent: float, message: str):
        """Update progress bar and label (call from main thread)"""
        if self.progress_bar:
            self.progress_bar['value'] = percent
        
        if self.progress_label:
            self.progress_label['text'] = message
        
        if self.details_label:
            self.details_label['text'] = f"{percent:.1f}%"
    
    def _show_error(self, message: str):
        """Show error message and close progress window"""
        if self.progress_window:
            self.progress_window.destroy()
        
        messagebox.showerror(
            "Update Failed",
            message,
            icon='error'
        )
    
    def _show_success(self):
        """Show success message and prompt for restart"""
        if self.progress_window:
            self.progress_window.destroy()
        
        response = messagebox.showinfo(
            "Update Complete",
            f"Layer8 has been updated to version {self.updater.latest_version}!\n\n"
            "The application will now restart.",
            icon='info'
        )
        
        # Restart application
        if self.on_restart_required:
            self.on_restart_required()
        else:
            # Default restart behavior
            self._restart_application()
    
    def _restart_application(self):
        """Restart the application"""
        import sys
        import os
        
        # Close current application
        self.parent.destroy()
        
        # Restart
        if getattr(sys, 'frozen', False):
            # Running as compiled executable
            os.execl(sys.executable, sys.executable, *sys.argv)
        else:
            # Running as script
            os.execl(sys.executable, sys.executable, *sys.argv)
    
    def start_background_checker(self, check_interval: int = 86400):
        """
        Start background update checker
        
        Args:
            check_interval: Interval in seconds (default: 24 hours)
        """
        def check_periodically():
            import time
            
            while True:
                try:
                    # Wait for interval
                    time.sleep(check_interval)
                    
                    # Check for updates
                    if self.updater.check_for_updates():
                        # Show notification on main thread
                        self.parent.after(0, self._show_update_notification)
                
                except Exception as e:
                    print(f"Background checker error: {e}")
        
        thread = threading.Thread(target=check_periodically, daemon=True)
        thread.start()
    
    def _show_update_notification(self):
        """Show subtle update notification"""
        response = messagebox.askyesno(
            "Update Available",
            f"Version {self.updater.latest_version} is available.\n\n"
            "Would you like to update now?",
            icon='info'
        )
        
        if response:
            self._start_update_process()


# =============================================================================
# INTEGRATION HELPERS
# =============================================================================

def add_updater_to_gui(
    root: tk.Tk,
    menu_bar: tk.Menu,
    current_version: str,
    update_url: str,
    on_restart: Optional[Callable] = None
) -> UpdaterGUI:
    """
    Add updater to existing GUI with menu item
    
    Args:
        root: Main Tkinter window
        menu_bar: Menu bar to add "Check for Updates" option
        current_version: Current version
        update_url: GitHub API URL
        on_restart: Callback for restart
        
    Returns:
        UpdaterGUI instance
    """
    updater_gui = UpdaterGUI(root, current_version, update_url, on_restart)
    
    # Add "Help" menu if it doesn't exist
    help_menu = None
    for i in range(menu_bar.index('end') + 1):
        try:
            label = menu_bar.entrycget(i, 'label')
            if label.lower() == 'help':
                help_menu = menu_bar.nametowidget(menu_bar.entrycget(i, 'menu'))
                break
        except:
            pass
    
    if not help_menu:
        help_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="Help", menu=help_menu)
    
    # Add "Check for Updates" menu item
    help_menu.add_command(
        label="Check for Updates...",
        command=updater_gui.check_for_updates_with_dialog
    )
    
    help_menu.add_separator()
    
    help_menu.add_command(
        label=f"About Layer8 v{current_version}",
        command=lambda: messagebox.showinfo(
            "About Layer8",
            f"Layer8 Security Platform\nVersion {current_version}\n\n"
            "© 2025 Layer8 Security"
        )
    )
    
    # Start background checker (checks once per day)
    updater_gui.start_background_checker(check_interval=86400)
    
    return updater_gui


# =============================================================================
# EXAMPLE USAGE
# =============================================================================

if __name__ == "__main__":
    # Example integration
    root = tk.Tk()
    root.title("Layer8 Security Platform")
    root.geometry("800x600")
    
    # Create menu bar
    menu_bar = tk.Menu(root)
    root.config(menu=menu_bar)
    
    # Add file menu (example)
    file_menu = tk.Menu(menu_bar, tearoff=0)
    menu_bar.add_cascade(label="File", menu=file_menu)
    file_menu.add_command(label="Exit", command=root.quit)
    
    # Add updater
    updater = add_updater_to_gui(
        root=root,
        menu_bar=menu_bar,
        current_version="1.0.0",
        update_url="https://api.github.com/repos/yourusername/layer8-gui/releases/latest"
    )
    
    # Add some content
    tk.Label(
        root,
        text="Layer8 Security Platform",
        font=("Arial", 24, "bold")
    ).pack(pady=50)
    
    tk.Label(
        root,
        text="Go to Help → Check for Updates to test the updater",
        font=("Arial", 12)
    ).pack()
    
    root.mainloop()
