import tkinter as tk
from tkinter import messagebox, ttk, font as tkfont, scrolledtext
import threading
import sys
import os
import shutil
import time
import base64
from PIL import Image, ImageTk
from updater_gui import add_updater_to_gui

# Set up basic logging FIRST
import logging
log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'gui_startup.log')
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename=log_file
)

class DebugLauncher:
    def __init__(self):
        try:
            from modern_theme import ModernTheme
            self.theme = ModernTheme
        except ImportError:
            # Fallback to default colors if modern_theme isn't available
            class FallbackTheme:
                COLORS = {
                    'bg_primary': '#0f0f0f',
                    'bg_secondary': '#1a1a1a',
                    'bg_tertiary': '#242424',
                    'accent_primary': '#00ff88',
                    'fg_primary': '#e8e8e8',
                    'fg_secondary': '#9ca3af',
                    'fg_tertiary': '#6b7280',
                    'warning': '#f59e0b',
                    'error': '#ef4444',
                    'success': '#10b981',
                    'info': '#3b82f6',
                    'border_light': '#2d2d2d',
                    'bg_input': '#1e1e1e',
                    'accent_hover': '#00cc6a'
                }
                FONTS = {
                    'heading': ('Segoe UI', 18, 'bold'),
                    'small': ('Segoe UI', 9),
                    'body_bold': ('Segoe UI', 11, 'bold'),
                    'tiny': ('Segoe UI', 8),
                    'subheading': ('Segoe UI', 14, 'bold'),
                    'info': ('Segoe UI', 11),
                    'mono_small': ('Consolas', 9)
                }
            self.theme = FallbackTheme

        self.root = tk.Tk()
        self.root.title("Layer8 - Debug Launcher")
        self.root.geometry("750x650")
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.configure(bg=self.theme.COLORS['bg_primary'])

        # Make sure window stays on top and centered
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - 375
        y = (self.root.winfo_screenheight() // 2) - 325
        self.root.geometry(f'750x650+{x}+{y}')

        # Title with modern design
        tk.Label(
            self.root,
            text="LAYER8 SECURITY PLATFORM",
            font=self.theme.FONTS['heading'],
            bg=self.theme.COLORS['bg_secondary'],
            fg=self.theme.COLORS['accent_primary'],
            pady=20
        ).pack(fill="x")

        tk.Label(
            self.root,
            text="DIAGNOSTIC MODE",
            font=self.theme.FONTS['small'],
            bg=self.theme.COLORS['bg_secondary'],
            fg=self.theme.COLORS['warning'],
            pady=0
        ).pack(fill="x", pady=(0, 10))
        
        # Status frame
        status_frame = tk.Frame(self.root, bg=self.theme.COLORS['bg_primary'], pady=10)
        status_frame.pack(fill="x", padx=24, pady=12)

        tk.Label(
            status_frame,
            text="CURRENT STATUS:",
            font=self.theme.FONTS['tiny'],
            bg=self.theme.COLORS['bg_primary'],
            fg=self.theme.COLORS['fg_secondary']
        ).pack()

        self.status_label = tk.Label(
            status_frame,
            text="Initializing Diagnostics...",
            font=self.theme.FONTS['subheading'],
            bg=self.theme.COLORS['bg_primary'],
            fg=self.theme.COLORS['warning']
        )
        self.status_label.pack(pady=8)

        # Progress
        self.progress_label = tk.Label(
            status_frame,
            text="",
            font=self.theme.FONTS['body_bold'],
            bg=self.theme.COLORS['bg_primary'],
            fg=self.theme.COLORS.get('info', '#3b82f6')
        )
        self.progress_label.pack()

        # Log area
        tk.Label(
            self.root,
            text="DIAGNOSTIC LOG:",
            font=self.theme.FONTS['body_bold'],
            bg=self.theme.COLORS['bg_primary'],
            fg=self.theme.COLORS['fg_secondary']
        ).pack(anchor="w", padx=24, pady=(12, 8))

        self.log_text = scrolledtext.ScrolledText(
            self.root,
            height=22,
            width=90,
            font=self.theme.FONTS['mono_small'],
            bg=self.theme.COLORS['bg_secondary'],
            fg=self.theme.COLORS['accent_primary'],
            padx=16,
            pady=16,
            borderwidth=0,
            highlightthickness=1,
            highlightbackground=self.theme.COLORS['border_light']
        )
        self.log_text.pack(padx=24, pady=8, fill="both", expand=True)
        
        # Button frame
        btn_frame = tk.Frame(self.root, bg=self.theme.COLORS['bg_primary'])
        btn_frame.pack(pady=20)
        
        self.continue_btn = tk.Button(
            btn_frame,
            text="LAUNCH ANYWAY",
            command=self.launch_main_app,
            bg="#27ae60",
            fg="white",
            activebackground="#2ecc71",
            activeforeground="white",
            state="disabled",
            width=18,
            font=("Segoe UI", 9, "bold"),
            relief=tk.FLAT,
            cursor="hand2"
        )
        self.continue_btn.pack(side="left", padx=10)
        
        self.skip_btn = tk.Button(
            btn_frame,
            text="SKIP DB TEST",
            command=self.skip_db_test,
            bg="#3498db",
            fg="white",
            activebackground="#2980b9",
            activeforeground="white",
            state="normal",
            width=18,
            font=("Segoe UI", 9, "bold"),
            relief=tk.FLAT,
            cursor="hand2"
        )
        self.skip_btn.pack(side="left", padx=10)
        
        self.exit_btn = tk.Button(
            btn_frame,
            text="EXIT",
            command=self.on_close,
            bg="#c0392b",
            fg="white",
            activebackground="#e74c3c",
            activeforeground="white",
            width=18,
            font=("Segoe UI", 9, "bold"),
            relief=tk.FLAT,
            cursor="hand2"
        )
        self.exit_btn.pack(side="left", padx=10)
        
        # State
        self.db_available = False
        self.db_error = None
        self.app_launched = False
        self.diagnostics_complete = False
        
        # Auto-start diagnostics after a brief delay
        self.root.after(500, self.start_diagnostics_thread)
    
    def _mask(self, value):
        """Mask sensitive information for display"""
        if not value or value == 'NOT SET':
            return 'NOT SET'
        s = str(value)
        if len(s) <= 4:
            return "*" * len(s)
        # For IPs
        if "." in s and s.replace(".", "").isdigit():
            parts = s.split(".")
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.xx.xxx"
        # General mask
        return s[:3] + "..." + s[-3:]
    
    def log(self, message, level="INFO"):
        """Add message to log with timestamp"""
        def _do_log():
            timestamp = time.strftime("%H:%M:%S")
            self.log_text.insert(tk.END, f"[{timestamp}] [{level}] {message}\n")
            self.log_text.see(tk.END)
        self.root.after(0, _do_log)
    
    def update_status(self, status, progress="", color=None):
        """Update status labels safely"""
        if color is None:
            color = self.theme.COLORS.get('error', '#ef4444')
        def _do_update():
            self.status_label.config(text=status, fg=color)
            self.progress_label.config(text=progress)
        self.root.after(0, _do_update)
    
    def start_diagnostics_thread(self):
        """Start diagnostics in background thread to avoid blocking GUI"""
        self.log("Starting diagnostics in background...", "INFO")
        thread = threading.Thread(target=self.run_diagnostics, daemon=True)
        thread.start()
    
    def skip_db_test(self):
        """Skip database test and launch immediately"""
        self.log("\n[USER ACTION] Skipping database diagnostics...", "WARN")
        self.update_status("⚠️ Launching without DB test", "", self.theme.COLORS['warning'])
        self.continue_btn.config(state="disabled")
        self.skip_btn.config(state="disabled")
        self.root.after(1000, self.launch_main_app)
    
    def run_diagnostics(self):
        """Run diagnostics in background thread"""
        try:
            self.log("="*70, "INFO")
            self.log("LAYER8 SECURITY PLATFORM - DIAGNOSTIC MODE", "INFO")
            self.log("="*70, "INFO")
            
            # Step 1: Environment check
            self.update_status("Checking environment...", "Step 1/4", self.theme.COLORS['info'])
            self.log("\n[STEP 1] Checking environment variables...", "INFO")
            
            try:
                from dotenv import load_dotenv
                load_dotenv()
                self.log("✓ Successfully loaded .env file", "SUCCESS")
                
                # Check key variables
                db_host = os.getenv('L8_DB_HOST', 'NOT SET')
                db_user = os.getenv('MYSQL_USER', 'NOT SET')
                db_name = os.getenv('L8_DB_NAME', 'NOT SET')
                
                self.log(f"  L8_DB_HOST: {self._mask(db_host)}", "INFO")
                self.log(f"  MYSQL_USER: {self._mask(db_user)}", "INFO")
                self.log(f"  L8_DB_NAME: {self._mask(db_name)}", "INFO")
                
            except Exception as e:
                self.log(f"✗ Failed to load .env: {e}", "WARN")
            
            # Step 2: Import check
            self.update_status("Checking imports...", "Step 2/4", self.theme.COLORS['info'])
            self.log("\n[STEP 2] Checking required modules...", "INFO")
            
            missing_modules = []
            
            try:
                import mysql.connector
                self.log("✓ mysql-connector-python is installed", "SUCCESS")
            except ImportError:
                self.log("✗ mysql-connector-python NOT installed!", "ERROR")
                missing_modules.append("mysql-connector-python")
            
            try:
                import nacl.secret
                self.log("✓ PyNaCl is installed", "SUCCESS")
            except ImportError:
                self.log("✗ PyNaCl NOT installed (encryption disabled)", "WARN")
                missing_modules.append("PyNaCl")
            
            try:
                from Crypto.Cipher import AES
                self.log("✓ pycryptodome is installed", "SUCCESS")
            except ImportError:
                self.log("✗ pycryptodome NOT installed (encryption disabled)", "WARN")
                missing_modules.append("pycryptodome")
            
            try:
                from argon2 import PasswordHasher
                self.log("✓ argon2-cffi is installed", "SUCCESS")
            except ImportError:
                self.log("✗ argon2-cffi NOT installed (password hashing disabled)", "WARN")
                missing_modules.append("argon2-cffi")
            
            if missing_modules:
                self.log(f"\n⚠️  Missing modules: {', '.join(missing_modules)}", "WARN")
                self.log("  Run: pip install " + " ".join(missing_modules), "WARN")
            
            try:
                from db_connection import DatabaseConnection
                self.log("✓ db_connection.py found and importable", "SUCCESS")
            except ImportError as e:
                self.log(f"✗ Cannot import db_connection.py: {e}", "ERROR")
                self.finish_diagnostics(False, "Missing db_connection.py - launching in offline mode")
                return
            
            # Step 3: Network test (with timeout)
            self.update_status("Testing network...", "Step 3/4", self.theme.COLORS['info'])
            self.log("\n[STEP 3] Testing network connectivity...", "INFO")
            
            db_host = os.getenv('L8_DB_HOST', '82.197.82.156')
            db_port = int(os.getenv('L8_DB_PORT', '3306'))
            
            self.log(f"Attempting to reach {self._mask(db_host)}:{db_port}...", "INFO")
            
            import socket
            network_ok = False
            try:
                sock = socket.create_connection((db_host, db_port), timeout=5)
                sock.close()
                self.log(f"✓ Network connection to {self._mask(db_host)}:{db_port} successful!", "SUCCESS")
                network_ok = True
            except socket.timeout:
                self.log(f"✗ TIMEOUT: Server at {self._mask(db_host)}:{db_port} not responding", "ERROR")
                self.log("  Possible causes:", "WARN")
                self.log("    - Remote MySQL not enabled in Hostinger", "WARN")
                self.log("    - Your IP not whitelisted", "WARN")
                self.log("    - Firewall blocking port 3306", "WARN")
            except Exception as e:
                self.log(f"✗ Network error: {e}", "ERROR")
            
            if not network_ok:
                self.finish_diagnostics(False, "Network unreachable - launching in offline mode")
                return
            
            # Step 4: Database connection (with timeout)
            self.update_status("Testing database...", "Step 4/4", self.theme.COLORS['info'])
            self.log("\n[STEP 4] Testing MySQL connection (10 second timeout)...", "INFO")
            
            db_success = [False]
            db_error = [None]
            
            def test_db():
                try:
                    db = DatabaseConnection()
                    self.log(f"Connecting to MySQL...", "INFO")
                    self.log(f"  Host: {self._mask(db.host)}", "INFO")
                    self.log(f"  Port: {db.port}", "INFO")
                    self.log(f"  Database: {self._mask(db.database)}", "INFO")
                    self.log(f"  User: {self._mask(db.user)}", "INFO")
                    
                    success, error = db.connect()
                    
                    if success:
                        db_success[0] = True
                        self.log("✓ MySQL connection successful!", "SUCCESS")
                        
                        # Test table
                        self.log("Checking for user_logins table...", "INFO")
                        table_success, table_msg = db.ensure_table_exists()
                        self.log(f"  {table_msg}", "SUCCESS" if table_success else "WARN")
                        
                        db.close()
                    else:
                        db_error[0] = error
                        self.log(f"✗ MySQL connection failed: {error}", "ERROR")
                        
                except Exception as e:
                    db_error[0] = str(e)
                    self.log(f"✗ Exception during database test: {e}", "ERROR")
            
            # Run with timeout
            db_thread = threading.Thread(target=test_db, daemon=True)
            db_thread.start()
            db_thread.join(timeout=10)
            
            if db_thread.is_alive():
                self.log("✗ Database connection TIMEOUT (10 seconds)", "ERROR")
                self.finish_diagnostics(False, "Database timeout - launching in offline mode")
                return
            
            if db_success[0]:
                self.finish_diagnostics(True, None)
            else:
                self.finish_diagnostics(False, db_error[0] or "Unknown database error")
        
        except Exception as e:
            self.log(f"✗ Diagnostic error: {e}", "ERROR")
            import traceback
            self.log(traceback.format_exc(), "ERROR")
            self.finish_diagnostics(False, "Diagnostic error - launching in offline mode")
    
    def finish_diagnostics(self, success, error):
        """Finish diagnostic process safely on main thread"""
        def _do_finish():
            self.diagnostics_complete = True
            self.db_available = success
            self.db_error = error
            
            self.log("\n" + "="*70, "INFO")
            
            if success:
                self.log("DIAGNOSTICS COMPLETE - ALL TESTS PASSED!", "SUCCESS")
                self.log("="*70, "INFO")
                self.update_status("✓ Ready to launch", "All systems operational", self.theme.COLORS['success'])
                
                self.log("\nLaunching main application in 2 seconds...", "INFO")
                self.continue_btn.config(state="normal", text="Launch Now", bg="#27ae60")
                self.skip_btn.config(state="disabled")
                self.root.after(2000, self.launch_main_app)
            else:
                self.log("DIAGNOSTICS COMPLETE - DATABASE UNAVAILABLE", "WARN")
                self.log("="*70, "INFO")
                if error:
                    self.log(f"\nReason: {error}", "WARN")
                self.update_status("⚠️ Database offline", "Can launch without DB", self.theme.COLORS['warning'])
                
                # Enable launch button
                self.continue_btn.config(state="normal", text="Launch Anyway", bg="#27ae60")
                self.skip_btn.config(state="disabled")
                
                self.log("\n✓ You can still use the application in offline mode", "INFO")
                self.log("  Click 'Launch Anyway' to continue", "INFO")
        
        self.root.after(0, _do_finish)
    
    def launch_main_app(self):
        """Signal that we are ready to launch the main application"""
        if self.app_launched:
            return
        
        self.app_launched = True
        self.root.destroy()
    
    def on_close(self):
        """Handle window close"""
        if self.app_launched:
            return # Let the main app handle it
        
        if messagebox.askyesno("Exit", "Are you sure you want to exit?"):
            self.log("\n[USER ACTION] Exiting application...", "INFO")
            self.root.destroy()
            sys.exit(0)
    
    def run(self):
        """Run the launcher and return results"""
        self.root.mainloop()
        return self.db_available, self.db_error

class LoginWindow:
    """Login window with proper error handling"""
    
    def __init__(self, parent, on_success_callback, db_available=True):
        self.parent = parent
        self.on_success_callback = on_success_callback
        self.db_available = db_available
        self.window = None
        self.db = None
        self.login_attempts = 0
        self.max_attempts = 5
        
    def show_login(self):
        """Display the login window"""
        from modern_theme import ModernTheme, ModernButton, ModernEntry, ModernLabel, ModernFrame

        self.window = tk.Toplevel(self.parent)
        self.window.title("Layer8 Security - Login")
        self.window.geometry("480x620")
        self.window.resizable(False, False)
        self.window.configure(bg=ModernTheme.COLORS['bg_primary'])
        
        # Center window
        self.window.update_idletasks()
        x = (self.window.winfo_screenwidth() // 2) - (480 // 2)
        y = (self.window.winfo_screenheight() // 2) - (620 // 2)
        self.window.geometry(f'480x620+{x}+{y}')

        self.window.grab_set()

        # Main container with padding
        main_container = tk.Frame(self.window, bg=ModernTheme.COLORS['bg_primary'])
        main_container.pack(fill=tk.BOTH, expand=True, padx=40, pady=40)

        # Load logo
        logo_path = get_resource_path(os.path.join("Layer8", "Media", "Layer8-logo.png"))
        if os.path.exists(logo_path):
            try:
                img = Image.open(logo_path)
                img = img.resize((100, 100), Image.Resampling.LANCZOS)
                self.logo_img = ImageTk.PhotoImage(img)
                logo_label = tk.Label(main_container, image=self.logo_img, bg=ModernTheme.COLORS['bg_primary'])
                logo_label.pack(pady=(0, 20))
            except Exception:
                pass

        # Title with modern styling
        title_label = ModernLabel(
            main_container,
            text="LAYER8",
            variant="title",
            fg=ModernTheme.COLORS['accent_primary']
        )
        title_label.pack(pady=(0, 5))

        subtitle_label = ModernLabel(
            main_container,
            text="ENTERPRISE SECURITY PLATFORM" if self.db_available else "OFFLINE DIAGNOSTIC MODE",
            variant="small",
            fg=ModernTheme.COLORS['fg_tertiary'] if self.db_available else ModernTheme.COLORS['warning']
        )
        subtitle_label.pack(pady=(0, 30))

        # Login card container with modern frame
        login_frame = ModernFrame(main_container)
        login_frame.pack(fill=tk.BOTH, expand=True)

        # Inner padding frame
        inner_frame = tk.Frame(login_frame, bg=ModernTheme.COLORS['bg_secondary'])
        inner_frame.pack(fill=tk.BOTH, expand=True, padx=ModernTheme.SPACING['xl'], pady=ModernTheme.SPACING['xl'])
        
        # Username field
        ModernLabel(
            inner_frame,
            text="USERNAME",
            variant="tiny",
            fg=ModernTheme.COLORS['fg_secondary']
        ).pack(anchor="w", pady=(0, 8))

        self.username_entry = ModernEntry(
            inner_frame,
            placeholder="Enter your username",
            width=35,
            state=tk.NORMAL if self.db_available else tk.DISABLED
        )
        self.username_entry.pack(fill='x', ipady=12, pady=(0, 24))
        if self.db_available:
            self.username_entry.focus()

        # Password field
        ModernLabel(
            inner_frame,
            text="PASSWORD",
            variant="tiny",
            fg=ModernTheme.COLORS['fg_secondary']
        ).pack(anchor="w", pady=(0, 8))

        self.password_entry = ModernEntry(
            inner_frame,
            placeholder="Enter your password",
            show="*",
            width=35,
            state=tk.NORMAL if self.db_available else tk.DISABLED
        )
        self.password_entry.pack(fill='x', ipady=12, pady=(0, 16))

        # Status label
        self.status_label = ModernLabel(
            inner_frame,
            text="" if self.db_available else "⚠️ DATABASE OFFLINE",
            variant="small",
            fg=ModernTheme.COLORS['error'] if not self.db_available else ModernTheme.COLORS['fg_tertiary']
        )
        self.status_label.pack(pady=(0, 20))

        # Login button with modern styling
        self.login_button = ModernButton(
            inner_frame,
            text="SIGN IN" if self.db_available else "OFFLINE MODE",
            variant="primary",
            command=self.attempt_login,
            state=tk.NORMAL if self.db_available else tk.DISABLED
        )
        self.login_button.pack(fill='x', ipady=6, pady=(0, 16))
        
        # Footer buttons frame
        footer_frame = tk.Frame(inner_frame, bg=ModernTheme.COLORS['bg_secondary'])
        footer_frame.pack(fill="x", pady=(8, 0))

        # Test connection button
        test_button = ModernButton(
            footer_frame,
            text="Test Connection",
            variant="ghost",
            command=self.test_database
        )
        test_button.config(font=ModernTheme.FONTS['small'], padx=8, pady=4)
        test_button.pack(side="left")

        # Bypass for offline
        if not self.db_available:
            bypass_btn = ModernButton(
                footer_frame,
                text="Bypass Login",
                variant="ghost",
                command=lambda: self.on_success_callback(False, "OfflineUser")
            )
            bypass_btn.config(
                font=ModernTheme.FONTS['small'],
                fg=ModernTheme.COLORS['warning'],
                padx=8,
                pady=4
            )
            bypass_btn.pack(side="right")
        
        # Bind Enter key
        if self.db_available:
            self.username_entry.bind('<Return>', lambda e: self.attempt_login())
            self.password_entry.bind('<Return>', lambda e: self.attempt_login())
        
        # Handle window close
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)
        
        logging.info("Login window displayed")
    
    def update_status(self, message, color=None):
        """Update status label safely"""
        from modern_theme import ModernTheme
        if color is None:
            color = ModernTheme.COLORS['error']
        try:
            def _do_update():
                self.status_label.config(text=message, fg=color)
            self.window.after(0, _do_update)
        except:
            pass
    
    def attempt_login(self):
        """Handle login attempt with comprehensive error handling"""
        # Use get_value() for ModernEntry to avoid placeholder text
        username = self.username_entry.get_value().strip() if hasattr(self.username_entry, 'get_value') else self.username_entry.get().strip()
        password = self.password_entry.get_value().strip() if hasattr(self.password_entry, 'get_value') else self.password_entry.get().strip()
        
        # Validation
        if not username or not password:
            self.update_status("Please enter both username and password")
            logging.warning("Login attempt with empty credentials")
            return
        
        # Check max attempts
        self.login_attempts += 1
        if self.login_attempts > self.max_attempts:
            messagebox.showerror(
                "Too Many Attempts",
                "Too many failed login attempts. Application will close."
            )
            logging.error(f"Max login attempts exceeded ({self.max_attempts})")
            self.parent.quit()
            return
        
        # Disable button during login
        self.login_button.config(state=tk.DISABLED, text="Logging in...")
        from modern_theme import ModernTheme
        self.update_status("Connecting to database...", ModernTheme.COLORS['info'])
        
        # Run login in separate thread to prevent GUI freeze
        threading.Thread(
            target=self._perform_login,
            args=(username, password),
            daemon=True
        ).start()
    
    def _perform_login(self, username, password):
        """Perform actual login in background thread"""
        try:
            logging.info(f"Login attempt {self.login_attempts} for user: {username}")
            
            # Create database connection
            from db_connection import DatabaseConnection
            self.db = DatabaseConnection()
            
            # Connect to database
            success, error = self.db.connect()
            
            if not success:
                logging.error(f"Database connection failed: {error}")
                self.window.after(0, lambda: self._login_failed(
                    f"Database connection failed:\n\n{error}"
                ))
                return
            
            logging.info("Database connected, verifying credentials...")
            
            # Verify credentials
            success, result = self.db.verify_login(username, password)
            
            if success:
                logging.info(f"Login successful for {username}")
                user_data = result
                
                # Close connection
                self.db.close()
                
                # Call success callback on main thread
                self.window.after(0, lambda: self._login_success(user_data))
            else:
                logging.warning(f"Login failed for {username}: {result}")
                self.db.close()
                
                # Show error on main thread
                self.window.after(0, lambda: self._login_failed(result))
        
        except Exception as e:
            error_msg = f"Unexpected error during login: {str(e)}"
            logging.error(error_msg, exc_info=True)
            
            # Show error on main thread
            self.window.after(0, lambda: self._login_failed(error_msg))
    
    def _login_success(self, user_data):
        """Handle successful login (runs on main thread)"""
        try:
            is_admin = user_data.get('is_admin', False)
            username = user_data.get('username', 'Unknown')
            
            logging.info(f"Login success handler called for {username}")
            
            # Close login window
            if self.window:
                self.window.destroy()
            
            # Call success callback
            if self.on_success_callback:
                self.on_success_callback(is_admin, username)
            
        except Exception as e:
            logging.error(f"Error in login success handler: {e}", exc_info=True)
            messagebox.showerror("Error", f"Login succeeded but app failed to load: {e}")
    
    def _login_failed(self, error_message):
        """Handle failed login (runs on main thread)"""
        try:
            # Re-enable button
            self.login_button.config(state=tk.NORMAL, text="Login")
            
            # Update status
            self.update_status(f"Login failed: {error_message[:50]}...")
            
            # Show detailed error in messagebox
            messagebox.showerror(
                "Login Failed",
                error_message + f"\n\nAttempt {self.login_attempts} of {self.max_attempts}"
            )
            
            # Clear password
            self.password_entry.delete(0, tk.END)
            self.password_entry.focus()
            
        except Exception as e:
            logging.error(f"Error in login failure handler: {e}", exc_info=True)
    
    def test_database(self):
        """Test database connection"""
        from modern_theme import ModernTheme
        self.update_status("Testing database connection...", ModernTheme.COLORS['info'])
        self.login_button.config(state=tk.DISABLED)

        threading.Thread(target=self._perform_test, daemon=True).start()
    
    def _perform_test(self):
        """Perform database test in background"""
        try:
            from db_connection import DatabaseConnection
            db = DatabaseConnection()
            success, message = db.test_connection()
            db.close()
            
            if success:
                self.window.after(0, lambda: self._show_test_result(True, message))
            else:
                self.window.after(0, lambda: self._show_test_result(False, message))
        
        except Exception as e:
            error_msg = f"Test failed: {str(e)}"
            self.window.after(0, lambda: self._show_test_result(False, error_msg))
    
    def _show_test_result(self, success, message):
        """Show test results"""
        from modern_theme import ModernTheme
        self.login_button.config(state=tk.NORMAL)

        if success:
            self.update_status("Connection successful!", ModernTheme.COLORS['success'])
            messagebox.showinfo("Success", f"✅ {message}\n\nDefault credentials:\nUsername: Layer8Wes\nPassword: Valorant123!")
        else:
            self.update_status("Connection failed", ModernTheme.COLORS['error'])
            messagebox.showerror("Connection Failed", f"❌ {message}\n\nCheck gui_app.log for details")
    
    def on_close(self):
        """Handle window close"""
        result = messagebox.askyesno(
            "Exit",
            "Are you sure you want to exit?"
        )
        if result:
            logging.info("User cancelled login")
            self.parent.quit()

def get_resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)

def get_db_path():
    db_name = "db.sqlite3"
    if getattr(sys, 'frozen', False):
        # The application is bundled by PyInstaller
        exe_dir = os.path.dirname(sys.executable)
        local_db = os.path.join(exe_dir, db_name)
        
        # If the database doesn't exist next to the exe, copy it from the bundle
        if not os.path.exists(local_db):
            try:
                bundled_db = os.path.join(sys._MEIPASS, db_name)
                if os.path.exists(bundled_db):
                    shutil.copy2(bundled_db, local_db)
            except:
                pass
        return local_db
    else:
        # The application is running in a normal Python environment
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), db_name)


def main(db_available=None, db_error=None):
    # If not provided, run the diagnostic launcher
    if db_available is None:
        launcher = DebugLauncher()
        db_available, db_error = launcher.run()
        # If the launcher was closed without triggering a launch, exit
        if not getattr(launcher, 'app_launched', False):
            return
        
    # Re-setup logging for the main app
    log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'gui_app.log')
    logging.basicConfig(filename=log_file, level=logging.INFO, 
                        format='%(asctime)s - %(levelname)s - %(message)s', force=True)
    logging.info(f"Main application starting (DB available: {db_available})")

    # Database path (SQLite fallback check)
    db_path = get_db_path()
    logging.info(f"Local database path: {db_path}")

    root = tk.Tk()
    logging.info("Tkinter root created.")
    root.title("Layer8 GUI Application")
    root.geometry("650x750")
    root.resizable(False, False)

    # Create menu bar
    menu_bar = tk.Menu(root)
    root.config(menu=menu_bar)

    # File Menu
    file_menu = tk.Menu(menu_bar, tearoff=0)
    menu_bar.add_cascade(label="File", menu=file_menu)
    file_menu.add_command(label="Exit", command=root.destroy)

    # ADD UPDATER (this creates Help menu with "Check for Updates")
    updater = add_updater_to_gui(
        root=root,
        menu_bar=menu_bar,
        current_version="1.0.1",
        update_url="https://api.github.com/repos/Wesley-Hatch/Layer8-GUI/releases/latest"
    )
    
    # Delay overrideredirect to ensure window is properly initialized
    def apply_overrideredirect():
        try:
            root.overrideredirect(True)
            logging.info("Overrideredirect(True) applied.")
        except Exception as e:
            logging.error(f"Error applying overrideredirect: {e}")
    
    # root.after(100, apply_overrideredirect) # Relocated to on_login_success

    # Import modern theme
    from modern_theme import ModernTheme, ModernButton, ModernLabel, ModernFrame

    # Define colors for dark mode using ModernTheme
    bg_color = tk.StringVar(value=ModernTheme.COLORS['bg_primary'])
    fg_color = ModernTheme.COLORS['fg_primary']
    title_bar_color = tk.StringVar(value=ModernTheme.COLORS['bg_secondary'])
    accent_color = tk.StringVar(value=ModernTheme.COLORS['accent_primary']) 

    def update_colors():
        root.configure(bg=bg_color.get())
        title_bar.configure(bg=title_bar_color.get())
        title_label.configure(bg=title_bar_color.get())
        exit_button.configure(bg=title_bar_color.get())
        min_button.configure(bg=title_bar_color.get())
        canvas.configure(bg=bg_color.get())
        style.configure("TNotebook", background=bg_color.get())
        style.map("TNotebook.Tab", background=[('selected', bg_color.get())])

    root.configure(bg=bg_color.get())

    # TTK Style for dark mode using ModernTheme
    style = ttk.Style()
    ModernTheme.apply_ttk_style(style)

    # Use Modern styles
    style.configure("Treeview",
                    background=ModernTheme.COLORS['bg_secondary'],
                    foreground=ModernTheme.COLORS['fg_primary'],
                    fieldbackground=ModernTheme.COLORS['bg_secondary'],
                    borderwidth=0,
                    font=ModernTheme.FONTS['body'],
                    rowheight=28)
    style.map("Treeview", background=[('selected', ModernTheme.COLORS['bg_tertiary'])])
    style.configure("Treeview.Heading",
                    background=ModernTheme.COLORS['bg_primary'],
                    foreground=ModernTheme.COLORS['accent_primary'],
                    relief="flat",
                    font=ModernTheme.FONTS['body_bold'])

    # Notebook Styling
    style.configure("TNotebook", background=bg_color.get(), borderwidth=0)
    style.configure("TNotebook.Tab",
                    background=ModernTheme.COLORS['bg_secondary'],
                    foreground=ModernTheme.COLORS['fg_secondary'],
                    padding=[18, 10],
                    font=ModernTheme.FONTS['body_bold'])
    style.map("TNotebook.Tab",
              background=[('selected', bg_color.get())],
              foreground=[('selected', ModernTheme.COLORS['accent_primary'])])

    # Progressbar Styling
    style.configure("Horizontal.TProgressbar",
                    thickness=12,
                    troughcolor=ModernTheme.COLORS['bg_secondary'],
                    background=ModernTheme.COLORS['accent_primary'],
                    borderwidth=0)

    # Scrollbar Styling
    style.configure("Vertical.TScrollbar",
                    gripcount=0,
                    background=ModernTheme.COLORS['bg_tertiary'],
                    darkcolor=ModernTheme.COLORS['bg_secondary'],
                    lightcolor=ModernTheme.COLORS['bg_secondary'],
                    troughcolor=ModernTheme.COLORS['bg_secondary'],
                    bordercolor=ModernTheme.COLORS['bg_secondary'],
                    arrowcolor=ModernTheme.COLORS['accent_primary'])

    # Custom Title Bar implementation with modern design
    title_bar = tk.Frame(root, bg=title_bar_color.get(), relief="flat", bd=0, height=40)
    title_bar.pack(side="top", fill="x")

    # Title label with modern font
    title_label = ModernLabel(
        title_bar,
        text="LAYER8 SECURITY PLATFORM",
        variant="body_bold",
        bg=title_bar_color.get(),
        fg=ModernTheme.COLORS['accent_primary']
    )
    title_label.pack(side="left", padx=16, pady=8)

    # Exit button
    def close_window():
        root.destroy()

    exit_button = tk.Button(
        title_bar,
        text="✕",
        command=close_window,
        bg=title_bar_color.get(),
        fg=fg_color,
        bd=0,
        activebackground=ModernTheme.COLORS['error'],
        activeforeground="#ffffff",
        font=ModernTheme.FONTS['subheading'],
        width=3,
        cursor="hand2"
    )
    exit_button.pack(side="right", padx=2)

    # Minimize button
    def minimize_window():
        root.withdraw()
        root.overrideredirect(False)
        root.iconify()

    def on_map(event):
        root.overrideredirect(True)

    # root.bind("<Map>", on_map)

    min_button = tk.Button(
        title_bar,
        text="—",
        command=minimize_window,
        bg=title_bar_color.get(),
        fg=fg_color,
        bd=0,
        activebackground=ModernTheme.COLORS['bg_tertiary'],
        activeforeground=fg_color,
        font=ModernTheme.FONTS['subheading'],
        width=3,
        cursor="hand2"
    )
    min_button.pack(side="right", padx=2)

    # Dragging functionality
    def start_move(event):
        root.x = event.x
        root.y = event.y

    def stop_move(event):
        root.x = None
        root.y = None

    def on_move(event):
        deltax = event.x - root.x
        deltay = event.y - root.y
        x = root.winfo_x() + deltax
        y = root.winfo_y() + deltay
        root.geometry(f"+{x}+{y}")

    title_bar.bind("<Button-1>", start_move)
    title_bar.bind("<ButtonRelease-1>", stop_move)
    title_bar.bind("<B1-Motion>", on_move)
    title_label.bind("<Button-1>", start_move)
    title_label.bind("<ButtonRelease-1>", stop_move)
    title_label.bind("<B1-Motion>", on_move)
    

    # Create a canvas to hold the background and allow "transparency"
    canvas = tk.Canvas(root, width=425, height=750, bg=bg_color.get(), highlightthickness=0, bd=0)
    canvas.pack(fill="both", expand=True)

    # Path to the logo
    logo_path = get_resource_path(os.path.join("Layer8", "Media", "Layer8-logo.png"))

    # Set window icon and background image on canvas
    bg_image_id = None
    if os.path.exists(logo_path):
        try:
            img = Image.open(logo_path)
            icon = ImageTk.PhotoImage(img)
            root.iconphoto(True, icon)

            # Background logo (initially centered)
            bg_image = ImageTk.PhotoImage(img)
            root.bg_image = bg_image
            bg_image_id = canvas.create_image(212, 375, image=bg_image, anchor="center")
        except Exception:
            pass
    else:
        pass

    def update_window_size(width=None, target_height=None, centered_items=None):
        root.update_idletasks()
        
        padding = 30
        # Determine base minimum width
        required_width = width if width else 650
        
        max_y = 0
        max_centered_item_width = 0
        
        items = canvas.find_all()
        for item in items:
            if item == bg_image_id: continue
            bbox = canvas.bbox(item)
            if not bbox: continue
            
            max_y = max(max_y, bbox[3])
            
            # If it's a centered item, it dictates the symmetrical width requirements
            if centered_items and item in centered_items:
                item_width = bbox[2] - bbox[0]
                max_centered_item_width = max(max_centered_item_width, item_width)
            else:
                # For non-centered items, just ensure they fit within the window.
                # We use a smaller safety margin (10) to avoid feedback loops with 
                # right-aligned elements that are placed at 'width - 20'.
                required_width = max(required_width, bbox[2] + 10)

        # Final width calculation: 
        # Widest centered item + padding on both sides OR the base/others width.
        required_width = max(required_width, max_centered_item_width + (2 * padding))

        title_bar_height = title_bar.winfo_height()
        if title_bar_height <= 1: title_bar_height = 30

        content_height = max_y + padding
        if target_height:
            content_height = max(content_height, target_height - title_bar_height)
        else:
            content_height = max(content_height, 150)
        
        total_height = content_height + title_bar_height
        
        canvas.config(width=required_width, height=content_height)
        root.geometry(f"{int(required_width)}x{int(total_height)}")
        
        # Re-center horizontal items based on the NEW center
        new_center_x = required_width / 2
        
        # Re-center the background logo
        if bg_image_id:
            canvas.coords(bg_image_id, new_center_x, content_height / 2)
            
        # Update any centered text/windows
        if centered_items:
            for item_id in centered_items:
                coords = canvas.coords(item_id)
                if coords:
                    canvas.coords(item_id, new_center_x, coords[1])

    def clear_canvas():
        # Remove all widgets added to the canvas via create_window
        # and delete all other canvas items except the background image
        for item in canvas.find_all():
            if item != bg_image_id: # Keep the background logo
                if canvas.type(item) == "window":
                    widget_path = canvas.itemcget(item, "window")
                    if widget_path:
                        try:
                            root.nametowidget(widget_path).destroy()
                        except:
                            pass
                canvas.delete(item)

    persistent_target = [""]
    scanner_instance = [None]
    status_text = None

    def show_main_menu(username, is_admin=False, db_available=True):
        nonlocal status_text
        from scanner_tools import ScannerTools
        from ai_analyzer import AIAnalyzer
        clear_canvas()

        # Create status_text for tooltips and messages
        status_text = canvas.create_text(212, 65, text="Hover over tools for help", fill="#aaaaaa", font=("Arial", 10, "bold"), anchor="center")

        def show_admin_panel():
            clear_canvas()
            admin_title_id = canvas.create_text(212, 40, text="Admin Panel - User Management", fill=fg_color, font=("Arial", 14, "bold"), anchor="center")
            
            # Back to Main Menu
            back_btn = tk.Button(root, text="Back", bg="#444444", fg=fg_color, bd=0, command=lambda: show_main_menu(username, is_admin, db_available))
            canvas.create_window(20, 40, window=back_btn, anchor="w")

            # List users
            canvas.create_text(20, 80, text="Current Users:", fill=fg_color, font=("Arial", 10, "bold"), anchor="w")
            
            user_list_frame = tk.Frame(root, bg="#1e1e1e")
            user_list_id = canvas.create_window(212, 180, window=user_list_frame, anchor="center")
            
            user_list_box = tk.Text(user_list_frame, bg="#1e1e1e", fg=fg_color, font=("Consolas", 9), bd=0, height=10, width=50, padx=10, pady=5, highlightthickness=0, wrap="none")
            
            ul_vscroll = tk.Scrollbar(user_list_frame, command=user_list_box.yview)
            ul_vscroll.pack(side="right", fill="y")
            ul_hscroll = tk.Scrollbar(user_list_frame, orient="horizontal", command=user_list_box.xview)
            ul_hscroll.pack(side="bottom", fill="x")
            
            user_list_box.pack(side="left", fill="both", expand=True)
            user_list_box.config(yscrollcommand=ul_vscroll.set, xscrollcommand=ul_hscroll.set)
            
            try:
                from db_connection import DatabaseConnection
                # Use DatabaseConnection module
                db = DatabaseConnection()
                success, error = db.connect()
                if success:
                    cursor = db.connection.cursor(dictionary=True)
                    cursor.execute("SELECT username, email, is_admin FROM user_logins")
                    users = cursor.fetchall()
                    db.close()
                    
                    user_list_box.config(state="normal")
                    user_list_box.insert("1.0", f"{'Username':<15} {'Email':<20} {'Admin':<5}\n")
                    user_list_box.insert("2.0", "-"*50 + "\n")
                    for u in users:
                        user_list_box.insert(tk.END, f"{u.get('username', 'N/A'):<15} {u.get('email', 'N/A'):<20} {str(bool(u.get('is_admin', 0))):<5}\n")
                    user_list_box.config(state="disabled")
                else:
                    messagebox.showerror("Error", "Failed to connect to MySQL database.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to fetch users: {e}")

            # Account Creation
            canvas.create_text(20, 280, text="Create New Account:", fill=fg_color, font=("Arial", 10, "bold"), anchor="w")
            
            canvas.create_text(20, 310, text="Username:", fill=fg_color, font=("Arial", 9), anchor="w")
            new_user_entry = tk.Entry(root, bg="#444444", fg=fg_color, bd=0, width=20)
            canvas.create_window(100, 310, window=new_user_entry, anchor="w")

            canvas.create_text(20, 340, text="Email:", fill=fg_color, font=("Arial", 9), anchor="w")
            new_email_entry = tk.Entry(root, bg="#444444", fg=fg_color, bd=0, width=20)
            canvas.create_window(100, 340, window=new_email_entry, anchor="w")

            canvas.create_text(20, 370, text="Password:", fill=fg_color, font=("Arial", 9), anchor="w")
            new_pass_entry = tk.Entry(root, bg="#444444", fg=fg_color, bd=0, width=20)
            canvas.create_window(100, 370, window=new_pass_entry, anchor="w")

            is_admin_var = tk.BooleanVar()
            admin_cb = tk.Checkbutton(root, text="Admin", variable=is_admin_var, bg=bg_color.get(), fg=fg_color, selectcolor="#1e1e1e", activebackground=bg_color.get(), activeforeground=fg_color)
            canvas.create_window(250, 340, window=admin_cb, anchor="w")

            def create_account(event=None):
                u = new_user_entry.get().strip()
                e = new_email_entry.get().strip()
                p = new_pass_entry.get().strip()
                adm = 1 if is_admin_var.get() else 0
                
                if not u or not p:
                    messagebox.showwarning("Input Error", "Username and Password are required.")
                    return
                
                try:
                    from db_connection import DatabaseConnection
                    # Use DatabaseConnection module
                    db = DatabaseConnection()
                    success, message = db.create_user(u, p, e, bool(adm))
                    if success:
                        db.close()
                        messagebox.showinfo("Success", message)
                        show_admin_panel() # Refresh
                    else:
                        messagebox.showerror("Database Error", message)
                except Exception as err:
                    messagebox.showerror("Database Error", f"Error: {err}")

            # Bind Enter key to create account
            new_user_entry.bind("<Return>", create_account)
            new_email_entry.bind("<Return>", create_account)
            new_pass_entry.bind("<Return>", create_account)

            create_btn = tk.Button(root, text="Create User", bg="#226622", fg=fg_color, bd=0, width=15, command=create_account)
            create_btn_id = canvas.create_window(212, 420, window=create_btn, anchor="center")

            update_window_size(width=650, target_height=750, centered_items=[admin_title_id, user_list_id, create_btn_id])

        # Welcome Message
        welcome_id = canvas.create_text(212, 40, text=f"WELCOME, {username.upper()}", fill="#00ff00", font=("Segoe UI", 16, "bold"), anchor="center")
    
        # --- Target Selection Section ---
        target_label_id = canvas.create_text(212, 80, text="TARGET ADDRESS / DOMAIN", fill="#aaaaaa", font=("Segoe UI", 8, "bold"), anchor="center")
        
        target_frame = tk.Frame(root, bg="#1e1e1e", padx=5, pady=5)
        target_entry = tk.Entry(target_frame, bg="#2b2b2b", fg="#ffffff", insertbackground="#00ff00", bd=0, width=40, font=("Consolas", 11))
        target_entry.insert(0, persistent_target[0])
        target_entry.pack(ipady=5)
        target_window_id = canvas.create_window(212, 110, window=target_frame, anchor="center")

        def update_target(event=None):
            persistent_target[0] = target_entry.get()
        target_entry.bind("<KeyRelease>", update_target)

        # --- Activity Reports ---
        log_label_id = canvas.create_text(20, 460, text="ACTIVITY REPORTS", fill="#00ff00", font=("Segoe UI", 9, "bold"), anchor="w")
        
        summary_frame = tk.Frame(root, bg="#1e1e1e", bd=1, highlightbackground="#333333", highlightthickness=1)
        summary_id = canvas.create_window(212, 580, window=summary_frame, anchor="center")
        
        columns = ("Time", "Tool/Task", "Status", "Report")
        activity_tree = ttk.Treeview(summary_frame, columns=columns, show="headings", height=10, style="Treeview")
        activity_tree.heading("Time", text="Time")
        activity_tree.heading("Tool/Task", text="Tool/Task")
        activity_tree.heading("Status", text="Status")
        activity_tree.heading("Report", text="Report")
        activity_tree.column("Time", width=80, anchor="center")
        activity_tree.column("Tool/Task", width=150, anchor="w")
        activity_tree.column("Status", width=80, anchor="center")
        activity_tree.column("Report", width=290, anchor="w")
        
        v_scrollbar = tk.Scrollbar(summary_frame, command=activity_tree.yview)
        v_scrollbar.pack(side="right", fill="y")
        
        h_scrollbar = tk.Scrollbar(summary_frame, orient="horizontal", command=activity_tree.xview)
        h_scrollbar.pack(side="bottom", fill="x")
        
        activity_tree.pack(side="left", fill="both", expand=True)
        activity_tree.config(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)

        def refresh_reports():
            # Refresh the activity tree from scanner history
            def update():
                activity_tree.delete(*activity_tree.get_children())
                for idx, item in enumerate(scanner.history):
                    # Insert at index 0 to show latest at top
                    activity_tree.insert("", 0, iid=str(idx), values=(item.get("time", "N/A"), item["cmd"], item["status"], "Double-click to View/Download"))
                
                # Expand window if needed
                if len(scanner.history) > 0:
                    update_window_size(width=650, centered_items=[welcome_id, summary_id])
            root.after(0, update)

        def show_report_details(event):
            selected = activity_tree.selection()
            if not selected: return
            idx_str = selected[0]
            try:
                idx = int(idx_str)
                report_item = scanner.history[idx]
            except (ValueError, IndexError): return
            
            detail_win = tk.Toplevel(root)
            detail_win.overrideredirect(True)
            detail_win.geometry("600x500")
            detail_win.configure(bg="#1e1e1e")
            
            # Custom Title Bar for Report Popup
            popup_title_bar = tk.Frame(detail_win, bg=title_bar_color.get(), relief="raised", bd=0, height=30)
            popup_title_bar.pack(side="top", fill="x")

            tk.Label(popup_title_bar, text=f"Report: {report_item['cmd']}", bg=title_bar_color.get(), fg=fg_color, font=("Arial", 10)).pack(side="left", padx=10)

            tk.Button(popup_title_bar, text="✕", command=detail_win.destroy, bg=title_bar_color.get(), fg=fg_color, 
                      bd=0, activebackground="red", activeforeground=fg_color, font=("Arial", 12), width=3).pack(side="right")

            # Dragging functionality for Report Popup
            def start_move_popup(event):
                detail_win.x = event.x
                detail_win.y = event.y

            def on_move_popup(event):
                deltax = event.x - detail_win.x
                deltay = event.y - detail_win.y
                x = detail_win.winfo_x() + deltax
                y = detail_win.winfo_y() + deltay
                detail_win.geometry(f"+{x}+{y}")

            popup_title_bar.bind("<Button-1>", start_move_popup)
            popup_title_bar.bind("<B1-Motion>", on_move_popup)

            title_label = tk.Label(detail_win, text=f"Command Report: {report_item['cmd']}", bg="#1e1e1e", fg=accent_color.get(), font=("Arial", 12, "bold"))
            title_label.pack(pady=10)

            info_frame = tk.Frame(detail_win, bg="#1e1e1e")
            info_frame.pack(fill="x", padx=20)
            tk.Label(info_frame, text=f"Time: {report_item.get('time', 'N/A')}", bg="#1e1e1e", fg="#aaaaaa").pack(side="left")
            tk.Label(info_frame, text=f"Status: {report_item['status']}", bg="#1e1e1e", fg="#aaaaaa").pack(side="right")
            
            text_frame = tk.Frame(detail_win, bg="#1e1e1e")
            text_frame.pack(fill="both", expand=True, padx=20, pady=10)
            
            v_scroll = tk.Scrollbar(text_frame)
            v_scroll.pack(side="right", fill="y")
            
            text_area = tk.Text(text_frame, bg="#000000", fg="#00ff00", insertbackground="#00ff00", bd=0, font=("Consolas", 9), yscrollcommand=v_scroll.set)
            text_area.insert("1.0", report_item.get("full_log", "No log available."))
            text_area.config(state="disabled")
            text_area.pack(side="left", fill="both", expand=True)
            v_scroll.config(command=text_area.yview)
            
            def download_report():
                from tkinter import filedialog
                fpath = filedialog.asksaveasfilename(defaultextension=".txt", 
                                                     filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                                                     initialfile=f"Report_{report_item['cmd'].replace(' ', '_').replace('/', '_')}.txt")
                if fpath:
                    try:
                        with open(fpath, "w", encoding="utf-8") as f:
                            f.write(report_item.get("full_log", ""))
                        messagebox.showinfo("Success", f"Report saved to:\n{fpath}")
                    except Exception as e:
                        messagebox.showerror("Error", f"Failed to save report: {e}")
            
            download_btn = tk.Button(detail_win, text="Download Report (.txt)", bg="#226622", fg=fg_color, bd=0, padx=10, pady=5, font=("Arial", 10, "bold"), command=download_report)
            download_btn.pack(pady=15)

        activity_tree.bind("<Double-1>", show_report_details)

        def log_to_tree(message, is_error=False):
            # This now only handles general logging if needed, 
            # but we use refresh_reports for the actual reports.
            # We keep it as a placeholder to satisfy ScannerTools initialization.
            pass

        # Initialize or reuse Scanner Tools
        if scanner_instance[0] is None:
            scanner_instance[0] = ScannerTools(log_to_tree, is_admin=is_admin)
        else:
            scanner_instance[0].log_callback = log_to_tree
            # Finding and progress callbacks will be set when running tools
        scanner = scanner_instance[0]
        
        # Initial refresh of reports if history exists
        if scanner.history:
            refresh_reports()

        def show_tool_screen(tool_name, tool_func):
            nonlocal status_text
            clear_canvas()
            # Create status_text for tooltips and messages in tool screen
            status_text = canvas.create_text(212, 20, text="", fill="#00ff00", font=("Segoe UI", 9, "bold"), anchor="center")
            
            tool_title_id = canvas.create_text(212, 45, text=tool_name.upper(), fill="#ffffff", font=("Segoe UI", 16, "bold"), anchor="center")
            
            # Back to Main Menu
            def go_back():
                canvas.coords(status_text, 212, 25) # Reset status_text position
                show_main_menu(username, is_admin, db_available)

            back_btn = tk.Button(root, text="← BACK", bg="#1e1e1e", fg="#aaaaaa", bd=0, font=("Segoe UI", 8, "bold"), 
                                 activebackground="#333333", activeforeground="#ffffff", cursor="hand2", command=go_back)
            canvas.create_window(20, 25, window=back_btn, anchor="w")

            # Target Selection in tool screen
            target_label_id = canvas.create_text(212, 80, text="TARGET ADDRESS / DOMAIN", fill="#aaaaaa", font=("Segoe UI", 8, "bold"), anchor="center")
            
            target_frame = tk.Frame(root, bg="#1e1e1e", padx=5, pady=5)
            tool_target_entry = tk.Entry(target_frame, bg="#2b2b2b", fg="#ffffff", insertbackground="#00ff00", bd=0, width=40, font=("Consolas", 11))
            tool_target_entry.insert(0, persistent_target[0])
            tool_target_entry.pack(ipady=5)
            target_window_id = canvas.create_window(212, 110, window=target_frame, anchor="center")

            def update_tool_target(event=None):
                persistent_target[0] = tool_target_entry.get()
            tool_target_entry.bind("<KeyRelease>", update_tool_target)

            current_y = 145

            # Common Variables for Tool Screens
            scan_type_var = tk.StringVar(value="Standard")
            brute_type_var = tk.StringVar(value="Common Directories")
            audit_type_var = tk.StringVar(value="Full Firewall Audit")
            hours_var = tk.StringVar(value="0")
            mins_var = tk.StringVar(value="5")
            
            # Traffic Monitor Custom UI
            if "Traffic Monitor" in tool_name:
                canvas.create_text(20, current_y, text="DURATION", fill="#aaaaaa", font=("Segoe UI", 8, "bold"), anchor="w")
                
                h_spinner = tk.Spinbox(root, from_=0, to=23, width=3, textvariable=hours_var, bg="#1e1e1e", fg="#ffffff", bd=0, buttonbackground="#333333", font=("Segoe UI", 9))
                canvas.create_window(100, current_y, window=h_spinner, anchor="w")
                canvas.create_text(135, current_y, text="h", fill="#00ff00", font=("Segoe UI", 9, "bold"), anchor="w")
                
                m_spinner = tk.Spinbox(root, from_=0, to=59, width=3, textvariable=mins_var, bg="#1e1e1e", fg="#ffffff", bd=0, buttonbackground="#333333", font=("Segoe UI", 9))
                canvas.create_window(160, current_y, window=m_spinner, anchor="w")
                canvas.create_text(195, current_y, text="m", fill="#00ff00", font=("Segoe UI", 9, "bold"), anchor="w")
                
                def export_action():
                    from tkinter import filedialog
                    fpath = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx"), ("All files", "*.*")])
                    if fpath:
                        scanner.export_monitor_to_excel(fpath)
                
                export_btn = tk.Button(root, text="EXPORT EXCEL", bg="#1e1e1e", fg="#00ff00", bd=0, font=("Segoe UI", 8, "bold"), 
                                       activebackground="#333333", activeforeground="#00ff00", cursor="hand2", command=export_action)
                canvas.create_window(300, current_y, window=export_btn, anchor="w")
                
                current_y += 35
                # Assign dummy for compatibility
                intensity_scale = tk.Scale(root)
                intensity_scale.set(3)
            
            # Scan Type Selection (Nmap only)
            elif "Nmap/Nessus" in tool_name:
                canvas.create_text(20, current_y, text="SCAN TYPE", fill="#aaaaaa", font=("Segoe UI", 8, "bold"), anchor="w")
                scan_type_opt = tk.OptionMenu(root, scan_type_var, "Standard", "Super sneaky", "Loud")
                scan_type_opt.config(bg="#1e1e1e", fg="#ffffff", bd=0, highlightthickness=0, activebackground="#333333", width=15, font=("Segoe UI", 9))
                scan_type_opt["menu"].config(bg="#1e1e1e", fg="#ffffff", font=("Segoe UI", 9))
                canvas.create_window(120, current_y, window=scan_type_opt, anchor="w")
                current_y += 35
            
            # DirBrute Selection
            elif "DirBrute" in tool_name:
                canvas.create_text(20, current_y, text="BRUTE TYPE", fill="#aaaaaa", font=("Segoe UI", 8, "bold"), anchor="w")
                brute_opt = tk.OptionMenu(root, brute_type_var, "Common Directories", "Sensitive Files", "PHP Files", "ASPX Files", "API Endpoints", "Full Brute")
                brute_opt.config(bg="#1e1e1e", fg="#ffffff", bd=0, highlightthickness=0, activebackground="#333333", width=20, font=("Segoe UI", 9))
                brute_opt["menu"].config(bg="#1e1e1e", fg="#ffffff", font=("Segoe UI", 9))
                canvas.create_window(120, current_y, window=brute_opt, anchor="w")
                current_y += 35
                # Assign dummy for compatibility
                intensity_scale = tk.Scale(root)
                intensity_scale.set(3)

            # Firewall Audit Selection
            elif "Firewall Audit" in tool_name:
                canvas.create_text(20, current_y, text="AUDIT TYPE", fill="#aaaaaa", font=("Segoe UI", 8, "bold"), anchor="w")
                audit_opt = tk.OptionMenu(root, audit_type_var, "Stealth Audit (ICMP)", "Management Interface Discovery", "Evasion & Fragmentation Test", "Egress Leak Test", "Full Firewall Audit")
                audit_opt.config(bg="#1e1e1e", fg="#ffffff", bd=0, highlightthickness=0, activebackground="#333333", width=30, font=("Segoe UI", 9))
                audit_opt["menu"].config(bg="#1e1e1e", fg="#ffffff", font=("Segoe UI", 9))
                canvas.create_window(120, current_y, window=audit_opt, anchor="w")
                current_y += 35
                # Assign dummy for compatibility
                intensity_scale = tk.Scale(root)
                intensity_scale.set(3)

            # Intensity Slider / Payload List / Custom Command (Conditional)
            is_sql_tool = any(x in tool_name for x in ["SQLMap-Lite", "XSS-to-SQL", "NoSQL Injector", "DB Breacher"])
            is_custom_cmd = "Custom Cmd" in tool_name
            is_dir_brute = "DirBrute" in tool_name
            is_firewall_audit = "Firewall Audit" in tool_name
            
            payload_list_var = tk.StringVar(value="Auth Bypass")
            custom_cmd_var = tk.StringVar(value="ping -n 4 {target}")
            
            if is_sql_tool:
                canvas.create_text(20, current_y, text="PAYLOAD LIST", fill="#aaaaaa", font=("Segoe UI", 8, "bold"), anchor="w")
                payload_opt = tk.OptionMenu(root, payload_list_var, "Auth Bypass", "Error Based", "UNION Based", "Blind (Time)", "Polyglot")
                payload_opt.config(bg="#1e1e1e", fg="#ffffff", bd=0, highlightthickness=0, activebackground="#333333", width=15, font=("Segoe UI", 9))
                payload_opt["menu"].config(bg="#1e1e1e", fg="#ffffff", font=("Segoe UI", 9))
                canvas.create_window(120, current_y, window=payload_opt, anchor="w")
                
                payload_desc = canvas.create_text(280, current_y, text="(Login Bypass)", fill="#00ff00", font=("Segoe UI", 8, "italic"), anchor="w")
                def update_payload_desc(*args):
                    descs = {
                        "Auth Bypass": "(Login Bypass)",
                        "Error Based": "(Detailed Errors)",
                        "UNION Based": "(Data Extraction)",
                        "Blind (Time)": "(Inference)",
                        "Polyglot": "(Cross-Database)"
                    }
                    canvas.itemconfig(payload_desc, text=descs.get(payload_list_var.get(), ""))
                payload_list_var.trace_add("write", update_payload_desc)
                
                # Assign dummy for compatibility
                intensity_scale = tk.Scale(root)
                intensity_scale.set(3)
            elif is_custom_cmd:
                canvas.create_text(20, current_y, text="COMMAND TEMPLATE", fill="#aaaaaa", font=("Segoe UI", 8, "bold"), anchor="w")
                cmd_entry = tk.Entry(root, textvariable=custom_cmd_var, bg="#1e1e1e", fg="#ffffff", insertbackground="#00ff00", bd=0, width=45, font=("Consolas", 10))
                canvas.create_window(120, current_y, window=cmd_entry, anchor="w")
                
                current_y += 30
                canvas.create_text(120, current_y, text="Use {target} as a placeholder for the address.", fill="#666666", font=("Segoe UI", 8, "italic"), anchor="w")
                
                # Assign dummy for compatibility
                intensity_scale = tk.Scale(root)
                intensity_scale.set(3)
            elif is_dir_brute or is_firewall_audit:
                # Dummy for compatibility, UI already added above
                intensity_scale = tk.Scale(root)
                intensity_scale.set(3)
            else:
                canvas.create_text(20, current_y, text="SCAN INTENSITY", fill="#aaaaaa", font=("Segoe UI", 8, "bold"), anchor="w")
                intensity_scale = tk.Scale(root, from_=1, to=5, orient="horizontal", bg=bg_color.get(), fg="#00ff00", 
                                           highlightthickness=0, bd=0, troughcolor="#1e1e1e", activebackground="#00ff00",
                                           length=200, font=("Segoe UI", 8, "bold"))
                intensity_scale.set(3)
                canvas.create_window(120, current_y, window=intensity_scale, anchor="w")
                
                intensity_desc = canvas.create_text(330, current_y, text="Medium (Default)", fill="#00ff00", font=("Segoe UI", 8, "italic"), anchor="w")
                
                def update_intensity_desc(val):
                    descs = {
                        "1": "Stealthy / Slow",
                        "2": "Subtle / Quiet",
                        "3": "Balanced (Medium)",
                        "4": "Thorough / Fast",
                        "5": "Insane / Aggressive"
                    }
                    canvas.itemconfig(intensity_desc, text=descs.get(str(val), ""))
                
                intensity_scale.config(command=update_intensity_desc)
            current_y += 40

            # Progress Bar
            progress_var = tk.DoubleVar()
            progress_bar = ttk.Progressbar(root, variable=progress_var, maximum=100, length=380, style="Horizontal.TProgressbar")
            progress_bar_id = canvas.create_window(212, current_y, window=progress_bar, anchor="center")
            current_y += 35

            # --- REDESIGNED RESULTS DASHBOARD ---
            results_frame = tk.Frame(root, bg=bg_color.get())
            results_id = canvas.create_window(212, 480, window=results_frame, anchor="center")
            
            # List of items to keep centered if window expands
            centered_tool_items = [tool_title_id, results_id, progress_bar_id, target_label_id, target_window_id]

            notebook = ttk.Notebook(results_frame, style="TNotebook")
            notebook.pack(fill="both", expand=True)
            
            # Tab 1: Findings Table
            findings_tab = tk.Frame(notebook, bg="#1e1e1e")
            notebook.add(findings_tab, text="  DASHBOARD  ")
            
            findings_tree = ttk.Treeview(findings_tab, show="headings", height=12, style="Treeview")
            
            ft_vscroll = ttk.Scrollbar(findings_tab, orient="vertical", style="Vertical.TScrollbar", command=findings_tree.yview)
            ft_vscroll.pack(side="right", fill="y")
            
            ft_hscroll = ttk.Scrollbar(findings_tab, orient="horizontal", command=findings_tree.xview)
            ft_hscroll.pack(side="bottom", fill="x")
            
            findings_tree.pack(side="left", fill="both", expand=True)
            findings_tree.config(yscrollcommand=ft_vscroll.set, xscrollcommand=ft_hscroll.set)
            
            # Tab 2: Raw Log
            log_tab = tk.Frame(notebook, bg="#1e1e1e")
            notebook.add(log_tab, text="  TECHNICAL LOGS  ")
            
            tool_log_box = tk.Text(log_tab, bg="#000000", fg="#00ff00", font=("Consolas", 9), bd=0, height=18, width=85, padx=10, pady=5, highlightthickness=0, wrap="none")
            tool_log_box.tag_configure("error", foreground="#e74c3c")
            tool_log_box.pack(side="top", fill="both", expand=True)
            
            lb_hscroll = ttk.Scrollbar(log_tab, orient="horizontal", command=tool_log_box.xview)
            lb_hscroll.pack(side="bottom", fill="x")
            
            lb_vscroll = ttk.Scrollbar(log_tab, orient="vertical", style="Vertical.TScrollbar", command=tool_log_box.yview)
            lb_vscroll.pack(side="right", fill="y")
            
            tool_log_box.config(yscrollcommand=lb_vscroll.set, xscrollcommand=lb_hscroll.set)
            tool_log_box.insert("1.0", f"[*] {tool_name} module loaded.\n[*] Ready to initialize scan.\n")
            tool_log_box.config(state="disabled")

            def tool_log_to_box(message, is_error=False):
                def append():
                    try:
                        tool_log_box.config(state="normal")
                        if is_error:
                            tool_log_box.insert(tk.END, message, "error")
                        else:
                            tool_log_box.insert(tk.END, message)
                        
                        # Dynamic width adjustment for Text box
                        try:
                            lines = tool_log_box.get("1.0", tk.END).splitlines()
                            if lines:
                                max_line_len = max(len(l) for l in lines)
                                current_width = int(tool_log_box.cget("width"))
                                if max_line_len > current_width:
                                    new_width = min(max_line_len + 2, 150)
                                    if new_width > current_width:
                                        tool_log_box.config(width=new_width)
                                        update_window_size(width=current_width, centered_items=centered_tool_items)
                        except: pass

                        tool_log_box.see(tk.END)
                        tool_log_box.config(state="disabled")
                    except:
                        pass
                root.after(0, append)

            # Export Findings Button (placed below notebook or in a header)
            export_frame = tk.Frame(findings_tab, bg="#121212", height=30)
            export_frame.pack(fill="x", side="top")
            
            def export_general():
                from tkinter import filedialog
                fpath = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx"), ("All files", "*.*")])
                if fpath:
                    scanner.export_findings_to_excel(fpath)

            export_btn = tk.Button(export_frame, text="EXPORT TO EXCEL", bg="#121212", fg="#00ff00", bd=0, 
                                   font=("Segoe UI", 7, "bold"), activebackground="#333333", activeforeground="#00ff00",
                                   cursor="hand2", command=export_general)
            export_btn.pack(side="right", padx=10)

            # Controls (Start/Stop) - Moved below results
            controls_frame = tk.Frame(root, bg=bg_color.get())
            controls_id = canvas.create_window(212, 700, window=controls_frame, anchor="center")
            centered_tool_items.append(controls_id)

            run_btn = tk.Button(controls_frame, text="RUN SECURITY SCAN", bg="#00ff00", fg="#000000", font=("Segoe UI", 10, "bold"), 
                                width=25, bd=0, activebackground="#00cc00", cursor="hand2")
            run_btn.pack(side="left", padx=10, ipady=8)
            
            stop_btn = tk.Button(controls_frame, text="TERMINATE", bg="#e74c3c", fg="#ffffff", font=("Segoe UI", 10, "bold"), 
                                 width=15, bd=0, activebackground="#c0392b", cursor="hand2", state="disabled")
            stop_btn.pack(side="left", padx=10, ipady=8)

            initialized_columns = [False]
            current_columns = []
            col_widths = {}
            def on_finding(data):
                def update_ui():
                    measure_font = tkfont.Font(family="Arial", size=9)
                    
                    # Check if we need to add new columns
                    new_cols_needed = False
                    incoming_keys = list(data.keys())
                    for k in incoming_keys:
                        if k not in current_columns:
                            new_cols_needed = True
                            break
                    
                    if new_cols_needed or not initialized_columns[0]:
                        # Merge new keys with existing ones to maintain order
                        for k in incoming_keys:
                            if k not in current_columns:
                                current_columns.append(k)
                        
                        findings_tree["columns"] = current_columns
                        for col in current_columns:
                            findings_tree.heading(col, text=col)
                            # Update width if not already set or if heading is wider
                            w = measure_font.measure(col) + 40
                            if col not in col_widths or w > col_widths[col]:
                                findings_tree.column(col, width=w, anchor="center")
                                col_widths[col] = w
                        initialized_columns[0] = True
                    
                    # Update column widths based on content
                    for col, val in data.items():
                        new_w = measure_font.measure(str(val)) + 40 # extra padding
                        if new_w > col_widths.get(col, 0):
                            col_widths[col] = new_w
                            findings_tree.column(col, width=new_w)

                    # Prepare values in correct column order
                    row_values = [data.get(col, "") for col in current_columns]
                    findings_tree.insert("", tk.END, values=row_values)
                    # Switch to findings tab if it's the first finding
                    if len(findings_tree.get_children()) == 1:
                        notebook.select(0)
                    
                    # Ensure window expands if tree expands
                    update_window_size(width=650, target_height=750, centered_items=centered_tool_items)
                        
                root.after(0, update_ui)

            def run_this_tool():
                target = tool_target_entry.get()
                intensity = int(intensity_scale.get())
                s_type = scan_type_var.get()
                b_type = brute_type_var.get() if is_dir_brute else None
                f_type = audit_type_var.get() if is_firewall_audit else None
                p_list = payload_list_var.get() if is_sql_tool else None
                c_tmpl = custom_cmd_var.get() if is_custom_cmd else None

                no_target_allowed = ["Win Audit", "WiFi Traffic Analyzer", "Security Camera Finder"]
                if not target and all(n not in tool_name for n in no_target_allowed):
                    messagebox.showwarning("Input Required", "Please enter a target address or domain.")
                    return
                
                # Clear previous results
                findings_tree.delete(*findings_tree.get_children())
                initialized_columns[0] = False
                current_columns.clear()
                col_widths.clear()
                progress_var.set(0)
                scanner.last_findings = []
                
                tool_log_box.config(state="normal")
                tool_log_box.delete("1.0", tk.END)
                tool_log_box.insert("1.0", f"[*] Initializing {tool_name}...\n")
                if "Win Audit" not in tool_name:
                    tool_log_box.insert("2.0", f"[*] Target: {target}\n")
                
                if is_sql_tool:
                    tool_log_box.insert("3.0", f"[*] Payload List: {p_list}\n")
                elif is_custom_cmd:
                    tool_log_box.insert("3.0", f"[*] Command Template: {c_tmpl}\n")
                elif is_dir_brute:
                    tool_log_box.insert("3.0", f"[*] Brute Type: {b_type}\n")
                elif is_firewall_audit:
                    tool_log_box.insert("3.0", f"[*] Audit Type: {f_type}\n")
                else:
                    tool_log_box.insert("3.0", f"[*] Intensity Level: {intensity}\n")
                
                if "Nmap/Nessus" in tool_name:
                    tool_log_box.insert("4.0", f"[*] Scan Type: {s_type}\n")
                tool_log_box.config(state="disabled")
                
                scanner.log_callback = tool_log_to_box
                scanner.finding_callback = on_finding
                scanner.progress_callback = lambda v: root.after(0, lambda: progress_var.set(v))
                
                def wrapper():
                    # UI show stop button
                    root.after(0, lambda: stop_btn.pack(side="left", padx=5))
                    root.after(0, lambda: run_btn.config(state="disabled"))
                    
                    scanner.reset_stop_event()
                    if tool_func:
                        if "Win Audit" in tool_name:
                            tool_func(intensity=intensity)
                        elif "Traffic Monitor" in tool_name:
                            try:
                                h = int(hours_var.get())
                                m = int(mins_var.get())
                                total_sec = (h * 3600) + (m * 60)
                                if total_sec <= 0: total_sec = 5 # Minimum
                                tool_func(target, duration_seconds=total_sec)
                            except:
                                tool_func(target, duration_seconds=300)
                        elif "Rev Shell" in tool_name:
                            tool_func(target)
                        elif "Nmap/Nessus" in tool_name:
                            tool_func(target, intensity=intensity, scan_type=s_type)
                        elif is_sql_tool:
                            tool_func(target, payload_list=p_list)
                        elif is_custom_cmd:
                            tool_func(target, command_template=c_tmpl)
                        elif is_dir_brute:
                            tool_func(target, brute_type=b_type)
                        elif is_firewall_audit:
                            tool_func(target, audit_type=f_type)
                        else:
                            tool_func(target, intensity=intensity)
                    else:
                        tool_log_to_box("[!] No functional implementation for this tool yet.\n", is_error=True)
                    
                    scanner.generate_report()
                    refresh_reports()
                    # UI hide stop button
                    root.after(0, lambda: stop_btn.pack_forget())
                    root.after(0, lambda: run_btn.config(state="normal"))

                threading.Thread(target=wrapper, daemon=True).start()

            # Execute and Export Buttons row
            btn_frame = tk.Frame(root, bg=bg_color.get())
            btn_frame_id = canvas.create_window(212, current_y, window=btn_frame, anchor="center")
            centered_tool_items.append(btn_frame_id)

            run_btn = tk.Button(btn_frame, text=f"Execute {tool_name}", bg="#226622", fg=fg_color, bd=0, width=20, 
                                font=("Arial", 10, "bold"), command=run_this_tool, activebackground=accent_color.get())
            run_btn.pack(side="left", padx=5)

            stop_btn = tk.Button(btn_frame, text="Terminate Process", bg="#990000", fg=fg_color, bd=0, width=20,
                                 font=("Arial", 10, "bold"), command=scanner.terminate)
            # stop_btn is initially hidden

            if "Traffic Monitor" not in tool_name:
                def export_general():
                    from tkinter import filedialog
                    fpath = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx"), ("All files", "*.*")])
                    if fpath:
                        scanner.export_to_excel(fpath)
                
                export_btn = tk.Button(btn_frame, text="Export to Excel", bg="#444444", fg=fg_color, bd=0, 
                                       font=("Arial", 10, "bold"), command=export_general)
                export_btn.pack(side="left", padx=5)
            else:
                def export_action():
                    from tkinter import filedialog
                    fpath = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx"), ("All files", "*.*")])
                    if fpath:
                        scanner.export_monitor_to_excel(fpath)
                
                export_btn = tk.Button(btn_frame, text="Export to Excel", bg="#444444", fg=fg_color, bd=0, 
                                       font=("Arial", 10, "bold"), command=export_action)
                export_btn.pack(side="left", padx=5)

            update_window_size(width=650, target_height=750, centered_items=centered_tool_items)

        def show_ddos_screen(scanner):
            nonlocal status_text
            clear_canvas()
            # Create status_text for tooltips and messages in DDoS screen
            status_text = canvas.create_text(212, 20, text="", fill="#00ff00", font=("Segoe UI", 9, "bold"), anchor="center")
            
            ddos_title_id = canvas.create_text(212, 45, text="DDOS ATTACK SIMULATOR", fill="#ffffff", font=("Segoe UI", 16, "bold"), anchor="center")
            
            # Back to Main Menu
            def go_back_ddos():
                canvas.coords(status_text, 212, 25) # Reset status_text position
                show_main_menu(username, is_admin, db_available)

            back_btn = tk.Button(root, text="← BACK", bg="#1e1e1e", fg="#aaaaaa", bd=0, font=("Segoe UI", 8, "bold"), 
                                 activebackground="#333333", activeforeground="#ffffff", cursor="hand2", command=go_back_ddos)
            canvas.create_window(20, 25, window=back_btn, anchor="w")

            # Target Selection
            target_label_id = canvas.create_text(212, 80, text="TARGET ADDRESS / DOMAIN", fill="#aaaaaa", font=("Segoe UI", 8, "bold"), anchor="center")
            
            target_frame = tk.Frame(root, bg="#1e1e1e", padx=5, pady=5)
            tool_target_entry = tk.Entry(target_frame, bg="#2b2b2b", fg="#ffffff", insertbackground="#00ff00", bd=0, width=40, font=("Consolas", 11))
            tool_target_entry.insert(0, persistent_target[0])
            tool_target_entry.pack(ipady=5)
            target_window_id = canvas.create_window(212, 110, window=target_frame, anchor="center")

            # DDoS Specifics
            current_y = 150
            canvas.create_text(20, current_y, text="TRAFFIC MODE", fill="#aaaaaa", font=("Segoe UI", 8, "bold"), anchor="w")
            attack_type_var = tk.StringVar(value="UDP Flood")
            attack_type_opt = tk.OptionMenu(root, attack_type_var, "UDP Flood", "TCP SYN Flood", "HTTP GET Flood", "ICMP Smash")
            attack_type_opt.config(bg="#1e1e1e", fg="#ffffff", bd=0, highlightthickness=0, activebackground="#333333", width=15, font=("Segoe UI", 9))
            attack_type_opt["menu"].config(bg="#1e1e1e", fg="#ffffff", font=("Segoe UI", 9))
            canvas.create_window(120, current_y, window=attack_type_opt, anchor="w")

            current_y += 40
            canvas.create_text(20, current_y, text="DURATION (S)", fill="#aaaaaa", font=("Segoe UI", 8, "bold"), anchor="w")
            duration_entry = tk.Entry(root, bg="#1e1e1e", fg="#ffffff", insertbackground="#00ff00", bd=0, width=10, font=("Consolas", 10), justify="center")
            duration_entry.insert(0, "10")
            canvas.create_window(120, current_y, window=duration_entry, anchor="w")

            canvas.create_text(200, current_y, text="WORKER THREADS", fill="#aaaaaa", font=("Segoe UI", 8, "bold"), anchor="w")
            threads_entry = tk.Entry(root, bg="#1e1e1e", fg="#ffffff", insertbackground="#00ff00", bd=0, width=10, font=("Consolas", 10), justify="center")
            threads_entry.insert(0, "50")
            canvas.create_window(310, current_y, window=threads_entry, anchor="w")

            current_y += 40
            # Progress Bar
            progress_var = tk.DoubleVar()
            progress_bar = ttk.Progressbar(root, variable=progress_var, maximum=100, length=380, style="Horizontal.TProgressbar")
            progress_bar_id = canvas.create_window(212, current_y, window=progress_bar, anchor="center")

            # --- REDESIGNED DDoS RESULTS ---
            results_frame = tk.Frame(root, bg=bg_color.get())
            results_id = canvas.create_window(212, 480, window=results_frame, anchor="center")
            
            centered_ddos_items = [ddos_title_id, results_id, progress_bar_id, target_label_id, target_window_id]

            # Stats Display
            stats_frame = tk.Frame(results_frame, bg="#121212", padx=30, pady=20, bd=1, highlightbackground="#333333", highlightthickness=1)
            stats_frame.pack(fill="x", pady=10)
            
            pkt_label = tk.Label(stats_frame, text="PACKETS SENT: 0", bg="#121212", fg="#ff3333", font=("Segoe UI", 18, "bold"))
            pkt_label.pack()
            
            status_label = tk.Label(stats_frame, text="STATUS: IDLE", bg="#121212", fg="#00ff00", font=("Segoe UI", 9, "bold"))
            status_label.pack(pady=(5, 0))
            
            # Mini Log
            log_container = tk.Frame(results_frame, bg="#1e1e1e", bd=1, highlightbackground="#333333", highlightthickness=1)
            log_container.pack(fill="both", expand=True, pady=10)

            tool_log_box = tk.Text(log_container, bg="#000000", fg="#aaaaaa", font=("Consolas", 8), bd=0, height=12, width=85, padx=10, pady=5, highlightthickness=0, wrap="none")
            tool_log_box.pack(side="left", fill="both", expand=True)
            
            lb_vscroll = ttk.Scrollbar(log_container, orient="vertical", style="Vertical.TScrollbar", command=tool_log_box.yview)
            lb_vscroll.pack(side="right", fill="y")
            
            tool_log_box.config(yscrollcommand=lb_vscroll.set)
            tool_log_box.config(state="normal")
            tool_log_box.insert("1.0", "[*] DDoS Module Ready.\n[*] Caution: For authorized testing only.\n")
            tool_log_box.config(state="disabled")

            def tool_log_to_box(message, is_error=False):
                def append():
                    try:
                        tool_log_box.config(state="normal")
                        tool_log_box.insert(tk.END, message)
                        
                        # Dynamic width adjustment
                        try:
                            lines = tool_log_box.get("1.0", tk.END).splitlines()
                            if lines:
                                max_line_len = max(len(l) for l in lines)
                                current_width = int(tool_log_box.cget("width"))
                                if max_line_len > current_width:
                                    new_width = min(max_line_len + 2, 150)
                                    if new_width > current_width:
                                        tool_log_box.config(width=new_width)
                                        update_window_size(width=650, target_height=750, centered_items=centered_ddos_items)
                        except: pass

                        tool_log_box.see(tk.END)
                        tool_log_box.config(state="disabled")
                    except: pass
                root.after(0, append)

            def on_finding(data):
                def update_ui():
                    if "Packets" in data:
                        pkt_label.config(text=f"PACKETS SENT: {data['Packets']}")
                root.after(0, update_ui)

            def run_ddos():
                target = tool_target_entry.get()
                if not target:
                    messagebox.showwarning("Input Required", "Please enter a target address or domain.")
                    return
                
                persistent_target[0] = target
                a_type = attack_type_var.get()
                try:
                    dur = int(duration_entry.get())
                    thrd = int(threads_entry.get())
                except:
                    messagebox.showerror("Input Error", "Duration and Threads must be integers.")
                    return

                scanner.last_findings = []
                tool_log_box.config(state="normal")
                tool_log_box.delete("1.0", tk.END)
                tool_log_box.insert("1.0", f"[*] Initializing {a_type} task on {target}...\n")
                tool_log_box.insert("2.0", f"[*] Target: {target}\n")
                tool_log_box.insert("3.0", f"[*] Mode: {a_type}\n")
                tool_log_box.insert("4.0", f"[*] Threads: {thrd}\n")
                tool_log_box.config(state="disabled")
                status_label.config(text=f"STATUS: EXECUTING ({a_type})", fg="#ff3333")
                progress_var.set(0)
                
                scanner.log_callback = tool_log_to_box
                scanner.finding_callback = on_finding
                scanner.progress_callback = lambda v: root.after(0, lambda: progress_var.set(v))
                
                def wrapper():
                    root.after(0, lambda: stop_btn.pack(side="left", padx=5))
                    root.after(0, lambda: run_btn.config(state="disabled", text="ATTACK IN PROGRESS..."))
                    
                    scanner.reset_stop_event()
                    scanner.ddos_attack(target, a_type, dur, thrd)
                    scanner.generate_report()
                    refresh_reports()
                    root.after(0, lambda: status_label.config(text="STATUS: FINISHED", fg="#00ff00"))
                    
                    root.after(0, lambda: stop_btn.pack_forget())
                    root.after(0, lambda: run_btn.config(state="normal", text="INITIALIZE ATTACK"))

                threading.Thread(target=wrapper, daemon=True).start()

            # Controls (Start/Stop) - Moved below results
            controls_frame = tk.Frame(root, bg=bg_color.get())
            controls_id = canvas.create_window(212, 700, window=controls_frame, anchor="center")
            centered_ddos_items.append(controls_id)

            run_btn = tk.Button(controls_frame, text="INITIALIZE ATTACK", bg="#ff3333", fg="#ffffff", font=("Segoe UI", 10, "bold"), 
                                width=25, bd=0, activebackground="#cc0000", cursor="hand2", command=run_ddos)
            run_btn.pack(side="left", padx=10, ipady=8)
            
            stop_btn = tk.Button(controls_frame, text="TERMINATE", bg="#aaaaaa", fg="#ffffff", font=("Segoe UI", 10, "bold"), 
                                 width=15, bd=0, activebackground="#333333", cursor="hand2", command=scanner.terminate)

            # Export Button
            def export_ddos():
                from tkinter import filedialog
                fpath = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx"), ("All files", "*.*")])
                if fpath:
                    scanner.export_findings_to_excel(fpath)

            export_btn = tk.Button(stats_frame, text="EXPORT STATS", bg="#121212", fg="#00ff00", bd=0, 
                                   font=("Segoe UI", 7, "bold"), activebackground="#333333", activeforeground="#00ff00",
                                   cursor="hand2", command=export_ddos)
            export_btn.place(relx=1.0, rely=0, anchor="ne", x=-5, y=5)

            update_window_size(width=650, target_height=750, centered_items=centered_ddos_items)

        def show_admin_ai_analyst():
            admin_ai_win = tk.Toplevel(root)
            admin_ai_win.overrideredirect(True)
            admin_ai_win.geometry("650x850")
            admin_ai_win.configure(bg="#1e1e1e")
            
            # State
            chat_history = []
            analyzer = AIAnalyzer(model="claude-sonnet-4-5") # Admin gets the better model
            send_btn = None
            start_analysis_btn = None
            stop_btn = None
            is_stopping = [False]

            def stop_analysis():
                is_stopping[0] = True
                scanner_instance[0].terminate()
                append_to_chat("System", "Stopping all AI processes and commands...", "system")
                try:
                    stop_btn.config(state="disabled", text="STOPPING...")
                    send_btn.config(state="normal")
                    start_analysis_btn.config(state="normal")
                except: pass
            
            # Custom Title Bar
            title_bar = tk.Frame(admin_ai_win, bg="#c0392b", relief="raised", bd=0, height=35)
            title_bar.pack(side="top", fill="x")
            tk.Label(title_bar, text="ADMIN AI SECURITY ASSISTANT", bg="#c0392b", fg="#ffffff", font=("Segoe UI", 9, "bold")).pack(side="left", padx=10)
            
            tk.Button(title_bar, text="✕", command=admin_ai_win.destroy, bg="#c0392b", fg="#ffffff", 
                      bd=0, activebackground="#e74c3c", activeforeground="#ffffff", font=("Segoe UI", 11, "bold"), width=3).pack(side="right")

            # Dragging
            def start_move_adv(event):
                admin_ai_win.x = event.x
                admin_ai_win.y = event.y
            def on_move_adv(event):
                deltax = event.x - admin_ai_win.x
                deltay = event.y - admin_ai_win.y
                x = admin_ai_win.winfo_x() + deltax
                y = admin_ai_win.winfo_y() + deltay
                admin_ai_win.geometry(f"+{x}+{y}")
            title_bar.bind("<Button-1>", start_move_adv)
            title_bar.bind("<B1-Motion>", on_move_adv)

            header_frame = tk.Frame(admin_ai_win, bg="#1e1e1e", pady=15)
            header_frame.pack(fill="x")
            
            tk.Label(header_frame, text="AI ANALYTICS ENGINE", bg="#1e1e1e", fg="#e67e22", font=("Segoe UI", 14, "bold")).pack()

            # Target Info
            current_target = target_entry.get().strip()
            tk.Label(header_frame, text=f"ACTIVE TARGET: {current_target if current_target else 'NONE'}", bg="#1e1e1e", fg="#666666", font=("Consolas", 9, "bold")).pack()

            # Model and API Key Section
            settings_frame = tk.Frame(admin_ai_win, bg="#121212", padx=20, pady=10, bd=1, highlightbackground="#333333", highlightthickness=1)
            settings_frame.pack(fill="x", padx=20, pady=5)
            
            # API Key
            tk.Label(settings_frame, text="API KEY:", bg="#121212", fg="#aaaaaa", font=("Segoe UI", 7, "bold")).pack(side="left")
            admin_api_key_entry = tk.Entry(settings_frame, show="*", bg="#1e1e1e", fg="#ffffff", insertbackground="#00ff00", bd=0, width=20, font=("Consolas", 9))
            admin_api_key_entry.pack(side="left", padx=5, ipady=3)
            
            # Autonomous Mode Toggle
            autonomous_var = tk.BooleanVar(value=False)
            tk.Label(settings_frame, text="AUTONOMOUS:", bg="#121212", fg="#aaaaaa", font=("Segoe UI", 7, "bold")).pack(side="left", padx=(10, 0))
            autonomous_cb = tk.Checkbutton(settings_frame, variable=autonomous_var, bg="#121212", activebackground="#121212", selectcolor="#1e1e1e", borderwidth=0)
            autonomous_cb.pack(side="left")

            # Model Dropdown
            tk.Label(settings_frame, text="MODEL:", bg="#121212", fg="#aaaaaa", font=("Segoe UI", 7, "bold")).pack(side="left", padx=(10, 0))
            admin_model_var = tk.StringVar(value="Claude Sonnet 4.5")
            admin_model_map = {
                "Claude Haiku 4.5": "claude-haiku-4-5",
                "Claude Sonnet 4.5": "claude-sonnet-4-5",
                "Claude Opus 4.1": "claude-opus-4-1",
                "Claude 3.7 Sonnet": "claude-3-7-sonnet-latest",
                "Claude 3.5 Sonnet": "claude-3-5-sonnet-latest",
                "Claude 3 Haiku": "claude-3-haiku-20240307"
            }
            admin_model_opt = tk.OptionMenu(settings_frame, admin_model_var, *admin_model_map.keys())
            admin_model_opt.config(bg="#1e1e1e", fg="#ffffff", bd=0, highlightthickness=0, activebackground="#333333", font=("Segoe UI", 8))
            admin_model_opt["menu"].config(bg="#1e1e1e", fg="#ffffff", font=("Segoe UI", 8))
            admin_model_opt.pack(side="left", padx=5)

            # Auto-load key
            try:
                stored_key = os.getenv("ANTHROPIC_API_KEY", "")
                if stored_key:
                    admin_api_key_entry.insert(0, stored_key)
            except:
                pass

            # Result Area (Chat Box)
            res_frame = tk.Frame(admin_ai_win, bg="#1e1e1e", bd=1, highlightbackground="#333333", highlightthickness=1)
            res_frame.pack(fill="both", expand=True, padx=20, pady=10)
            
            v_scroll = ttk.Scrollbar(res_frame, orient="vertical", style="Vertical.TScrollbar")
            v_scroll.pack(side="right", fill="y")
            
            res_text = tk.Text(res_frame, bg="#000000", fg="#3498db", insertbackground="#3498db", 
                               bd=0, font=("Consolas", 10), yscrollcommand=v_scroll.set, wrap="word", padx=10, pady=10)
            res_text.pack(side="left", fill="both", expand=True)
            v_scroll.config(command=res_text.yview)
            
            res_text.tag_configure("user", foreground="#00ff00", font=("Consolas", 10, "bold"))
            res_text.tag_configure("ai", foreground="#3498db")
            res_text.tag_configure("system", foreground="#e67e22", font=("Consolas", 10, "italic"))
            res_text.tag_configure("cmd", foreground="#f1c40f", font=("Consolas", 10, "bold"))
            
            def append_to_chat(sender, message, tag):
                res_text.config(state="normal")
                res_text.insert(tk.END, f"[{sender.upper()}]: ", tag)
                res_text.insert(tk.END, f"{message}\n\n")
                res_text.see(tk.END)
                res_text.config(state="disabled")

            append_to_chat("Assistant", f"Hello Admin. I'm ready to analyze {current_target if current_target else 'the current session'}. Type 'Analyze' to start or ask me anything.", "ai")
            res_text.config(state="disabled")

            def execute_autonomous_cmd(cmd):
                if is_stopping[0]: return
                append_to_chat("System", f"Executing autonomous command: {cmd}", "system")
                target = target_entry.get().strip()
                active_scanner = scanner_instance[0]
                
                def run_and_report():
                    output_lines = []
                    def temp_log(msg, is_err=False):
                        output_lines.append(msg)
                    
                    orig_log = active_scanner.log_callback
                    active_scanner.log_callback = temp_log
                    
                    try:
                        active_scanner.custom_command(target, cmd)
                        full_output = "".join(output_lines)
                        
                        def back_to_ai():
                            if is_stopping[0]: return
                            append_to_chat("System", "Command execution complete.", "system")
                            if autonomous_var.get():
                                append_to_chat("System", "Auto-submitting results to AI...", "system")
                                send_to_ai(f"COMMAND OUTPUT ({cmd}):\n{full_output}", is_hidden=True)
                            else:
                                if messagebox.askyesno("Send Feedback", f"Command '{cmd}' finished. Send results back to AI for further analysis?"):
                                    append_to_chat("System", "Feedback sent to AI.", "system")
                                    send_to_ai(f"COMMAND OUTPUT ({cmd}):\n{full_output}", is_hidden=True)
                                else:
                                    append_to_chat("System", "Results NOT sent to AI. Token usage paused.", "system")
                        
                        root.after(0, back_to_ai)
                    finally:
                        active_scanner.log_callback = orig_log

                threading.Thread(target=run_and_report, daemon=True).start()

            def handle_ai_response(response):
                if is_stopping[0]:
                    is_stopping[0] = False
                    return

                # Re-enable UI
                try:
                    send_btn.config(state="normal")
                    start_analysis_btn.config(state="normal")
                    stop_btn.config(state="disabled", text="STOP ANALYSIS")
                except: pass

                append_to_chat("Assistant", response, "ai")
                chat_history.append({"role": "assistant", "content": response})
                
                # Look for EXECUTE: command
                for line in response.split("\n"):
                    if line.strip().startswith("EXECUTE:"):
                        cmd = line.replace("EXECUTE:", "").strip()
                        if cmd:
                            if autonomous_var.get():
                                append_to_chat("System", f"Autonomous execution: {cmd}", "system")
                                execute_autonomous_cmd(cmd)
                            else:
                                if messagebox.askyesno("Autonomous Execution", f"The AI wants to execute the following command:\n\n{cmd}\n\nDo you want to allow this?"):
                                    execute_autonomous_cmd(cmd)
                                else:
                                    append_to_chat("System", f"Execution of '{cmd}' was cancelled by user.", "system")

            def send_to_ai(message=None, is_hidden=False):
                if is_stopping[0]: return
                
                # Disable UI to prevent multiple requests
                try:
                    send_btn.config(state="disabled")
                    start_analysis_btn.config(state="disabled")
                    stop_btn.config(state="normal", text="STOP ANALYSIS")
                except: pass

                is_stopping[0] = False # Reset if starting fresh

                # Update analyzer settings from UI
                selected_model_name = admin_model_var.get()
                analyzer.model = admin_model_map.get(selected_model_name, "claude-sonnet-4-5")
                
                new_key = admin_api_key_entry.get().strip()
                if new_key and new_key != analyzer.api_key:
                    analyzer.api_key = new_key
                    analyzer.client = analyzer._init_client()

                if message is None:
                    message = cmd_entry.get().strip()
                    if not message: return
                    cmd_entry.delete(0, tk.END)
                    append_to_chat("Admin", message, "user")
                elif not is_hidden:
                    append_to_chat("Admin", message, "user")
                
                target = target_entry.get().strip()
                active_scanner = scanner_instance[0]
                
                if not is_hidden:
                    append_to_chat("System", "AI is analyzing your request. Please wait...", "system")

                # Snapshot history before appending new message to avoid duplication
                history_snapshot = list(chat_history)
                
                def thread_func():
                    response = analyzer.admin_chat(target, active_scanner.all_findings, message, history_snapshot)
                    root.after(0, lambda: handle_ai_response(response))
                
                chat_history.append({"role": "user", "content": message})
                threading.Thread(target=thread_func, daemon=True).start()

            # Chat Input Area
            input_frame = tk.Frame(admin_ai_win, bg="#121212", padx=20, pady=15)
            input_frame.pack(fill="x")
            
            cmd_entry = tk.Entry(input_frame, bg="#1e1e1e", fg="#ffffff", insertbackground="#00ff00", bd=0, font=("Segoe UI", 10))
            cmd_entry.pack(side="left", fill="x", expand=True, padx=(0, 10), ipady=8)
            cmd_entry.bind("<Return>", lambda e: send_to_ai())
            
            send_btn = tk.Button(input_frame, text="SEND", bg="#00ff00", fg="#000000", bd=0, width=12, font=("Segoe UI", 9, "bold"), activebackground="#00cc00", cursor="hand2", command=send_to_ai)
            send_btn.pack(side="right", ipady=5)

            # Bottom Buttons
            btn_frame = tk.Frame(admin_ai_win, bg="#1e1e1e", pady=10)
            btn_frame.pack(fill="x")
            
            def start_analysis():
                send_to_ai("Please perform a full analysis of the target domain.")

            start_analysis_btn = tk.Button(btn_frame, text="START AUTO-ANALYSIS", bg="#2980b9", fg="#ffffff", font=("Segoe UI", 9, "bold"), bd=0, padx=20, pady=8, activebackground="#3498db", cursor="hand2", command=start_analysis)
            start_analysis_btn.pack(side="left", padx=(20, 10))

            stop_btn = tk.Button(btn_frame, text="STOP ANALYSIS", bg="#e74c3c", fg="#ffffff", font=("Segoe UI", 9, "bold"), bd=0, padx=20, pady=8, activebackground="#c0392b", cursor="hand2", command=stop_analysis, state="disabled")
            stop_btn.pack(side="left", padx=10)
            
            tk.Button(btn_frame, text="CLEAR CHAT", bg="#333333", fg="#ffffff", font=("Segoe UI", 9, "bold"), bd=0, padx=20, pady=8, activebackground="#444444", cursor="hand2", command=lambda: [chat_history.clear(), res_text.config(state="normal"), res_text.delete("1.0", tk.END), append_to_chat("Assistant", "Chat history cleared.", "ai")]).pack(side="left", padx=10)
            
            tk.Button(btn_frame, text="CLOSE", bg="#c0392b", fg="#ffffff", font=("Segoe UI", 9, "bold"), bd=0, padx=20, pady=8, activebackground="#e74c3c", cursor="hand2", command=admin_ai_win.destroy).pack(side="right", padx=20)

        def show_ai_feedback_screen():
            ai_win = tk.Toplevel(root)
            ai_win.overrideredirect(True)
            ai_win.geometry("550x750")
            ai_win.configure(bg="#1e1e1e")
            
            # Custom Title Bar for AI Popup
            ai_title_bar = tk.Frame(ai_win, bg=title_bar_color.get(), relief="raised", bd=0, height=35)
            ai_title_bar.pack(side="top", fill="x")

            tk.Label(ai_title_bar, text="AI SECURITY ASSISTANT", bg=title_bar_color.get(), fg="#ffffff", font=("Segoe UI", 9, "bold")).pack(side="left", padx=10)

            tk.Button(ai_title_bar, text="✕", command=ai_win.destroy, bg=title_bar_color.get(), fg="#ffffff", 
                      bd=0, activebackground="red", activeforeground="#ffffff", font=("Segoe UI", 11, "bold"), width=3).pack(side="right")

            # Dragging functionality
            def start_move_ai(event):
                ai_win.x = event.x
                ai_win.y = event.y

            def on_move_ai(event):
                deltax = event.x - ai_win.x
                deltay = event.y - ai_win.y
                x = ai_win.winfo_x() + deltax
                y = ai_win.winfo_y() + deltay
                ai_win.geometry(f"+{x}+{y}")

            ai_title_bar.bind("<Button-1>", start_move_ai)
            ai_title_bar.bind("<B1-Motion>", on_move_ai)
            
            # AI Title
            tk.Label(ai_win, text="AI VULNERABILITY ANALYSIS", bg="#1e1e1e", fg="#00ff00", font=("Segoe UI", 14, "bold")).pack(pady=(20, 10))

            # Settings Frame
            settings_card = tk.Frame(ai_win, bg="#121212", padx=20, pady=15, bd=1, highlightbackground="#333333", highlightthickness=1)
            settings_card.pack(fill="x", padx=20, pady=10)

            # API Key Section
            api_row = tk.Frame(settings_card, bg="#121212")
            api_row.pack(fill="x", pady=5)
            tk.Label(api_row, text="CLAUDE API KEY (OPTIONAL):", bg="#121212", fg="#aaaaaa", font=("Segoe UI", 7, "bold")).pack(side="left")
            api_key_entry = tk.Entry(api_row, show="*", bg="#1e1e1e", fg="#ffffff", insertbackground="#00ff00", bd=0, width=30, font=("Consolas", 9))
            api_key_entry.pack(side="right", padx=5, ipady=3)

            # Mode Selection
            mode_row = tk.Frame(settings_card, bg="#121212")
            mode_row.pack(fill="x", pady=5)
            tk.Label(mode_row, text="ANALYSIS MODE:", bg="#121212", fg="#aaaaaa", font=("Segoe UI", 7, "bold")).pack(side="left")
            analysis_mode_var = tk.StringVar(value="Both")
            mode_opt = tk.OptionMenu(mode_row, analysis_mode_var, "Offensive (Penetrate)", "Defensive (Patch)", "Both")
            mode_opt.config(bg="#1e1e1e", fg="#ffffff", bd=0, highlightthickness=0, activebackground="#333333", font=("Segoe UI", 8))
            mode_opt["menu"].config(bg="#1e1e1e", fg="#ffffff", font=("Segoe UI", 8))
            mode_opt.pack(side="right", padx=5)

            # Model Selection
            model_row = tk.Frame(settings_card, bg="#121212")
            model_row.pack(fill="x", pady=5)
            tk.Label(model_row, text="CLAUDE MODEL:", bg="#121212", fg="#aaaaaa", font=("Segoe UI", 7, "bold")).pack(side="left")
            model_var = tk.StringVar(value="Claude Haiku 4.5")
            model_map = {
                "Claude Haiku 4.5": "claude-haiku-4-5",
                "Claude Sonnet 4.5": "claude-sonnet-4-5",
                "Claude Opus 4.1": "claude-opus-4-1",
                "Claude 3.7 Sonnet": "claude-3-7-sonnet-latest",
                "Claude 3.5 Sonnet": "claude-3-5-sonnet-latest",
                "Claude 3 Haiku": "claude-3-haiku-20240307",
                "Custom ID": "CUSTOM"
            }
            model_options = list(model_map.keys())
            model_opt = tk.OptionMenu(model_row, model_var, *model_options)
            model_opt.config(bg="#1e1e1e", fg="#ffffff", bd=0, highlightthickness=0, activebackground="#333333", font=("Segoe UI", 8))
            model_opt["menu"].config(bg="#1e1e1e", fg="#ffffff", font=("Segoe UI", 8))
            model_opt.pack(side="right", padx=5)

            # Custom Model ID Entry
            custom_model_frame = tk.Frame(settings_card, bg="#121212")
            tk.Label(custom_model_frame, text="CUSTOM MODEL ID:", bg="#121212", fg="#aaaaaa", font=("Segoe UI", 7, "bold")).pack(side="left")
            custom_model_entry = tk.Entry(custom_model_frame, bg="#1e1e1e", fg="#ffffff", insertbackground="#00ff00", bd=0, width=25, font=("Consolas", 9))
            custom_model_entry.pack(side="right", padx=5, ipady=3)
            custom_model_entry.insert(0, "claude-haiku-4-5")
            
            def toggle_custom_model(*args):
                if model_var.get() == "Custom ID":
                    custom_model_frame.pack(fill="x", padx=20, pady=5, after=model_frame)
                else:
                    custom_model_frame.pack_forget()
            
            model_var.trace_add("write", toggle_custom_model)

            # AI Feedback Content
            ai_content_frame = tk.Frame(ai_win, bg="#1e1e1e")
            ai_content_frame.pack(fill="both", expand=True, padx=20)
            
            info_label = tk.Label(ai_content_frame, text="Analyze your session data for offensive or defensive insights.", bg="#1e1e1e", fg="#666666", font=("Segoe UI", 8, "italic"))
            info_label.pack(pady=5)

            text_frame = tk.Frame(ai_content_frame, bg="#1e1e1e", bd=1, highlightbackground="#333333", highlightthickness=1)
            text_frame.pack(fill="both", expand=True, pady=10)
            
            v_scroll = ttk.Scrollbar(text_frame, orient="vertical", style="Vertical.TScrollbar")
            v_scroll.pack(side="right", fill="y")
            
            ai_text = tk.Text(text_frame, bg="#000000", fg="#3498db", insertbackground="#00ff00", bd=0, font=("Consolas", 10), width=50, height=18, yscrollcommand=v_scroll.set, padx=10, pady=10)
            ai_text.tag_configure("error", foreground="#e74c3c")
            ai_text.insert("1.0", "Welcome to the AI Security Assistant.\n\n[Status: Awaiting analysis request...]\n\nClick the button below to start the analysis of your current session history and findings.")
            ai_text.config(state="disabled")
            ai_text.pack(side="left", fill="both", expand=True)
            v_scroll.config(command=ai_text.yview)
            
            def run_ai_analysis():
                api_key = api_key_entry.get().strip()
                selected_mode = analysis_mode_var.get()
                
                # Model selection logic
                model_display_name = model_var.get()
                selected_model = model_map.get(model_display_name)
                if selected_model == "CUSTOM":
                    selected_model = custom_model_entry.get().strip()
                
                if not selected_model:
                    selected_model = "claude-haiku-4-5"
                
                analyzer = AIAnalyzer(api_key=api_key if api_key else None, model=selected_model)
                
                ai_text.config(state="normal")
                ai_text.delete("1.0", tk.END)
                
                current_time = time.strftime("%H:%M:%S")
                ai_text.insert("1.0", f"[*] ANALYSIS INITIATED AT {current_time}\n", "error")
                ai_text.insert(tk.END, "="*40 + "\n")
                ai_text.insert(tk.END, "[*] Gathering latest session data...\n")
                
                # Use absolute latest data from persistent scanner instance
                active_scanner = scanner_instance[0]
                history_data = active_scanner.history
                findings_data = active_scanner.all_findings
                
                ai_text.insert(tk.END, f"[*] FOUND {len(history_data)} TASKS AND {len(findings_data)} FINDINGS.\n")
                ai_text.insert(tk.END, f"[*] MODE: {selected_mode.upper()}\n")
                ai_text.insert(tk.END, f"[*] MODEL: {model_display_name.upper()}\n")
                ai_text.insert(tk.END, "[*] Analyzing data and generating recommendations...\n")
                if api_key:
                    ai_text.insert(tk.END, "[*] Requesting Claude AI analysis...\n\n")
                else:
                    ai_text.insert(tk.END, "[*] Running local analysis engine...\n\n")
                
                def analysis_thread():
                    try:
                        result = analyzer.analyze_session(history_data, findings_data, mode=selected_mode)
                        def update_ui():
                            if result.startswith("[!]"):
                                ai_text.insert(tk.END, result, "error")
                            else:
                                ai_text.insert(tk.END, result)
                            ai_text.see(tk.END)
                            ai_text.config(state="disabled")
                            analyze_btn.config(state="normal", text="RE-RUN ANALYSIS")
                        root.after(0, update_ui)
                    except Exception as e:
                        def update_error():
                            ai_text.insert(tk.END, f"\n[!] ERROR DURING ANALYSIS: {str(e)}", "error")
                            ai_text.config(state="disabled")
                            analyze_btn.config(state="normal", text="RE-RUN ANALYSIS")
                        root.after(0, update_error)

                analyze_btn.config(state="disabled", text="ANALYZING...")
                threading.Thread(target=analysis_thread, daemon=True).start()

            analyze_btn = tk.Button(ai_win, text="GENERATE AI RECOMMENDATIONS", bg="#00ff00", fg="#000000", bd=0, padx=30, pady=10, font=("Segoe UI", 10, "bold"), activebackground="#00cc00", cursor="hand2", command=run_ai_analysis)
            analyze_btn.pack(pady=20)

        # State for tools
        tools_visible = [True] # Tools are now always visible
        view_mode = ["Categorized"] # "Categorized" or "All Tools"
        tool_items = []

        def toggle_view_mode():
            if view_mode[0] == "Categorized":
                view_mode[0] = "All Tools"
            else:
                view_mode[0] = "Categorized"
            render_menu()

        def render_menu():
            current_width = 650
            
            # Clear existing tool-related items
            for item in tool_items:
                if canvas.type(item) == "window":
                    widget_path = canvas.itemcget(item, "window")
                    if widget_path:
                        try:
                            root.nametowidget(widget_path).destroy()
                        except:
                            pass
                canvas.delete(item)
            tool_items.clear()

            # --- Tool Categories (Mapped to functional tools) ---
            tool_descriptions = {
                "Network": "Scan your network to find connected devices and open doors (ports).",
                "Web Scan": "Check websites for hidden files and common security flaws.",
                "Vuln Scan": "Search for known weaknesses (CVEs) in software versions.",
                "System": "Audit local computer settings and permissions.",
                "Hacker Tools": "Advanced tools for testing security and network traffic.",
                "SQL Injection": "Test if a database can be manipulated through input fields.",
                "Password": "Test the strength of passwords using common lists.",
                "Custom Tools": "Create and run your own specialized security commands."
            }
            
            tool_help = {
                "Nmap/Nessus": "The gold standard for finding devices and their vulnerabilities.",
                "Port Scan": "Checks which 'doors' are open on a computer.",
                "Ping Sweep": "Quickly finds which computers are currently online.",
                "Firewall Audit": "Audits the target for firewall misconfigurations and bypasses.",
                "Traffic Monitor": "Monitors network traffic for a set duration and allows exporting to Excel.",
                "WiFi Traffic Analyzer": "Scans available WiFi networks, identifies connected devices and associated data (User, Device Type) on the current network.",
                "Security Camera Finder": "Scans the network for IP addresses of security cameras and identifies their vendor/model.",
                "Sniffer": "Listens to network traffic passing by.",
                "Wireshark": "Opens a powerful tool to inspect every detail of network data.",
                "Nikto-Lite": "A fast scanner that looks for dangerous files on web servers.",
                "DirBrute": "Tries to guess names of hidden folders on a website.",
                "Burp Suite": "A professional tool for 'intercepting' and changing web data.",
                "CVE Search": "Looks up known bugs for specific software names.",
                "WPScan-Lite": "Specialized scanner for WordPress websites.",
                "Win Audit": "Checks if your Windows settings are secure.",
                "FTP Brute": "Tests if an FTP site has weak passwords.",
                "Subdomains": "Finds related websites (like 'dev.example.com').",
                "Metasploit": "A famous framework for testing known exploits.",
                "Rev Shell": "Creates a way to remotely control a computer (for testing).",
                "Packet Interceptor": "Intercepts and copies text messages and files sent over the network.",
                "DDoS Tool": "Simulates a heavy load of traffic to test server stability.",
                "DB Breacher": "Extracts schemas, tables, and sensitive records from a vulnerable database.",
                "SQLMap-Lite": "Automatically finds ways to break into databases.",
                "XSS-to-SQL": "Tests for vulnerabilities that jump from website scripts to the database.",
                "NoSQL Injector": "Tests modern databases (like MongoDB) for security flaws.",
                "John The Ripper": "A classic tool for checking if passwords are easy to guess.",
                "Full Audit": "Orchestrates a comprehensive security review by running all core scan tools sequentially.",
                "Custom Cmd": "Run any command line tool against your target.",
                "Web Fetch": "Download a website's main page to check for responsiveness.",
                "NSLookup": "Query DNS servers for domain information."
            }

            tool_categories = {
                "Network": [
                    ("Nmap/Nessus", lambda: show_tool_screen("Nmap/Nessus", scanner.nmap_nessus_scan)),
                    ("Port Scan", lambda: show_tool_screen("Port Scan", scanner.port_scan)),
                    ("Ping Sweep", lambda: show_tool_screen("Ping Sweep", scanner.ping_sweep)),
                    ("Firewall Audit", lambda: show_tool_screen("Firewall Audit", scanner.firewall_audit)),
                    ("Traffic Monitor", lambda: show_tool_screen("Traffic Monitor", scanner.traffic_monitor)),
                    ("WiFi Traffic Analyzer", lambda: show_tool_screen("WiFi Traffic Analyzer", scanner.wifi_traffic_analyzer)),
                    ("Security Camera Finder", lambda: show_tool_screen("Security Camera Finder", scanner.security_camera_finder)),
                    ("Sniffer", lambda: show_tool_screen("Sniffer", scanner.sniffer)),
                    ("Wireshark", lambda: show_tool_screen("Wireshark", scanner.wireshark_launch))
                ],
                "Web Scan": [
                    ("Nikto-Lite", lambda: show_tool_screen("Nikto-Lite", scanner.nikto_lite)),
                    ("DirBrute", lambda: show_tool_screen("DirBrute", scanner.dir_brute)),
                    ("Burp Suite", lambda: show_tool_screen("Burp Suite", scanner.burp_suite_link))
                ],
                "Vuln Scan": [
                    ("CVE Search", lambda: show_tool_screen("CVE Search", scanner.cve_search)),
                    ("WPScan-Lite", lambda: show_tool_screen("WPScan-Lite", scanner.wpscan_lite))
                ],
                "System": [
                    ("Win Audit", lambda: show_tool_screen("Win Audit", scanner.win_audit)),
                    ("LinPeas", lambda: show_tool_screen("LinPeas", scanner.linpeas_audit)),
                    ("Auditd", lambda: show_tool_screen("Auditd", scanner.auditd_scan))
                ],
                "Hacker Tools": [
                    ("FTP Brute", lambda: show_tool_screen("FTP Brute", scanner.ftp_brute)),
                    ("Subdomains", lambda: show_tool_screen("Subdomains", scanner.subdomain_scan)),
                    ("Metasploit", lambda: show_tool_screen("Metasploit", scanner.metasploit_meterpreter)),
                    ("Rev Shell", lambda: show_tool_screen("Rev Shell", scanner.rev_shell_gen)),
                    ("Packet Interceptor", lambda: show_tool_screen("Packet Interceptor", scanner.packet_interceptor)),
                    ("DDoS Tool", lambda: show_ddos_screen(scanner))
                ],
                "SQL Injection": [
                    ("DB Breacher", lambda: show_tool_screen("DB Breacher", scanner.db_breacher)),
                    ("SQLMap-Lite", lambda: show_tool_screen("SQLMap-Lite", scanner.sql_map_lite)),
                    ("XSS-to-SQL", lambda: show_tool_screen("XSS-to-SQL", scanner.xss_to_sql)),
                    ("NoSQL Injector", lambda: show_tool_screen("NoSQL Injector", scanner.nosql_injector))
                ],
                "Password": [
                    ("John The Ripper", lambda: show_tool_screen("John The Ripper", scanner.john_the_ripper)),
                    ("Hydra Brute", lambda: show_tool_screen("Hydra Brute", scanner.hydra_brute))
                ],
                "Custom Tools": [
                    ("Full Audit", lambda: show_tool_screen("Full Audit", scanner.full_audit)),
                    ("Custom Cmd", lambda: show_tool_screen("Custom Cmd", scanner.custom_command)),
                    ("Web Fetch", lambda: show_tool_screen("Web Fetch", lambda t, **k: scanner.custom_command(t, "curl -I {target}"))),
                    ("NSLookup", lambda: show_tool_screen("NSLookup", lambda t, **k: scanner.custom_command(t, "nslookup {target}")))
                ]
            }

            view_btn_text = "VIEW: " + view_mode[0].upper()
            view_btn = tk.Button(root, text=view_btn_text, bg="#1e1e1e", fg="#aaaaaa",
                                 activebackground="#333333", activeforeground=accent_color.get(), width=18, bd=0,
                                 font=("Segoe UI", 8, "bold"), command=toggle_view_mode, cursor="hand2")
            tool_items.append(canvas.create_window(20, 125, window=view_btn, anchor="w"))

            if is_admin:
                admin_btn = tk.Button(root, text="ADMIN PANEL", bg="#1e1e1e", fg="#f1c40f", 
                                       activebackground="#333333", activeforeground="#f1c40f", width=14, bd=0,
                                       font=("Segoe UI", 8, "bold"), command=show_admin_panel, cursor="hand2")
                tool_items.append(canvas.create_window(current_width - 20, 125, window=admin_btn, anchor="e"))

                admin_ai_btn = tk.Button(root, text="AI ANALYST", bg="#1e1e1e", fg="#e67e22", 
                                         activebackground="#333333", activeforeground="#e67e22", width=14, bd=0,
                                         font=("Segoe UI", 8, "bold"), command=show_admin_ai_analyst, cursor="hand2")
                tool_items.append(canvas.create_window(current_width - 130, 125, window=admin_ai_btn, anchor="e"))

            ai_btn = tk.Button(root, text="AI FEEDBACK", bg="#1e1e1e", fg="#00ff00", 
                                   activebackground="#333333", activeforeground="#00ff00", width=14, bd=0,
                                   font=("Segoe UI", 8, "bold"), command=show_ai_feedback_screen, cursor="hand2")
            if is_admin:
                ai_x = current_width - 240
            else:
                ai_x = current_width - 20
            tool_items.append(canvas.create_window(ai_x, 125, window=ai_btn, anchor="e"))

            # --- Theme Selector ---
            def set_theme(color_hex):
                accent_color.set(color_hex)
                style.configure("Horizontal.TProgressbar", background=color_hex)
                style.configure("Vertical.TScrollbar", arrowcolor=color_hex)
                style.map("TNotebook.Tab", foreground=[('selected', color_hex)])
                render_menu()

            theme_frame = tk.Frame(root, bg=bg_color.get())
            theme_label = tk.Label(theme_frame, text="THEME:", bg=bg_color.get(), fg="#666666", font=("Segoe UI", 7, "bold"))
            theme_label.pack(side="left")
            
            colors = [("#00ff00", "Green"), ("#3498db", "Blue"), ("#e74c3c", "Red"), ("#f1c40f", "Gold"), ("#9b59b6", "Purple")]
            for color, name in colors:
                btn = tk.Button(theme_frame, bg=color, width=1, height=0, bd=0, command=lambda c=color: set_theme(c), cursor="hand2")
                btn.pack(side="left", padx=2)
            
            tool_items.append(canvas.create_window(20, 100, window=theme_frame, anchor="w"))

            start_y = 170
            btn_gap_x = 125
            btns_per_row = 5

            if view_mode[0] == "Categorized":
                cat_gap_y = 100
                for i, (category, tools) in enumerate(tool_categories.items()):
                    cat_y = start_y + (i * cat_gap_y)
                    # Category Header with background
                    cat_header_frame = tk.Frame(root, bg="#121212", padx=10)
                    tk.Label(cat_header_frame, text=category.upper(), font=("Segoe UI", 8, "bold"), bg="#121212", fg="#00ff00").pack()
                    cat_label = canvas.create_window(20, cat_y, window=cat_header_frame, anchor="w")
                    tool_items.append(cat_label)
                    
                    # Category Tooltip
                    cat_header_frame.bind("<Enter>", lambda e, c=category: canvas.itemconfig(status_text, text=tool_descriptions.get(c, ""), fill=accent_color.get()))
                    cat_header_frame.bind("<Leave>", lambda e: canvas.itemconfig(status_text, text="", fill=fg_color))

                    for j, (tool_name, tool_cmd) in enumerate(tools):
                        row = j // btns_per_row
                        col = j % btns_per_row
                        btn_y = cat_y + 35 + (row * 35)
                        
                        btn = tk.Button(root, text=tool_name, bg="#1e1e1e", fg="#ffffff", 
                                        activebackground="#333333", activeforeground=accent_color.get(), 
                                        width=14, bd=0, font=("Segoe UI", 8), cursor="hand2")
                        
                        btn.bind("<Enter>", lambda e, name=tool_name: canvas.itemconfig(status_text, text=tool_help.get(name, ""), fill=accent_color.get()))
                        btn.bind("<Leave>", lambda e: canvas.itemconfig(status_text, text="", fill=fg_color))

                        def on_tool_click(cmd=tool_cmd, name=tool_name):
                            if name == "DDoS Tool":
                                show_ddos_screen(scanner)
                                canvas.itemconfig(status_text, text=tool_help.get(name, ""), fill="#aaaaaa")
                                canvas.coords(status_text, 212, 20)
                            else:
                                cmd()
                                canvas.itemconfig(status_text, text=tool_help.get(name, ""), fill="#aaaaaa")
                                canvas.coords(status_text, 212, 20)

                        btn.configure(command=on_tool_click)
                        tool_items.append(canvas.create_window(20 + (col * btn_gap_x), btn_y, window=btn, anchor="w"))
            else:
                # All Tools View
                all_tools = []
                for cat_tools in tool_categories.values():
                    all_tools.extend(cat_tools)
                all_tools.sort(key=lambda x: x[0])
                
                for j, (tool_name, tool_cmd) in enumerate(all_tools):
                    row = j // btns_per_row
                    col = j % btns_per_row
                    btn_y = start_y + (row * 35)
                    
                    btn = tk.Button(root, text=tool_name, bg="#1e1e1e", fg="#ffffff", 
                                    activebackground="#333333", activeforeground=accent_color.get(), 
                                    width=14, bd=0, font=("Segoe UI", 8), cursor="hand2")
                    
                    btn.bind("<Enter>", lambda e, name=tool_name: canvas.itemconfig(status_text, text=tool_help.get(name, ""), fill=accent_color.get()))
                    btn.bind("<Leave>", lambda e: canvas.itemconfig(status_text, text="", fill=fg_color))

                    def on_tool_click(cmd=tool_cmd, name=tool_name):
                        if name == "DDoS Tool":
                            show_ddos_screen(scanner)
                            canvas.itemconfig(status_text, text=tool_help.get(name, ""), fill="#aaaaaa")
                            canvas.coords(status_text, 212, 20)
                        else:
                            cmd()
                            canvas.itemconfig(status_text, text=tool_help.get(name, ""), fill="#aaaaaa")
                            canvas.coords(status_text, 212, 20)

                    btn.configure(command=on_tool_click)
                    tool_items.append(canvas.create_window(20 + (col * btn_gap_x), btn_y, window=btn, anchor="w"))

            root.update_idletasks()
            max_cat_y = 0
            for item in tool_items:
                bbox = canvas.bbox(item)
                if bbox:
                    max_cat_y = max(max_cat_y, bbox[3])

            last_y = max_cat_y + 40
            canvas.coords(log_label_id, 20, last_y)
            canvas.coords(summary_id, current_width / 2, last_y + 110)

            root.update_idletasks()
            max_y = 0
            for item in canvas.find_all():
                if item != bg_image_id:
                    item_bbox = canvas.bbox(item)
                    if item_bbox:
                        max_y = max(max_y, item_bbox[3])
            
            logout_y = max_y + 40
            def on_logout():
                root.withdraw()
                login = LoginWindow(root, on_login_success, db_available=db_available)
                login.show_login()

            logout_btn = tk.Button(root, text="LOGOUT", bg="#662222", fg="#ffffff", 
                                   activebackground="#883333", activeforeground="#ffffff", width=10, bd=0,
                                   font=("Segoe UI", 8, "bold"), command=on_logout, cursor="hand2")
            tool_items.append(canvas.create_window(current_width - 20, logout_y, window=logout_btn, anchor="e"))
            
            update_window_size(width=current_width, centered_items=[welcome_id, summary_id, target_label_id, target_window_id])

        # Initialize menu view
        render_menu()

    def on_login_success(is_admin, username):
        logging.info(f"Login success for {username}. Showing main menu.")
        apply_overrideredirect()
        root.deiconify()
        show_main_menu(username, is_admin, db_available=db_available)
        # Force a resize update
        update_window_size(width=650, target_height=750)

    # Initially hide the main root window
    root.withdraw()

    # Show login window
    login = LoginWindow(root, on_login_success, db_available=db_available)
    login.show_login()

    # Start the event loop
    logging.info("Starting mainloop...")
    root.mainloop()
    logging.info("Mainloop exited.")

if __name__ == "__main__":
    main()
