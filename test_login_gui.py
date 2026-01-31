"""
Minimal test GUI to verify database login works
Save as: test_login_gui.py
Run: python test_login_gui.py
"""

import tkinter as tk
from tkinter import messagebox, scrolledtext
import threading
import time

try:
    from db_connection import DatabaseConnection
    DB_MODULE_AVAILABLE = True
except ImportError:
    DB_MODULE_AVAILABLE = False


class MinimalLoginTest:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Database Login Test")
        self.root.geometry("600x500")
        
        # Title
        tk.Label(
            self.root,
            text="Database Login Test",
            font=("Arial", 16, "bold")
        ).pack(pady=10)
        
        # Check if DB module is available
        if not DB_MODULE_AVAILABLE:
            tk.Label(
                self.root,
                text="❌ ERROR: db_connection.py not found!",
                fg="red",
                font=("Arial", 12)
            ).pack(pady=10)
            tk.Button(
                self.root,
                text="Exit",
                command=self.root.quit
            ).pack(pady=10)
            return
        
        # Connection status
        self.status_label = tk.Label(
            self.root,
            text="Not connected",
            fg="orange",
            font=("Arial", 10)
        )
        self.status_label.pack(pady=5)
        
        # Login frame
        login_frame = tk.LabelFrame(self.root, text="Login Credentials", padx=20, pady=20)
        login_frame.pack(padx=20, pady=10, fill="both")
        
        tk.Label(login_frame, text="Username:").grid(row=0, column=0, sticky="w", pady=5)
        self.username_entry = tk.Entry(login_frame, width=30)
        self.username_entry.grid(row=0, column=1, pady=5)
        self.username_entry.insert(0, "Layer8Wes")  # Default from your db_connection.py
        
        tk.Label(login_frame, text="Password:").grid(row=1, column=0, sticky="w", pady=5)
        self.password_entry = tk.Entry(login_frame, width=30, show="*")
        self.password_entry.grid(row=1, column=1, pady=5)
        self.password_entry.insert(0, "Valorant123!")  # Default from your db_connection.py
        
        # Buttons
        btn_frame = tk.Frame(login_frame)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        tk.Button(
            btn_frame,
            text="Test Connection",
            command=self.test_connection,
            bg="#3498db",
            fg="white",
            width=15
        ).pack(side="left", padx=5)
        
        tk.Button(
            btn_frame,
            text="Test Login",
            command=self.test_login,
            bg="#27ae60",
            fg="white",
            width=15
        ).pack(side="left", padx=5)
        
        # Log output
        tk.Label(self.root, text="Log Output:", font=("Arial", 10, "bold")).pack(pady=(10, 0))
        self.log_text = scrolledtext.ScrolledText(self.root, height=15, width=70)
        self.log_text.pack(padx=20, pady=10)
        
        self.log("Application started")
        self.log("Click 'Test Connection' to check database connectivity")
        
    def log(self, message):
        """Add message to log"""
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.root.update()
    
    def test_connection(self):
        """Test database connection"""
        self.log("\n=== Testing Database Connection ===")
        self.status_label.config(text="Connecting...", fg="orange")
        
        def do_test():
            try:
                self.log("Creating DatabaseConnection object...")
                db = DatabaseConnection()
                
                self.log("Attempting to connect to database...")
                self.log(f"  Host: {db.host}")
                self.log(f"  Port: {db.port}")
                self.log(f"  Database: {db.database}")
                self.log(f"  User: {db.user}")
                
                success, error = db.connect()
                
                if success:
                    self.log("✅ SUCCESS: Connected to database!")
                    self.status_label.config(text="✅ Connected", fg="green")
                    
                    # Check if table exists
                    self.log("\nChecking for user_logins table...")
                    table_success, table_msg = db.ensure_table_exists()
                    if table_success:
                        self.log(f"✅ {table_msg}")
                    else:
                        self.log(f"❌ {table_msg}")
                    
                    db.close()
                    self.log("\nDatabase connection closed")
                else:
                    self.log(f"❌ FAILED: {error}")
                    self.status_label.config(text="❌ Connection failed", fg="red")
                    
            except Exception as e:
                self.log(f"❌ EXCEPTION: {str(e)}")
                import traceback
                self.log(traceback.format_exc())
                self.status_label.config(text="❌ Error", fg="red")
        
        threading.Thread(target=do_test, daemon=True).start()
    
    def test_login(self):
        """Test login with credentials"""
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showwarning("Input Required", "Please enter both username and password")
            return
        
        self.log(f"\n=== Testing Login for '{username}' ===")
        self.status_label.config(text="Logging in...", fg="orange")
        
        def do_login():
            try:
                db = DatabaseConnection()
                
                self.log("Connecting to database...")
                success, error = db.connect()
                
                if not success:
                    self.log(f"❌ Connection failed: {error}")
                    self.status_label.config(text="❌ Connection failed", fg="red")
                    return
                
                self.log("✅ Connected!")
                self.log(f"Verifying credentials for '{username}'...")
                
                login_success, result = db.verify_login(username, password)
                
                if login_success:
                    self.log("✅ LOGIN SUCCESSFUL!")
                    self.log(f"\nUser Data:")
                    for key, value in result.items():
                        self.log(f"  {key}: {value}")
                    
                    self.status_label.config(text="✅ Login successful", fg="green")
                    
                    messagebox.showinfo(
                        "Success",
                        f"Login successful!\n\nWelcome, {result.get('username')}!"
                    )
                else:
                    self.log(f"❌ LOGIN FAILED: {result}")
                    self.status_label.config(text="❌ Login failed", fg="red")
                    
                    messagebox.showerror(
                        "Login Failed",
                        f"Login failed:\n\n{result}"
                    )
                
                db.close()
                self.log("Database connection closed")
                
            except Exception as e:
                self.log(f"❌ EXCEPTION: {str(e)}")
                import traceback
                self.log(traceback.format_exc())
                self.status_label.config(text="❌ Error", fg="red")
        
        threading.Thread(target=do_login, daemon=True).start()
    
    def run(self):
        """Start the GUI"""
        self.root.mainloop()


if __name__ == "__main__":
    app = MinimalLoginTest()
    app.run()
