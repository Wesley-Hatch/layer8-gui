import tkinter as tk
from tkinter import ttk, messagebox
import base64
from secure_config import SecureConfig
from credential_generator import generate_pepper, generate_encryption_key
from secure_logger import get_logger

# Set up secure logging
logger = get_logger('application')

class SetupWizard:
    """
    First-run setup wizard for Layer8
    
    Collects:
    - Database host, port, name, user, password
    - Pepper
    - Encryption key
    - Master password (for encrypted storage fallback)
    
    Tests connection before saving.
    """
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Layer8 Setup Wizard")
        self.root.geometry("500x600")
        self.root.resizable(False, False)
        
        self.config = SecureConfig()
        self.current_step = 0
        
        # Variables to store user input
        self.db_host = tk.StringVar(value="127.0.0.1")
        self.db_port = tk.StringVar(value="3306")
        self.db_name = tk.StringVar(value="u844677182_app")
        self.db_user = tk.StringVar()
        self.db_password = tk.StringVar()
        self.pepper = tk.StringVar()
        self.pwd_key = tk.StringVar()
        self.master_password = tk.StringVar()
        
        self.main_frame = ttk.Frame(self.root, padding="20")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        self.content_frame = ttk.Frame(self.main_frame)
        self.content_frame.pack(fill=tk.BOTH, expand=True)
        
        self.nav_frame = ttk.Frame(self.main_frame)
        self.nav_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=(20, 0))
        
        self.prev_button = ttk.Button(self.nav_frame, text="Back", command=self._prev_step)
        self.prev_button.pack(side=tk.LEFT)
        
        self.next_button = ttk.Button(self.nav_frame, text="Next", command=self._next_step)
        self.next_button.pack(side=tk.RIGHT)
        
        self.steps = [
            self._welcome_step,
            self._database_credentials_step,
            self._security_keys_step,
            self._master_password_step,
            self._test_connection_step,
            self._completion_step
        ]
        
        self._show_step()

    def _clear_content(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

    def _show_step(self):
        self._clear_content()
        self.steps[self.current_step]()
        
        self.prev_button.config(state=tk.NORMAL if self.current_step > 0 else tk.DISABLED)
        
        if self.current_step == len(self.steps) - 1:
            self.next_button.config(text="Finish", command=self.root.destroy)
        elif self.current_step == 4: # Test connection step
             self.next_button.config(text="Save & Next", command=self._save_and_next)
        else:
            self.next_button.config(text="Next", command=self._next_step)

    def _prev_step(self):
        if self.current_step > 0:
            self.current_step -= 1
            self._show_step()

    def _next_step(self):
        if self.current_step < len(self.steps) - 1:
            # Validation before moving forward
            if self.current_step == 1: # DB creds
                if not all([self.db_host.get(), self.db_port.get(), self.db_name.get(), self.db_user.get(), self.db_password.get()]):
                    messagebox.showerror("Error", "All database fields are required.")
                    return
            elif self.current_step == 2: # Security keys
                if len(self.pepper.get()) < 32:
                    messagebox.showerror("Error", "Pepper must be at least 32 characters.")
                    return
                try:
                    key = base64.b64decode(self.pwd_key.get())
                    if len(key) != 32:
                        raise ValueError()
                except:
                    messagebox.showerror("Error", "Encryption key must be a valid 32-byte Base64 string.")
                    return
            elif self.current_step == 3: # Master password
                if not self.master_password.get():
                    messagebox.showerror("Error", "Master password is required for backup storage.")
                    return

            self.current_step += 1
            self._show_step()

    def _save_and_next(self):
        credentials = {
            'db_host': self.db_host.get(),
            'db_port': int(self.db_port.get()),
            'db_name': self.db_name.get(),
            'db_user': self.db_user.get(),
            'db_password': self.db_password.get(),
            'pepper': self.pepper.get(),
            'pwd_key': base64.b64decode(self.pwd_key.get())
        }
        
        try:
            self.config.save_credentials(credentials, self.master_password.get())
            logger.info("Setup wizard completed successfully.")
            self.current_step += 1
            self._show_step()
        except Exception as e:
            logger.error(f"Setup wizard failed to save credentials: {e}")
            messagebox.showerror("Error", f"Failed to save credentials: {e}")

    def _welcome_step(self):
        ttk.Label(self.content_frame, text="Welcome to Layer8 Setup", font=("Helvetica", 16, "bold")).pack(pady=(0, 20))
        ttk.Label(self.content_frame, text="This wizard will help you configure your database\nand security settings.", justify=tk.CENTER).pack(pady=10)
        ttk.Label(self.content_frame, text="Your credentials will be stored securely in your\nsystem's keyring and an encrypted local file.", justify=tk.CENTER).pack(pady=10)
        
        # Migration check
        migratable = self.config.migrate_from_env()
        if migratable:
            ttk.Label(self.content_frame, text="\nOld configuration detected!", foreground="green").pack()
            ttk.Button(self.content_frame, text="Import from .env", command=self._import_from_env).pack(pady=10)

    def _import_from_env(self):
        creds = self.config.migrate_from_env()
        if creds:
            self.db_host.set(creds.get('db_host', ''))
            self.db_port.set(str(creds.get('db_port', '3306')))
            self.db_name.set(creds.get('db_name', ''))
            self.db_user.set(creds.get('db_user', ''))
            self.db_password.set(creds.get('db_password', ''))
            self.pepper.set(creds.get('pepper', ''))
            if isinstance(creds.get('pwd_key'), bytes):
                self.pwd_key.set(base64.b64encode(creds['pwd_key']).decode('utf-8'))
            else:
                self.pwd_key.set(creds.get('pwd_key', ''))
            messagebox.showinfo("Success", "Credentials imported from .env. Please review them in the next steps.")
            self.current_step = 1
            self._show_step()

    def _database_credentials_step(self):
        ttk.Label(self.content_frame, text="Database Credentials", font=("Helvetica", 14, "bold")).pack(pady=(0, 20))
        
        fields = [
            ("Host:", self.db_host),
            ("Port:", self.db_port),
            ("Database Name:", self.db_name),
            ("Username:", self.db_user),
            ("Password:", self.db_password)
        ]
        
        for label, var in fields:
            frame = ttk.Frame(self.content_frame)
            frame.pack(fill=tk.X, pady=5)
            ttk.Label(frame, text=label, width=15).pack(side=tk.LEFT)
            if "Password" in label:
                ttk.Entry(frame, textvariable=var, show="*").pack(side=tk.LEFT, fill=tk.X, expand=True)
            else:
                ttk.Entry(frame, textvariable=var).pack(side=tk.LEFT, fill=tk.X, expand=True)

    def _security_keys_step(self):
        ttk.Label(self.content_frame, text="Security Keys", font=("Helvetica", 14, "bold")).pack(pady=(0, 20))
        ttk.Label(self.content_frame, text="These keys are used for password hashing and encryption.\nDO NOT LOSE THEM.", foreground="red", justify=tk.CENTER).pack(pady=10)
        
        ttk.Label(self.content_frame, text="Pepper (min 32 chars):").pack(anchor=tk.W)
        ttk.Entry(self.content_frame, textvariable=self.pepper).pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(self.content_frame, text="Encryption Key (32-byte Base64):").pack(anchor=tk.W)
        ttk.Entry(self.content_frame, textvariable=self.pwd_key).pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(self.content_frame, text="Generate Random Keys", command=self._generate_keys).pack(pady=10)

    def _generate_keys(self):
        self.pepper.set(generate_pepper())
        self.pwd_key.set(generate_encryption_key())

    def _master_password_step(self):
        ttk.Label(self.content_frame, text="Master Password", font=("Helvetica", 14, "bold")).pack(pady=(0, 20))
        ttk.Label(self.content_frame, text="This password will be used to encrypt the backup\nconfiguration file stored on your disk.", justify=tk.CENTER).pack(pady=10)
        
        ttk.Label(self.content_frame, text="Master Password:").pack(anchor=tk.W)
        ttk.Entry(self.content_frame, textvariable=self.master_password, show="*").pack(fill=tk.X, pady=5)
        
        ttk.Label(self.content_frame, text="Confirm Master Password:").pack(anchor=tk.W)
        self.confirm_pwd = tk.StringVar()
        ttk.Entry(self.content_frame, textvariable=self.confirm_pwd, show="*").pack(fill=tk.X, pady=5)

    def _test_connection_step(self):
        ttk.Label(self.content_frame, text="Test Connection", font=("Helvetica", 14, "bold")).pack(pady=(0, 20))
        
        self.test_result = tk.StringVar(value="Click 'Test Connection' to verify settings.")
        ttk.Label(self.content_frame, textvariable=self.test_result, wraplength=400, justify=tk.CENTER).pack(pady=20)
        
        ttk.Button(self.content_frame, text="Test Connection", command=self._perform_test).pack(pady=10)

    def _perform_test(self):
        credentials = {
            'db_host': self.db_host.get(),
            'db_port': self.db_port.get(),
            'db_name': self.db_name.get(),
            'db_user': self.db_user.get(),
            'db_password': self.db_password.get()
        }
        self.test_result.set("Testing connection... please wait.")
        self.root.update_idletasks()
        
        success, message = self.config.test_database_connection(credentials)
        self.test_result.set(message)
        if success:
            messagebox.showinfo("Success", "Database connection successful!")
        else:
            messagebox.showerror("Error", f"Database connection failed: {message}")

    def _completion_step(self):
        ttk.Label(self.content_frame, text="Setup Complete!", font=("Helvetica", 16, "bold"), foreground="green").pack(pady=(0, 20))
        ttk.Label(self.content_frame, text="Layer8 has been configured successfully.\n\nYour credentials are stored securely.\nYou can now start using the application.", justify=tk.CENTER).pack(pady=20)

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    wizard = SetupWizard()
    wizard.run()
