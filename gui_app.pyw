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
from secure_logger import get_logger

# Set up secure logging
logger = get_logger('application')

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
            text="ENTERPRISE SECURITY PLATFORM",
            variant="small",
            fg=ModernTheme.COLORS['fg_tertiary']
        )
        subtitle_label.pack(pady=(0, 30))

        # Login card container with modern frame
        login_frame = ModernFrame(main_container)
        login_frame.pack(fill=tk.BOTH, expand=True)

        # Inner padding frame
        inner_frame = tk.Frame(login_frame, bg=ModernTheme.COLORS['bg_secondary'])
        inner_frame.pack(fill=tk.BOTH, expand=True, padx=ModernTheme.SPACING['xl'], pady=ModernTheme.SPACING['xl'])
        
        # Email field (verified against the website access console)
        ModernLabel(
            inner_frame,
            text="EMAIL",
            variant="tiny",
            fg=ModernTheme.COLORS['fg_secondary']
        ).pack(anchor="w", pady=(0, 8))

        self.username_entry = ModernEntry(
            inner_frame,
            placeholder="Enter your email",
            width=35
        )
        self.username_entry.pack(fill='x', ipady=12, pady=(0, 24))
        self.username_entry.focus()

        # Access key field (the key issued by the website console)
        ModernLabel(
            inner_frame,
            text="ACCESS KEY",
            variant="tiny",
            fg=ModernTheme.COLORS['fg_secondary']
        ).pack(anchor="w", pady=(0, 8))

        self.password_entry = ModernEntry(
            inner_frame,
            placeholder="XXXXX-XXXXX-XXXXX-XXXXX",
            show="*",
            width=35
        )
        self.password_entry.pack(fill='x', ipady=12, pady=(0, 16))

        # Status label
        self.status_label = ModernLabel(
            inner_frame,
            text="",
            variant="small",
            fg=ModernTheme.COLORS['fg_tertiary']
        )
        self.status_label.pack(pady=(0, 20))

        # Login button with modern styling
        self.login_button = ModernButton(
            inner_frame,
            text="SIGN IN",
            variant="primary",
            command=self.attempt_login
        )
        self.login_button.pack(fill='x', ipady=6, pady=(0, 16))

        # Bind Enter key
        self.username_entry.bind('<Return>', lambda e: self.attempt_login())
        self.password_entry.bind('<Return>', lambda e: self.attempt_login())
        
        # Handle window close
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)
        
        logger.info("Login window displayed")
    
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
            logger.warning("Login attempt with empty credentials")
            return
        
        # Check max attempts
        self.login_attempts += 1
        if self.login_attempts > self.max_attempts:
            messagebox.showerror(
                "Too Many Attempts",
                "Too many failed login attempts. Application will close."
            )
            logger.error(f"Max login attempts exceeded ({self.max_attempts})")
            self.parent.quit()
            return
        
        # Disable button during login
        self.login_button.config(state=tk.DISABLED, text="Signing in...")
        from modern_theme import ModernTheme
        self.update_status("Verifying access...", ModernTheme.COLORS['info'])
        
        # Run login in separate thread to prevent GUI freeze
        threading.Thread(
            target=self._perform_login,
            args=(username, password),
            daemon=True
        ).start()
    
    def _perform_login(self, username, password):
        """Verify the person against the website access console.

        The username field is their EMAIL and the password field is their ACCESS
        KEY, both issued/controlled from the web admin console. The website is
        the source of truth: suspend / revoke / expire / seat limits / version
        floor / maintenance all take effect here at sign-in.
        """
        email = (username or "").strip().lower()
        access_key = (password or "").strip()
        try:
            logger.info(f"Access sign-in attempt {self.login_attempts} for {email}")

            import access_client
            result = access_client.check_access(email, access_key)

            if result.get('allowed'):
                logger.info(f"Access granted for {email} "
                            f"(reason={result.get('reason')}, offline={result.get('offline')})")
                # The website 'plan' decides in-app admin rights: an 'admin' or
                # 'owner' plan unlocks the app's admin features.
                is_admin = str(result.get('plan', '')).lower() in ('admin', 'owner')
                user_data = {
                    'username': result.get('name') or email,
                    'email': email,
                    'is_admin': is_admin,
                    'plan': result.get('plan', ''),
                }
                self.window.after(0, lambda: self._login_success(user_data))
            else:
                logger.warning(f"Access denied for {email}: {result.get('reason')}")
                self.window.after(0, lambda: self._login_failed(
                    result.get('message') or 'Access denied.'))

        except Exception as e:
            error_msg = f"Unexpected error during sign-in: {str(e)}"
            logger.error(error_msg, exc_info=True)
            self.window.after(0, lambda: self._login_failed(error_msg))
    
    def _login_success(self, user_data):
        """Handle successful login (runs on main thread)"""
        try:
            is_admin = user_data.get('is_admin', False)
            username = user_data.get('username', 'Unknown')
            
            logger.info(f"Login success handler called for {username}")
            
            # Close login window
            if self.window:
                self.window.destroy()
            
            # Call success callback
            if self.on_success_callback:
                self.on_success_callback(is_admin, username)
            
        except Exception as e:
            logger.error(f"Error in login success handler: {e}", exc_info=True)
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
            logger.error(f"Error in login failure handler: {e}", exc_info=True)
    
    def on_close(self):
        """Handle window close"""
        result = messagebox.askyesno(
            "Exit",
            "Are you sure you want to exit?"
        )
        if result:
            logger.info("User cancelled login")
            self.parent.quit()

def get_resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)


def main(db_available=None, db_error=None):
    # Access is verified against the website console at sign-in; there is no
    # local database to set up, so the app launches straight to the login.
    db_available = True

    logger.info("Main application starting")

    root = tk.Tk()
    logger.info("Tkinter root created.")
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
    from updater_gui import add_updater_to_gui

    # Resolve the running version from version.json, which build.py writes from the
    # git tag (L8_VERSION) and ships next to the executable. This makes Help and the
    # updater always reflect the ACTUAL release instead of a stale hardcoded value
    # (previously every build reported 1.4.2). Falls back to the constant only for
    # source checkouts that have no built version.json.
    def _resolve_current_version(fallback="1.5.5"):
        import json
        try:
            base = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) \
                else os.path.dirname(os.path.abspath(__file__))
            vpath = os.path.join(base, "version.json")
            if os.path.isfile(vpath):
                with open(vpath, "r", encoding="utf-8") as fh:
                    v = str(json.load(fh).get("version", "")).strip()
                if v:
                    return v
        except Exception:
            pass
        return fallback

    current_version = _resolve_current_version()
    updater_gui = add_updater_to_gui(
        root=root,
        menu_bar=menu_bar,
        current_version=current_version,
        update_url="https://api.github.com/repos/Wesley-Hatch/layer8-gui/releases/latest"
    )

    # Check for updates in background (silent check on startup)
    def check_updates_background():
        """Check for updates silently and notify user if available"""
        try:
            import time
            time.sleep(3)  # Wait 3 seconds after app starts

            if updater_gui.check_for_updates_silent():
                # Update available - show notification
                def show_notification():
                    response = messagebox.askyesno(
                        "Update Available",
                        f"Layer8 v{updater_gui.updater.latest_version} is available!\n"
                        f"Current version: {current_version}\n\n"
                        "Would you like to download and install it now?"
                    )

                    if response:
                        updater_gui.download_and_install_with_progress()

                root.after(0, show_notification)
        except Exception as e:
            logger.error(f"Background update check failed: {e}")

    # Start background checker
    threading.Thread(target=check_updates_background, daemon=True).start()
    logger.info(f"Auto-update enabled (current version: {current_version})")
    
    # Delay overrideredirect to ensure window is properly initialized
    def apply_overrideredirect():
        try:
            root.overrideredirect(True)
            logger.info("Overrideredirect(True) applied.")
        except Exception as e:
            logger.error(f"Error applying overrideredirect: {e}")
    
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
            admin_title_id = canvas.create_text(212, 40, text="Admin Panel", fill=fg_color, font=("Arial", 14, "bold"), anchor="center")

            # Back to Main Menu
            back_btn = tk.Button(root, text="Back", bg="#444444", fg=fg_color, bd=0, command=lambda: show_main_menu(username, is_admin, db_available))
            canvas.create_window(20, 40, window=back_btn, anchor="w")

            admin_info = (
                "User accounts are managed in the\n"
                "Layer8 web console.\n\n"
                "Create, suspend, revoke or expire users,\n"
                "assign plans and manage device seats there.\n"
                "Changes take effect the next time a\n"
                "user signs in to this app."
            )
            info_id = canvas.create_text(
                212, 200, text=admin_info,
                fill=fg_color, font=("Segoe UI", 11), anchor="center", justify="center")

            def _open_console():
                import webbrowser
                webbrowser.open("https://hatchtag.dev/access/")

            open_btn = tk.Button(root, text="Open Web Console", bg="#226622", fg=fg_color, bd=0, width=20, command=_open_console)
            open_btn_id = canvas.create_window(212, 330, window=open_btn, anchor="center")

            update_window_size(width=650, target_height=750, centered_items=[admin_title_id, info_id, open_btn_id])

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
        activity_tree = ttk.Treeview(summary_frame, columns=columns, show="headings", height=8, style="Treeview")
        activity_tree.heading("Time", text="Time")
        activity_tree.heading("Tool/Task", text="Tool/Task")
        activity_tree.heading("Status", text="Status")
        activity_tree.heading("Report", text="Report")
        # Widths kept so the whole table fits under the left column (~555px total)
        activity_tree.column("Time", width=75, anchor="center")
        activity_tree.column("Tool/Task", width=150, anchor="w")
        activity_tree.column("Status", width=80, anchor="center")
        activity_tree.column("Report", width=250, anchor="w")
        
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
                
                # Keep the wide dashboard sized correctly after populating reports
                if len(scanner.history) > 0:
                    update_window_size(width=1180, centered_items=[])
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

        def show_tool_usecase(tool_name):
            """Open a themed panel describing a tool's purpose, when/how to use it,
            its capabilities and caveats (content from tool_docs.TOOL_DOCS)."""
            try:
                from tool_docs import get_tool_doc
            except Exception:
                messagebox.showinfo("Use Case", "Tool documentation is unavailable.")
                return
            doc = get_tool_doc(tool_name)

            win = tk.Toplevel(root)
            win.overrideredirect(True)
            win.geometry("560x580")
            win.configure(bg="#1e1e1e")
            try:
                win.update_idletasks()
                x = root.winfo_x() + (root.winfo_width() // 2) - 280
                y = root.winfo_y() + (root.winfo_height() // 2) - 290
                win.geometry(f"+{max(x, 0)}+{max(y, 0)}")
            except Exception:
                pass

            bar = tk.Frame(win, bg=title_bar_color.get(), height=30)
            bar.pack(side="top", fill="x")
            tk.Label(bar, text=f"USE CASE  —  {tool_name}", bg=title_bar_color.get(), fg=fg_color,
                     font=("Segoe UI", 10, "bold")).pack(side="left", padx=10)
            tk.Button(bar, text="✕", command=win.destroy, bg=title_bar_color.get(), fg=fg_color,
                      bd=0, activebackground="red", activeforeground=fg_color, font=("Arial", 12),
                      width=3).pack(side="right")

            def _sm(e):
                win._dx, win._dy = e.x, e.y

            def _mv(e):
                win.geometry(f"+{win.winfo_x() + e.x - win._dx}+{win.winfo_y() + e.y - win._dy}")
            bar.bind("<Button-1>", _sm)
            bar.bind("<B1-Motion>", _mv)

            frame = tk.Frame(win, bg="#1e1e1e")
            frame.pack(fill="both", expand=True, padx=2, pady=2)
            sb = tk.Scrollbar(frame)
            sb.pack(side="right", fill="y")
            txt = tk.Text(frame, bg="#0d0d0d", fg="#e0e0e0", bd=0, wrap="word",
                          font=("Segoe UI", 10), yscrollcommand=sb.set, padx=14, pady=12)
            txt.pack(side="left", fill="both", expand=True)
            sb.config(command=txt.yview)

            acc = accent_color.get()
            txt.tag_configure("tagline", foreground="#9aa0a6", font=("Segoe UI", 9, "italic"), spacing3=10)
            txt.tag_configure("h", foreground=acc, font=("Segoe UI", 11, "bold"), spacing1=12, spacing3=4)
            txt.tag_configure("body", foreground="#e0e0e0", font=("Segoe UI", 10), spacing3=4)
            txt.tag_configure("bullet", foreground="#cfcfcf", font=("Segoe UI", 10),
                              lmargin1=16, lmargin2=30, spacing3=3)
            txt.tag_configure("warn", foreground="#e67e22", font=("Segoe UI", 10),
                              lmargin1=16, lmargin2=30, spacing3=3)

            if doc.get("tagline"):
                txt.insert("end", doc["tagline"] + "\n", "tagline")

            def section(title, content, bullet_tag="bullet"):
                txt.insert("end", title + "\n", "h")
                if isinstance(content, list):
                    for item in content:
                        txt.insert("end", "•  " + item + "\n", bullet_tag)
                else:
                    txt.insert("end", (content or "-") + "\n", "body")

            section("Purpose", doc.get("purpose", ""))
            section("When to use it", doc.get("when", ""))
            section("How to use it", doc.get("how", ""))
            section("Capabilities", doc.get("capabilities", []))
            section("Caveats & cautions", doc.get("caveats", []), bullet_tag="warn")
            txt.config(state="disabled")

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

            # Per-tool "Use Case" info panel (purpose / when / how / caveats)
            usecase_btn = tk.Button(root, text="ℹ USE CASE", bg="#2c3e50", fg="#ffffff", bd=0,
                                    font=("Segoe UI", 8, "bold"), activebackground="#34495e",
                                    activeforeground="#ffffff", cursor="hand2",
                                    command=lambda tn=tool_name: show_tool_usecase(tn))
            usecase_btn_id = canvas.create_window(632, 25, window=usecase_btn, anchor="e")

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

            # --- Scan own machine (localhost) toggle ---
            # When checked, the scan runs against THIS machine (127.0.0.1)
            # regardless of what's typed above, and the target box is locked.
            scan_own_machine = tk.BooleanVar(value=False)
            _prev_tool_target = [persistent_target[0]]

            def toggle_scan_own_machine():
                if scan_own_machine.get():
                    _prev_tool_target[0] = tool_target_entry.get()
                    tool_target_entry.config(state="normal")
                    tool_target_entry.delete(0, tk.END)
                    tool_target_entry.insert(0, "127.0.0.1")
                    tool_target_entry.config(state="disabled")
                else:
                    tool_target_entry.config(state="normal")
                    tool_target_entry.delete(0, tk.END)
                    restore = "" if _prev_tool_target[0] == "127.0.0.1" else _prev_tool_target[0]
                    tool_target_entry.insert(0, restore)
                    persistent_target[0] = restore

            own_machine_frame = tk.Frame(root, bg="#1e1e1e")
            own_machine_cb = tk.Checkbutton(
                own_machine_frame, text="Scan own machine (localhost)",
                variable=scan_own_machine, command=toggle_scan_own_machine,
                bg="#1e1e1e", fg="#00ff00", selectcolor="#1e1e1e",
                activebackground="#1e1e1e", activeforeground="#00ff00",
                font=("Segoe UI", 8, "bold"), borderwidth=0, cursor="hand2")
            own_machine_cb.pack()
            own_machine_cb_id = canvas.create_window(212, 140, window=own_machine_frame, anchor="center")

            current_y = 168

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

                # (Export handled by the single "Export to Excel" button in the action row below.)
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
            # Tools whose scanner method ignores intensity - don't show the slider.
            is_no_intensity = any(x in tool_name for x in
                                  ["CVE Search", "WPScan-Lite", "Auditd", "Burp Suite",
                                   "Metasploit", "Rev Shell", "Web Fetch", "NSLookup"])
            
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
            elif is_dir_brute or is_firewall_audit or is_no_intensity:
                # These tools don't use scan intensity - no slider shown.
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
            centered_tool_items = [tool_title_id, results_id, progress_bar_id, target_label_id, target_window_id, own_machine_cb_id]

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

            # Tab 3: Command Preview / Audit trail
            cmd_tab = tk.Frame(notebook, bg="#1e1e1e")
            notebook.add(cmd_tab, text="  COMMAND PREVIEW  ")
            cmd_box = tk.Text(cmd_tab, bg="#000000", fg="#00ff00", font=("Consolas", 9), bd=0,
                              height=18, padx=10, pady=5, highlightthickness=0, wrap="word")
            cmd_box.tag_configure("hdr", foreground="#00ff00", font=("Consolas", 9, "bold"))
            cmd_box.tag_configure("plan", foreground="#f1c40f")
            cmb_vscroll = ttk.Scrollbar(cmd_tab, orient="vertical", style="Vertical.TScrollbar", command=cmd_box.yview)
            cmb_vscroll.pack(side="right", fill="y")
            cmd_box.pack(side="left", fill="both", expand=True)
            cmd_box.config(yscrollcommand=cmb_vscroll.set)

            def _preview_opts():
                opts = {}
                try: opts["intensity"] = int(intensity_scale.get())
                except Exception: opts["intensity"] = 3
                opts["scan_type"] = scan_type_var.get()
                opts["brute_type"] = brute_type_var.get()
                opts["audit_type"] = audit_type_var.get()
                opts["payload_list"] = payload_list_var.get()
                opts["command_template"] = custom_cmd_var.get()
                try:
                    opts["duration_seconds"] = (int(hours_var.get()) * 3600) + (int(mins_var.get()) * 60) or 300
                except Exception:
                    opts["duration_seconds"] = 300
                return opts

            def refresh_preview():
                try:
                    tgt = tool_target_entry.get() or "<target>"
                    planned = scanner.preview_command(tool_name, tgt, **_preview_opts())
                    cmd_box.config(state="normal")
                    cmd_box.delete("1.0", tk.END)
                    cmd_box.insert(tk.END, "Command that runs when you press Execute:\n\n", "hdr")
                    cmd_box.insert(tk.END, f"  $ {planned}\n\n", "plan")
                    if scanner.command_log:
                        cmd_box.insert(tk.END, "Commands executed (this session):\n", "hdr")
                        for e in scanner.command_log:
                            cmd_box.insert(tk.END, f"  [{e['time']}]  {e['command']}\n")
                    cmd_box.config(state="disabled")
                except Exception:
                    pass

            def on_command_recorded(entry):
                def _add():
                    try:
                        cmd_box.config(state="normal")
                        cmd_box.insert(tk.END, f"  [{entry['time']}]  {entry['command']}\n")
                        cmd_box.see(tk.END)
                        cmd_box.config(state="disabled")
                    except Exception:
                        pass
                root.after(0, _add)

            notebook.bind("<<NotebookTabChanged>>", lambda e: refresh_preview())
            refresh_preview()

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

            # (The Execute / Terminate controls are created in btn_frame below;
            #  the old duplicate "RUN SECURITY SCAN" control row was removed.)

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
                target = "127.0.0.1" if scan_own_machine.get() else tool_target_entry.get()
                intensity = int(intensity_scale.get())
                s_type = scan_type_var.get()
                b_type = brute_type_var.get() if is_dir_brute else None
                f_type = audit_type_var.get() if is_firewall_audit else None
                p_list = payload_list_var.get() if is_sql_tool else None
                c_tmpl = custom_cmd_var.get() if is_custom_cmd else None

                no_target_allowed = ["Win Audit", "WiFi Traffic Analyzer", "Security Camera Finder", "John The Ripper"]
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
                # Reset the command audit trail and stream new commands into the
                # Command Preview tab live as they run.
                scanner.clear_command_log()
                scanner.command_callback = on_command_recorded
                refresh_preview()

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

            # Per-tool "Use Case" info panel
            ddos_usecase_btn = tk.Button(root, text="ℹ USE CASE", bg="#2c3e50", fg="#ffffff", bd=0,
                                         font=("Segoe UI", 8, "bold"), activebackground="#34495e",
                                         activeforeground="#ffffff", cursor="hand2",
                                         command=lambda: show_tool_usecase("DDoS Tool"))
            canvas.create_window(632, 25, window=ddos_usecase_btn, anchor="e")

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
            
            # Mini Log + Command Preview (tabbed, for parity with the tool screens)
            ddos_nb = ttk.Notebook(results_frame, style="TNotebook")
            ddos_nb.pack(fill="both", expand=True, pady=10)

            log_container = tk.Frame(ddos_nb, bg="#1e1e1e")
            ddos_nb.add(log_container, text="  LIVE LOG  ")

            tool_log_box = tk.Text(log_container, bg="#000000", fg="#aaaaaa", font=("Consolas", 8), bd=0, height=12, width=85, padx=10, pady=5, highlightthickness=0, wrap="none")
            tool_log_box.pack(side="left", fill="both", expand=True)

            lb_vscroll = ttk.Scrollbar(log_container, orient="vertical", style="Vertical.TScrollbar", command=tool_log_box.yview)
            lb_vscroll.pack(side="right", fill="y")

            tool_log_box.config(yscrollcommand=lb_vscroll.set)
            tool_log_box.config(state="normal")
            tool_log_box.insert("1.0", "[*] DDoS Module Ready.\n[*] Caution: For authorized testing only.\n")
            tool_log_box.config(state="disabled")

            # Command Preview tab
            cmd_tab = tk.Frame(ddos_nb, bg="#1e1e1e")
            ddos_nb.add(cmd_tab, text="  COMMAND PREVIEW  ")
            cmd_box = tk.Text(cmd_tab, bg="#000000", fg="#00ff00", font=("Consolas", 9), bd=0, height=12, padx=10, pady=5, highlightthickness=0, wrap="word")
            cmd_box.tag_configure("hdr", foreground="#00ff00", font=("Consolas", 9, "bold"))
            cmd_box.tag_configure("plan", foreground="#f1c40f")
            cmb_vscroll = ttk.Scrollbar(cmd_tab, orient="vertical", style="Vertical.TScrollbar", command=cmd_box.yview)
            cmb_vscroll.pack(side="right", fill="y")
            cmd_box.pack(side="left", fill="both", expand=True)
            cmd_box.config(yscrollcommand=cmb_vscroll.set)

            def refresh_ddos_preview():
                try:
                    tgt = tool_target_entry.get() or "<target>"
                    try: thrd = int(threads_entry.get())
                    except Exception: thrd = 50
                    try: dur = int(duration_entry.get())
                    except Exception: dur = 10
                    planned = scanner.preview_command("DDoS Tool", tgt,
                                                      attack_type=attack_type_var.get(), threads=thrd, duration=dur)
                    cmd_box.config(state="normal")
                    cmd_box.delete("1.0", tk.END)
                    cmd_box.insert(tk.END, "Command that runs when you press Initialize Attack:\n\n", "hdr")
                    cmd_box.insert(tk.END, f"  $ {planned}\n\n", "plan")
                    if scanner.command_log:
                        cmd_box.insert(tk.END, "Commands executed (this session):\n", "hdr")
                        for e in scanner.command_log:
                            cmd_box.insert(tk.END, f"  [{e['time']}]  {e['command']}\n")
                    cmd_box.config(state="disabled")
                except Exception:
                    pass

            def on_ddos_command(entry):
                def _add():
                    try:
                        cmd_box.config(state="normal")
                        cmd_box.insert(tk.END, f"  [{entry['time']}]  {entry['command']}\n")
                        cmd_box.see(tk.END)
                        cmd_box.config(state="disabled")
                    except Exception:
                        pass
                root.after(0, _add)

            ddos_nb.bind("<<NotebookTabChanged>>", lambda e: refresh_ddos_preview())
            refresh_ddos_preview()

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
                scanner.clear_command_log()
                scanner.command_callback = on_ddos_command
                refresh_ddos_preview()

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
            analyzer = AIAnalyzer(model="claude-opus-5-5") # Admin gets the better model
            send_btn = None
            start_analysis_btn = None
            stop_btn = None
            is_stopping = [False]

            def stop_analysis():
                is_stopping[0] = True
                scanner_instance[0].terminate()
                append_to_chat("System", "Stopping all AI processes and commands...", "system")
                try:
                    ai_busy[0] = False
                    set_ai_status("stopping...", "#e74c3c")
                except Exception:
                    pass
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

            # Live status line so the operator always knows what the AI is doing
            # (thinking, running a tool, finished, stopped, or declined) - the model
            # can take a while and must never look frozen.
            ai_busy = [False]
            ai_status_lbl = tk.Label(header_frame, text="Status: idle", bg="#1e1e1e",
                                     fg="#888888", font=("Consolas", 9, "bold"))
            ai_status_lbl.pack()

            def set_ai_status(txt, color="#888888"):
                try:
                    ai_status_lbl.config(text=f"Status: {txt}", fg=color)
                except Exception:
                    pass

            def _heartbeat(start):
                if not ai_busy[0]:
                    return
                secs = int(time.time() - start)
                set_ai_status(f"AI is thinking... ({secs}s) - the model may take a while", "#f1c40f")
                root.after(1000, lambda: _heartbeat(start))

            def start_ai_busy(label="AI is thinking..."):
                ai_busy[0] = True
                set_ai_status(label, "#f1c40f")
                _heartbeat(time.time())

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
            admin_model_var = tk.StringVar(value="Claude Opus 5.5")
            admin_model_map = {
                "Claude Opus 5.5": "claude-opus-5-5",
                "Claude Sonnet 5.5": "claude-sonnet-5-5",
                "Claude Haiku 4.5": "claude-haiku-4-5",
                "Claude Opus 4.8": "claude-opus-4-8"
            }
            admin_model_opt = tk.OptionMenu(settings_frame, admin_model_var, *admin_model_map.keys())
            admin_model_opt.config(bg="#1e1e1e", fg="#ffffff", bd=0, highlightthickness=0, activebackground="#333333", font=("Segoe UI", 8))
            admin_model_opt["menu"].config(bg="#1e1e1e", fg="#ffffff", font=("Segoe UI", 8))
            admin_model_opt.pack(side="left", padx=5)

            def save_admin_key():
                if analyzer.save_api_key(admin_api_key_entry.get().strip()):
                    append_to_chat("System", "API key saved for future sessions.", "system")
                else:
                    append_to_chat("System", "Could not save API key (empty or write error).", "system")
            tk.Button(settings_frame, text="SAVE KEY", bg="#226622", fg="#ffffff", bd=0,
                      font=("Segoe UI", 7, "bold"), activebackground="#2a7a2a", cursor="hand2",
                      command=save_admin_key).pack(side="left", padx=5)

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
                set_ai_status(f"running tool: {cmd[:40]}", "#f1c40f")
                target = target_entry.get().strip()
                active_scanner = scanner_instance[0]
                
                def run_and_report():
                    output_lines = []
                    def temp_log(msg, is_err=False):
                        output_lines.append(msg)
                    
                    orig_log = active_scanner.log_callback
                    active_scanner.log_callback = temp_log
                    
                    try:
                        # Prefer a native Layer8 tool if the AI named one (e.g.
                        # "port_scan", "nikto", "win_audit"); otherwise run it as a
                        # command-line tool via custom_command. (DDoS is not exposed
                        # to ai_run_tool, so the AI cannot auto-launch it.)
                        first_tok = cmd.split()[0].lower() if cmd.split() else ""
                        if not active_scanner.ai_run_tool(first_tok, target):
                            active_scanner.custom_command(target, cmd)
                        full_output = "".join(output_lines)
                        
                        def back_to_ai():
                            if is_stopping[0]: return
                            append_to_chat("System", "Command execution complete.", "system")
                            set_ai_status("tool finished", "#2ecc71")
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
                ai_busy[0] = False
                if is_stopping[0]:
                    is_stopping[0] = False
                    set_ai_status("stopped by user", "#e74c3c")
                    return

                # Re-enable UI
                try:
                    send_btn.config(state="normal")
                    start_analysis_btn.config(state="normal")
                    stop_btn.config(state="disabled", text="STOP ANALYSIS")
                except: pass

                # Reflect the outcome in the status line (declined / empty / error / ok)
                r_strip = (response or "").lstrip()
                declined = r_strip.startswith(("[AI DECLINED", "[AI returned no content", "[!]"))
                if r_strip.startswith("[AI DECLINED"):
                    set_ai_status("AI declined this request (see message)", "#e74c3c")
                elif r_strip.startswith("[AI returned no content") or r_strip.startswith("[!]"):
                    set_ai_status("AI stopped without a full answer (see message)", "#e74c3c")
                else:
                    set_ai_status("AI responded", "#2ecc71")

                append_to_chat("Assistant", response, "ai")
                chat_history.append({"role": "assistant", "content": response})

                # Look for EXECUTE: command
                ran_cmd = False
                for line in response.split("\n"):
                    if line.strip().startswith("EXECUTE:"):
                        cmd = line.replace("EXECUTE:", "").strip()
                        if cmd:
                            ran_cmd = True
                            if autonomous_var.get():
                                set_ai_status(f"running tool: {cmd[:40]}", "#f1c40f")
                                append_to_chat("System", f"Autonomous execution: {cmd}", "system")
                                execute_autonomous_cmd(cmd)
                            else:
                                if messagebox.askyesno("Autonomous Execution", f"The AI wants to execute the following command:\n\n{cmd}\n\nDo you want to allow this?"):
                                    set_ai_status(f"running tool: {cmd[:40]}", "#f1c40f")
                                    execute_autonomous_cmd(cmd)
                                else:
                                    append_to_chat("System", f"Execution of '{cmd}' was cancelled by user.", "system")
                                    set_ai_status("tool execution cancelled - awaiting your input", "#888888")
                if not ran_cmd and not declined:
                    set_ai_status("AI finished - awaiting your input", "#2ecc71")

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
                analyzer.model = admin_model_map.get(selected_model_name, "claude-opus-5-5")
                
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

                start_ai_busy("AI is thinking (contacting the model)...")

                def thread_func():
                    try:
                        response = analyzer.admin_chat(target, active_scanner.all_findings, message, history_snapshot)
                    except Exception as e:
                        response = f"[!] AI request failed: {e}"
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
            
            def save_report():
                append_to_chat("System", "Generating report from this session's findings...", "system")
                def worker():
                    tgt = target_entry.get().strip()
                    sc = scanner_instance[0]
                    transcript = res_text.get("1.0", tk.END)
                    rep = analyzer.generate_report(tgt, sc.all_findings, sc.history, transcript)
                    def save_it():
                        from tkinter import filedialog
                        fpath = filedialog.asksaveasfilename(
                            defaultextension=".md",
                            filetypes=[("Markdown", "*.md"), ("Text", "*.txt"), ("All", "*.*")],
                            initialfile=f"Layer8_Report_{(tgt or 'session').replace('.', '_')}.md")
                        if fpath:
                            try:
                                with open(fpath, "w", encoding="utf-8") as f:
                                    f.write(rep)
                                append_to_chat("System", f"Report saved: {fpath}", "system")
                            except Exception as e:
                                append_to_chat("System", f"Save failed: {e}", "system")
                        else:
                            append_to_chat("Assistant", rep, "ai")
                    root.after(0, save_it)
                threading.Thread(target=worker, daemon=True).start()
            tk.Button(btn_frame, text="SAVE REPORT", bg="#8e44ad", fg="#ffffff", font=("Segoe UI", 9, "bold"), bd=0, padx=20, pady=8, activebackground="#9b59b6", cursor="hand2", command=save_report).pack(side="left", padx=10)

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
            model_var = tk.StringVar(value="Claude Opus 5.5")
            model_map = {
                "Claude Opus 5.5": "claude-opus-5-5",
                "Claude Sonnet 5.5": "claude-sonnet-5-5",
                "Claude Haiku 4.5": "claude-haiku-4-5",
                "Claude Opus 4.8": "claude-opus-4-8",
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
            current_width = 1180
            
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

            # ---- Header: WELCOME + status on the left, target + controls top-right ----
            canvas.itemconfig(welcome_id, anchor="w")
            canvas.coords(welcome_id, 20, 34)
            canvas.itemconfig(status_text, anchor="w")
            canvas.coords(status_text, 20, 64)
            canvas.itemconfig(target_label_id, anchor="e")
            canvas.coords(target_label_id, current_width - 20, 26)
            canvas.itemconfig(target_window_id, anchor="e")
            canvas.coords(target_window_id, current_width - 20, 54)

            # Control buttons row (top-right)
            hdr_btns = tk.Frame(root, bg=bg_color.get())
            view_btn = tk.Button(hdr_btns, text="VIEW: " + view_mode[0].upper(), bg="#1e1e1e", fg="#aaaaaa",
                                 activebackground="#333333", activeforeground=accent_color.get(), bd=0,
                                 font=("Segoe UI", 8, "bold"), padx=8, pady=4, command=toggle_view_mode, cursor="hand2")
            view_btn.pack(side="left", padx=(6, 0))
            ai_btn = tk.Button(hdr_btns, text="AI FEEDBACK", bg="#1e1e1e", fg="#00ff00",
                               activebackground="#333333", activeforeground="#00ff00", bd=0,
                               font=("Segoe UI", 8, "bold"), padx=8, pady=4, command=show_ai_feedback_screen, cursor="hand2")
            ai_btn.pack(side="left", padx=(6, 0))
            # Agentic AI operator (runs tools + writes reports) - available to all
            # users with their own API key.
            operator_ai_btn = tk.Button(hdr_btns, text="AI OPERATOR", bg="#1e1e1e", fg="#e67e22",
                                        activebackground="#333333", activeforeground="#e67e22", bd=0,
                                        font=("Segoe UI", 8, "bold"), padx=8, pady=4, command=show_admin_ai_analyst, cursor="hand2")
            operator_ai_btn.pack(side="left", padx=(6, 0))
            if is_admin:
                admin_btn_placeholder = None
                admin_btn = tk.Button(hdr_btns, text="ADMIN PANEL", bg="#1e1e1e", fg="#f1c40f",
                                      activebackground="#333333", activeforeground="#f1c40f", bd=0,
                                      font=("Segoe UI", 8, "bold"), padx=8, pady=4, command=show_admin_panel, cursor="hand2")
                admin_btn.pack(side="left", padx=(6, 0))
            tool_items.append(canvas.create_window(current_width - 20, 90, window=hdr_btns, anchor="e"))

            # --- Theme Selector (top-right, under the controls) ---
            def set_theme(color_hex):
                accent_color.set(color_hex)
                style.configure("Horizontal.TProgressbar", background=color_hex)
                style.configure("Vertical.TScrollbar", arrowcolor=color_hex)
                style.map("TNotebook.Tab", foreground=[('selected', color_hex)])
                render_menu()

            theme_frame = tk.Frame(root, bg=bg_color.get())
            tk.Label(theme_frame, text="THEME", bg=bg_color.get(), fg="#666666", font=("Segoe UI", 7, "bold")).pack(side="left", padx=(0, 4))
            for color, name in [("#00ff00", "Green"), ("#3498db", "Blue"), ("#e74c3c", "Red"), ("#f1c40f", "Gold"), ("#9b59b6", "Purple")]:
                tk.Button(theme_frame, bg=color, width=2, height=1, bd=0, command=lambda c=color: set_theme(c), cursor="hand2").pack(side="left", padx=2)
            tool_items.append(canvas.create_window(current_width - 20, 116, window=theme_frame, anchor="e"))

            # ================================================================
            # Tool grid - card-based layout.
            # Design principles applied from frontend practice:
            #  - Design tokens: one small palette instead of scattered hex
            #  - 8pt spacing rhythm for consistent gaps/padding
            #  - Card containers per category + accent bar = clear hierarchy
            #  - Uniform 3-column grid so columns actually align
            #  - Full labels (no clipping) with hover affordance
            # ================================================================
            GUTTER = 20
            COLGAP = 16
            CARD_W = current_width - (GUTTER * 2)          # full width (All Tools view)
            COLW = (current_width - GUTTER * 2 - COLGAP) // 2   # per-column width (2-col view)
            COLS = 3
            CARD_GAP = 12
            CARD_BG = "#16181c"
            CARD_BORDER = "#262b31"
            BTN_BG = "#1c1f24"
            BTN_HOVER = "#242a31"
            TXT = "#e8eaed"

            # Remove the large center shield watermark on the dense dashboard;
            # the title bar already carries the brand. (Kept on the login screen.)
            if bg_image_id is not None:
                try:
                    canvas.itemconfigure(bg_image_id, state="hidden")
                except Exception:
                    pass

            # Shorter display labels for a few long names so nothing clips.
            # The underlying tool_name (used for logic/help) is unchanged.
            SHORT = {
                "WiFi Traffic Analyzer": "WiFi Analyzer",
                "Security Camera Finder": "Camera Finder",
                "Packet Interceptor": "Packet Intercept",
            }

            def make_tool_button(parent, tool_name, tool_cmd):
                display = SHORT.get(tool_name, tool_name)
                btn = tk.Button(parent, text=display, bg=BTN_BG, fg=TXT,
                                activebackground=BTN_HOVER, activeforeground=accent_color.get(),
                                bd=0, relief="flat", font=("Segoe UI", 9), cursor="hand2",
                                padx=8, pady=7, wraplength=150,
                                highlightthickness=1, highlightbackground=CARD_BORDER,
                                highlightcolor=CARD_BORDER)

                def on_enter(e, name=tool_name):
                    btn.config(bg=BTN_HOVER, fg=accent_color.get())
                    canvas.itemconfig(status_text, text=tool_help.get(name, ""), fill=accent_color.get())

                def on_leave(e):
                    btn.config(bg=BTN_BG, fg=TXT)
                    canvas.itemconfig(status_text, text="", fill=fg_color)

                btn.bind("<Enter>", on_enter)
                btn.bind("<Leave>", on_leave)

                def on_tool_click(cmd=tool_cmd, name=tool_name):
                    if name == "DDoS Tool":
                        show_ddos_screen(scanner)
                    else:
                        cmd()
                    canvas.itemconfig(status_text, text=tool_help.get(name, ""), fill="#aaaaaa")
                    canvas.coords(status_text, 212, 20)

                btn.configure(command=on_tool_click)
                return btn

            def build_grid(parent, tools):
                grid = tk.Frame(parent, bg=CARD_BG)
                for c in range(COLS):
                    grid.grid_columnconfigure(c, weight=1, uniform="tools")
                for idx, (tool_name, tool_cmd) in enumerate(tools):
                    r, c = divmod(idx, COLS)
                    make_tool_button(grid, tool_name, tool_cmd).grid(
                        row=r, column=c, sticky="nsew", padx=4, pady=4)
                return grid

            def build_card(category, tools):
                card = tk.Frame(root, bg=CARD_BG, highlightthickness=1,
                                highlightbackground=CARD_BORDER, highlightcolor=CARD_BORDER)
                inner = tk.Frame(card, bg=CARD_BG)
                inner.pack(fill="both", expand=True, padx=12, pady=(10, 12))

                header = tk.Frame(inner, bg=CARD_BG)
                header.pack(fill="x", pady=(0, 8))
                bar = tk.Frame(header, bg=accent_color.get(), width=3, height=14)
                bar.pack(side="left", padx=(0, 8))
                bar.pack_propagate(False)
                lbl = tk.Label(header, text=category.upper(), font=("Segoe UI", 9, "bold"),
                               bg=CARD_BG, fg=accent_color.get())
                lbl.pack(side="left")

                def on_h_enter(e, c=category):
                    canvas.itemconfig(status_text, text=tool_descriptions.get(c, ""), fill=accent_color.get())

                def on_h_leave(e):
                    canvas.itemconfig(status_text, text="", fill=fg_color)

                for w in (header, lbl, bar):
                    w.bind("<Enter>", on_h_enter)
                    w.bind("<Leave>", on_h_leave)

                build_grid(inner, tools).pack(fill="x")
                return card

            start_y = 150
            left_bottom = start_y

            if view_mode[0] == "Categorized":
                # Split categories into two balanced columns (order preserved
                # within each column) so the dashboard is wide, not tall.
                def _rows(t):
                    return (len(t) + COLS - 1) // COLS

                left_cats, right_cats, lh, rh = [], [], 0, 0
                for category, tools in tool_categories.items():
                    if lh <= rh:
                        left_cats.append((category, tools)); lh += _rows(tools)
                    else:
                        right_cats.append((category, tools)); rh += _rows(tools)

                col_bottoms = []
                for col_x, col in ((GUTTER, left_cats), (GUTTER + COLW + COLGAP, right_cats)):
                    y = start_y
                    for category, tools in col:
                        card = build_card(category, tools)
                        win = canvas.create_window(col_x, y, window=card, anchor="nw", width=COLW)
                        tool_items.append(win)
                        root.update_idletasks()
                        bbox = canvas.bbox(win)
                        y = (bbox[3] if bbox else y + 90) + CARD_GAP
                    col_bottoms.append(y)
                left_bottom = col_bottoms[0] if col_bottoms else start_y
            else:
                # All Tools View - single full-width card, alphabetized
                all_tools = []
                for cat_tools in tool_categories.values():
                    all_tools.extend(cat_tools)
                all_tools.sort(key=lambda x: x[0])

                card = tk.Frame(root, bg=CARD_BG, highlightthickness=1,
                                highlightbackground=CARD_BORDER, highlightcolor=CARD_BORDER)
                inner = tk.Frame(card, bg=CARD_BG)
                inner.pack(fill="both", expand=True, padx=12, pady=12)
                build_grid(inner, all_tools).pack(fill="x")
                win = canvas.create_window(GUTTER, start_y, window=card, anchor="nw", width=CARD_W)
                tool_items.append(win)
                root.update_idletasks()
                bbox = canvas.bbox(win)
                left_bottom = (bbox[3] if bbox else start_y + 300) + CARD_GAP

            root.update_idletasks()

            # Activity log tucked into the bottom-left, under the (shorter) left column.
            last_y = left_bottom + 6
            canvas.itemconfig(log_label_id, anchor="w")
            canvas.coords(log_label_id, GUTTER, last_y)
            canvas.itemconfig(summary_id, anchor="nw")
            canvas.coords(summary_id, GUTTER, last_y + 22)

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
            
            update_window_size(width=current_width, centered_items=[])

        # Initialize menu view
        render_menu()

    def on_login_success(is_admin, username):
        logger.info(f"Login success for {username}. Showing main menu.")
        apply_overrideredirect()
        root.deiconify()
        show_main_menu(username, is_admin, db_available=db_available)
        # Force a resize update (wide dashboard)
        update_window_size(width=1180, centered_items=[])

    # Initially hide the main root window
    root.withdraw()

    # Show login window
    login = LoginWindow(root, on_login_success, db_available=db_available)
    login.show_login()

    # Start the event loop
    logger.info("Starting mainloop...")
    root.mainloop()
    logger.info("Mainloop exited.")

if __name__ == "__main__":
    main()
