"""
Modern Dark Theme Module for Layer8 Security Platform
Provides consistent styling, colors, and UI components
"""

import tkinter as tk
from tkinter import ttk

class ModernTheme:
    """Modern dark theme color palette and styling utilities"""

    # Color Palette - Refined dark theme
    COLORS = {
        # Backgrounds
        'bg_primary': '#0f0f0f',        # Deep black background
        'bg_secondary': '#1a1a1a',      # Card/container background
        'bg_tertiary': '#242424',       # Hover state background
        'bg_input': '#1e1e1e',          # Input field background

        # Foregrounds
        'fg_primary': '#e8e8e8',        # Primary text
        'fg_secondary': '#9ca3af',      # Secondary text
        'fg_tertiary': '#6b7280',       # Disabled/muted text

        # Accents
        'accent_primary': '#00ff88',    # Primary accent (neon green)
        'accent_hover': '#00cc6a',      # Hover state
        'accent_pressed': '#00aa55',    # Pressed state

        # Status colors
        'success': '#10b981',           # Success green
        'warning': '#f59e0b',           # Warning orange
        'error': '#ef4444',             # Error red
        'info': '#3b82f6',              # Info blue

        # Borders & Dividers
        'border_light': '#2d2d2d',
        'border_dark': '#1a1a1a',

        # Special
        'overlay': 'rgba(0, 0, 0, 0.5)',
        'glass': '#1a1a1acc',           # Semi-transparent glass effect
    }

    # Typography
    FONTS = {
        'title': ('Segoe UI', 24, 'bold'),
        'heading': ('Segoe UI', 18, 'bold'),
        'subheading': ('Segoe UI', 14, 'bold'),
        'body': ('Segoe UI', 11),
        'body_bold': ('Segoe UI', 11, 'bold'),
        'small': ('Segoe UI', 9),
        'tiny': ('Segoe UI', 8),
        'mono': ('Consolas', 10),
        'mono_small': ('Consolas', 9),
    }

    # Spacing
    SPACING = {
        'xs': 4,
        'sm': 8,
        'md': 16,
        'lg': 24,
        'xl': 32,
        'xxl': 48,
    }

    # Border Radius (simulated with relief styles)
    RADIUS = {
        'sm': 4,
        'md': 8,
        'lg': 12,
        'xl': 16,
        'full': 999,
    }

    @staticmethod
    def apply_ttk_style(style=None):
        """Apply modern theme to TTK widgets"""
        if style is None:
            style = ttk.Style()

        style.theme_use('clam')

        # Configure Treeview
        style.configure("Modern.Treeview",
            background=ModernTheme.COLORS['bg_secondary'],
            foreground=ModernTheme.COLORS['fg_primary'],
            fieldbackground=ModernTheme.COLORS['bg_secondary'],
            borderwidth=0,
            font=ModernTheme.FONTS['body'],
            rowheight=32
        )
        style.map("Modern.Treeview",
            background=[('selected', ModernTheme.COLORS['bg_tertiary'])],
            foreground=[('selected', ModernTheme.COLORS['accent_primary'])]
        )
        style.configure("Modern.Treeview.Heading",
            background=ModernTheme.COLORS['bg_primary'],
            foreground=ModernTheme.COLORS['accent_primary'],
            relief="flat",
            font=ModernTheme.FONTS['body_bold']
        )

        # Configure Notebook (Tabs)
        style.configure("Modern.TNotebook",
            background=ModernTheme.COLORS['bg_primary'],
            borderwidth=0,
            tabmargins=[2, 5, 2, 0]
        )
        style.configure("Modern.TNotebook.Tab",
            background=ModernTheme.COLORS['bg_secondary'],
            foreground=ModernTheme.COLORS['fg_secondary'],
            padding=[20, 12],
            font=ModernTheme.FONTS['body_bold'],
            borderwidth=0
        )
        style.map("Modern.TNotebook.Tab",
            background=[('selected', ModernTheme.COLORS['bg_primary'])],
            foreground=[('selected', ModernTheme.COLORS['accent_primary'])],
            expand=[('selected', [1, 1, 1, 0])]
        )

        # Configure Progressbar
        style.configure("Modern.Horizontal.TProgressbar",
            thickness=8,
            troughcolor=ModernTheme.COLORS['bg_secondary'],
            background=ModernTheme.COLORS['accent_primary'],
            borderwidth=0
        )

        # Configure Scrollbar
        style.configure("Modern.Vertical.TScrollbar",
            gripcount=0,
            background=ModernTheme.COLORS['bg_tertiary'],
            darkcolor=ModernTheme.COLORS['bg_secondary'],
            lightcolor=ModernTheme.COLORS['bg_secondary'],
            troughcolor=ModernTheme.COLORS['bg_secondary'],
            bordercolor=ModernTheme.COLORS['bg_secondary'],
            arrowcolor=ModernTheme.COLORS['accent_primary']
        )

        return style


class ModernButton(tk.Button):
    """Modern styled button with hover effects"""

    def __init__(self, parent, text="", variant="primary", **kwargs):
        """
        Create modern button

        Args:
            parent: Parent widget
            text: Button text
            variant: 'primary', 'secondary', 'success', 'danger', 'ghost'
            **kwargs: Additional button parameters
        """
        self.variant = variant

        # Get colors based on variant
        colors = self._get_variant_colors(variant)

        # Default styling
        default_config = {
            'text': text,
            'font': ModernTheme.FONTS['body_bold'],
            'bg': colors['bg'],
            'fg': colors['fg'],
            'activebackground': colors['hover'],
            'activeforeground': colors['fg'],
            'relief': tk.FLAT,
            'bd': 0,
            'cursor': 'hand2',
            'padx': ModernTheme.SPACING['lg'],
            'pady': ModernTheme.SPACING['md'],
        }

        # Override with user kwargs
        default_config.update(kwargs)

        super().__init__(parent, **default_config)

        # Bind hover events for smooth transitions
        self.bind('<Enter>', self._on_hover)
        self.bind('<Leave>', self._on_leave)

        self.default_bg = colors['bg']
        self.hover_bg = colors['hover']

    def _get_variant_colors(self, variant):
        """Get colors for button variant"""
        theme = ModernTheme.COLORS

        variants = {
            'primary': {
                'bg': theme['accent_primary'],
                'fg': theme['bg_primary'],
                'hover': theme['accent_hover'],
            },
            'secondary': {
                'bg': theme['bg_secondary'],
                'fg': theme['fg_primary'],
                'hover': theme['bg_tertiary'],
            },
            'success': {
                'bg': theme['success'],
                'fg': '#ffffff',
                'hover': '#059669',
            },
            'danger': {
                'bg': theme['error'],
                'fg': '#ffffff',
                'hover': '#dc2626',
            },
            'ghost': {
                'bg': theme['bg_secondary'],
                'fg': theme['fg_secondary'],
                'hover': theme['bg_tertiary'],
            },
        }

        return variants.get(variant, variants['primary'])

    def _on_hover(self, event):
        """Handle hover state"""
        if self['state'] != tk.DISABLED:
            self.config(bg=self.hover_bg)

    def _on_leave(self, event):
        """Handle leave state"""
        if self['state'] != tk.DISABLED:
            self.config(bg=self.default_bg)


class ModernEntry(tk.Entry):
    """Modern styled entry field with focus effects"""

    def __init__(self, parent, placeholder="", **kwargs):
        """
        Create modern entry field

        Args:
            parent: Parent widget
            placeholder: Placeholder text
            **kwargs: Additional entry parameters
        """
        self.placeholder = placeholder
        self.placeholder_active = False

        # Default styling
        default_config = {
            'font': ModernTheme.FONTS['body'],
            'bg': ModernTheme.COLORS['bg_input'],
            'fg': ModernTheme.COLORS['fg_primary'],
            'insertbackground': ModernTheme.COLORS['accent_primary'],
            'relief': tk.FLAT,
            'bd': 0,
            'highlightthickness': 2,
            'highlightcolor': ModernTheme.COLORS['accent_primary'],
            'highlightbackground': ModernTheme.COLORS['border_light'],
        }

        default_config.update(kwargs)
        super().__init__(parent, **default_config)

        # Add placeholder functionality
        if placeholder:
            self._show_placeholder()
            self.bind('<FocusIn>', self._on_focus_in)
            self.bind('<FocusOut>', self._on_focus_out)

    def _show_placeholder(self):
        """Show placeholder text"""
        self.placeholder_active = True
        self.insert(0, self.placeholder)
        self.config(fg=ModernTheme.COLORS['fg_tertiary'])

    def _hide_placeholder(self):
        """Hide placeholder text"""
        if self.placeholder_active:
            self.delete(0, tk.END)
            self.config(fg=ModernTheme.COLORS['fg_primary'])
            self.placeholder_active = False

    def _on_focus_in(self, event):
        """Handle focus in"""
        self._hide_placeholder()

    def _on_focus_out(self, event):
        """Handle focus out"""
        if not self.get():
            self._show_placeholder()

    def get_value(self):
        """Get actual value (not placeholder)"""
        if self.placeholder_active:
            return ""
        return self.get()


class ModernLabel(tk.Label):
    """Modern styled label"""

    def __init__(self, parent, text="", variant="body", **kwargs):
        """
        Create modern label

        Args:
            parent: Parent widget
            text: Label text
            variant: 'title', 'heading', 'subheading', 'body', 'small', 'tiny'
            **kwargs: Additional label parameters
        """
        # Get font based on variant
        font_map = {
            'title': ModernTheme.FONTS['title'],
            'heading': ModernTheme.FONTS['heading'],
            'subheading': ModernTheme.FONTS['subheading'],
            'body': ModernTheme.FONTS['body'],
            'body_bold': ModernTheme.FONTS['body_bold'],
            'small': ModernTheme.FONTS['small'],
            'tiny': ModernTheme.FONTS['tiny'],
        }

        default_config = {
            'text': text,
            'font': font_map.get(variant, ModernTheme.FONTS['body']),
            'bg': ModernTheme.COLORS['bg_primary'],
            'fg': ModernTheme.COLORS['fg_primary'],
        }

        default_config.update(kwargs)
        super().__init__(parent, **default_config)


class ModernFrame(tk.Frame):
    """Modern styled frame (card-like container)"""

    def __init__(self, parent, **kwargs):
        """
        Create modern frame

        Args:
            parent: Parent widget
            **kwargs: Additional frame parameters
        """
        default_config = {
            'bg': ModernTheme.COLORS['bg_secondary'],
            'bd': 0,
            'relief': tk.FLAT,
            'highlightthickness': 1,
            'highlightbackground': ModernTheme.COLORS['border_light'],
        }

        default_config.update(kwargs)
        super().__init__(parent, **default_config)


def create_tooltip(widget, text):
    """
    Create a modern tooltip for a widget

    Args:
        widget: Widget to attach tooltip to
        text: Tooltip text
    """
    tooltip = None

    def show_tooltip(event):
        nonlocal tooltip
        if tooltip:
            return

        x = event.x_root + 15
        y = event.y_root + 10

        tooltip = tk.Toplevel()
        tooltip.wm_overrideredirect(True)
        tooltip.wm_geometry(f"+{x}+{y}")

        label = tk.Label(
            tooltip,
            text=text,
            font=ModernTheme.FONTS['small'],
            bg=ModernTheme.COLORS['bg_tertiary'],
            fg=ModernTheme.COLORS['fg_primary'],
            relief=tk.FLAT,
            padx=ModernTheme.SPACING['sm'],
            pady=ModernTheme.SPACING['xs'],
            borderwidth=1,
            highlightthickness=1,
            highlightbackground=ModernTheme.COLORS['border_light']
        )
        label.pack()

    def hide_tooltip(event):
        nonlocal tooltip
        if tooltip:
            tooltip.destroy()
            tooltip = None

    widget.bind('<Enter>', show_tooltip)
    widget.bind('<Leave>', hide_tooltip)


def animate_fade_in(widget, duration=300, steps=10):
    """
    Fade in animation for widget (simulated with alpha)
    Note: Tkinter doesn't support true transparency, this is a workaround

    Args:
        widget: Widget to animate
        duration: Animation duration in ms
        steps: Number of animation steps
    """
    # Simple visibility animation
    widget.lift()


def create_separator(parent, orient='horizontal'):
    """
    Create a modern separator line

    Args:
        parent: Parent widget
        orient: 'horizontal' or 'vertical'
    """
    if orient == 'horizontal':
        sep = tk.Frame(
            parent,
            height=1,
            bg=ModernTheme.COLORS['border_light'],
            bd=0
        )
        sep.pack(fill='x', pady=ModernTheme.SPACING['md'])
    else:
        sep = tk.Frame(
            parent,
            width=1,
            bg=ModernTheme.COLORS['border_light'],
            bd=0
        )
        sep.pack(fill='y', padx=ModernTheme.SPACING['md'])

    return sep
