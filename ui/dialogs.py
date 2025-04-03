"""
NetworkX - Dialog Windows Module
Dialog windows for the NetworkX application
"""

import tkinter as tk
from tkinter import ttk, scrolledtext

from core.constants import APP_NAME, APP_VERSION, APP_DESCRIPTION, APP_FEATURES


class FilterHelperDialog:
    """Dialog to help build BPF filters"""
    
    def __init__(self, parent, current_filter=""):
        """
        Initialize the filter helper dialog
        
        Args:
            parent: Parent window
            current_filter: Current filter string
        """
        self.parent = parent
        self.result = current_filter
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Filter Helper")
        self.dialog.geometry("500x400")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Main frame
        main_frame = ttk.Frame(self.dialog, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Current filter
        ttk.Label(main_frame, text="Current Filter:").pack(anchor=tk.W)
        self.filter_var = tk.StringVar(value=current_filter)
        filter_entry = ttk.Entry(main_frame, textvariable=self.filter_var, width=50)
        filter_entry.pack(fill=tk.X, pady=(0, 10))
        
        # Quick filter buttons
        quick_frame = ttk.LabelFrame(main_frame, text="Quick Filters")
        quick_frame.pack(fill=tk.X, pady=5)
        
        # Protocol filters
        proto_frame = ttk.Frame(quick_frame)
        proto_frame.pack(fill=tk.X, pady=5)
        
        for i, proto in enumerate(["tcp", "udp", "icmp", "arp"]):
            btn = ttk.Button(proto_frame, text=proto.upper(), 
                            command=lambda p=proto: self.add_filter_part(p))
            btn.grid(row=0, column=i, padx=5, pady=5)
        
        # Common services
        services_frame = ttk.Frame(quick_frame)
        services_frame.pack(fill=tk.X, pady=5)
        
        common_services = [
            ("HTTP", "tcp port 80"), 
            ("HTTPS", "tcp port 443"), 
            ("DNS", "udp port 53"), 
            ("SSH", "tcp port 22")
        ]
        
        for i, (name, filter_expr) in enumerate(common_services):
            btn = ttk.Button(services_frame, text=name, 
                            command=lambda f=filter_expr: self.add_filter_part(f))
            btn.grid(row=0, column=i, padx=5, pady=5)
        
        # Host & port options
        host_port_frame = ttk.Frame(quick_frame)
        host_port_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(host_port_frame, text="Host:").grid(row=0, column=0, padx=5)
        self.host_var = tk.StringVar()
        host_entry = ttk.Entry(host_port_frame, textvariable=self.host_var, width=15)
        host_entry.grid(row=0, column=1, padx=5)
        
        ttk.Button(host_port_frame, text="src host", 
                  command=lambda: self.add_host_filter("src")).grid(row=0, column=2, padx=5)
        ttk.Button(host_port_frame, text="dst host", 
                  command=lambda: self.add_host_filter("dst")).grid(row=0, column=3, padx=5)
        
        ttk.Label(host_port_frame, text="Port:").grid(row=1, column=0, padx=5, pady=5)
        self.port_var = tk.StringVar()
        port_entry = ttk.Entry(host_port_frame, textvariable=self.port_var, width=15)
        port_entry.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Button(host_port_frame, text="src port", 
                  command=lambda: self.add_port_filter("src")).grid(row=1, column=2, padx=5)
        ttk.Button(host_port_frame, text="dst port", 
                  command=lambda: self.add_port_filter("dst")).grid(row=1, column=3, padx=5)
        
        # Logical operators
        operators_frame = ttk.Frame(quick_frame)
        operators_frame.pack(fill=tk.X, pady=5)
        
        for i, op in enumerate(["and", "or", "not"]):
            btn = ttk.Button(operators_frame, text=op.upper(), 
                           command=lambda o=op: self.add_filter_part(f" {o} "))
            btn.grid(row=0, column=i, padx=5, pady=5)
            
        # Help text
        help_frame = ttk.LabelFrame(main_frame, text="Filter Examples")
        help_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        help_text = scrolledtext.ScrolledText(help_frame, wrap=tk.WORD, height=6)
        help_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        help_examples = """
- tcp port 80 or tcp port 443: HTTP or HTTPS traffic
- host 192.168.1.1: Traffic to/from specific IP
- icmp: Only ICMP packets (ping)
- arp: Only ARP packets
- tcp port 80 and host 192.168.1.1: HTTP to/from specific host
- not arp: Exclude ARP packets
- src net 192.168.1.0/24: From specific subnet
        """
        help_text.insert(tk.END, help_examples)
        help_text.configure(state="disabled")
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(button_frame, text="Clear", command=lambda: self.filter_var.set("")).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.dialog.destroy).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Apply", command=self.apply_filter).pack(side=tk.RIGHT, padx=5)
        
        self.dialog.wait_window()
    
    def add_filter_part(self, part):
        """
        Add a part to the filter
        
        Args:
            part: Filter part to add
        """
        current = self.filter_var.get().strip()
        if current and not (current.endswith(" ") or part.startswith(" ")):
            current += " "
        self.filter_var.set(current + part)
    
    def add_host_filter(self, direction):
        """
        Add a host filter
        
        Args:
            direction: Direction ('src' or 'dst')
        """
        host = self.host_var.get().strip()
        if host:
            self.add_filter_part(f"{direction} host {host}")
    
    def add_port_filter(self, direction):
        """
        Add a port filter
        
        Args:
            direction: Direction ('src' or 'dst')
        """
        port = self.port_var.get().strip()
        if port:
            self.add_filter_part(f"{direction} port {port}")
    
    def apply_filter(self):
        """Apply the filter and return it"""
        self.result = self.filter_var.get().strip()
        self.dialog.destroy()
    
    def get_result(self):
        """
        Get the result after dialog closure
        
        Returns:
            str: Filter string
        """
        return self.result


class AboutDialog:
    """About dialog window"""
    
    def __init__(self, parent):
        """
        Initialize the about dialog
        
        Args:
            parent: Parent window
        """
        self.parent = parent
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("About " + APP_NAME)
        self.dialog.geometry("400x300")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Center on parent window
        x = parent.winfo_x() + (parent.winfo_width() // 2) - 200
        y = parent.winfo_y() + (parent.winfo_height() // 2) - 150
        self.dialog.geometry(f"+{x}+{y}")
        
        # Main frame
        main_frame = ttk.Frame(self.dialog, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # App title
        title_label = ttk.Label(main_frame, text=APP_NAME, 
                              font=("Helvetica", 16, "bold"))
        title_label.pack(pady=(0, 10))
        
        # Version
        version_label = ttk.Label(main_frame, text=f"Version {APP_VERSION}")
        version_label.pack()
        
        # Description
        desc_label = ttk.Label(main_frame, text=APP_DESCRIPTION, 
                             wraplength=350, justify="center")
        desc_label.pack(pady=20)
        
        # Features
        features_text = "Features:\n" + "\n".join(f"• {feature}" for feature in APP_FEATURES)
        features_label = ttk.Label(main_frame, text=features_text, justify="left")
        features_label.pack(pady=10)
        
        # Library credits
        credits_label = ttk.Label(main_frame, text="Built with Python, Tkinter, and Scapy")
        credits_label.pack(pady=10)
        
        # Close button
        close_button = ttk.Button(main_frame, text="Close", command=self.dialog.destroy)
        close_button.pack(pady=10)


class ProgressDialog:
    """Progress dialog window"""
    
    def __init__(self, parent, title="Progress", message="Please wait..."):
        """
        Initialize progress dialog
        
        Args:
            parent: Parent window
            title: Dialog title
            message: Dialog message
        """
        self.parent = parent
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.geometry("300x120")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Center on parent
        x = parent.winfo_x() + (parent.winfo_width() // 2) - 150
        y = parent.winfo_y() + (parent.winfo_height() // 2) - 60
        self.dialog.geometry(f"+{x}+{y}")
        
        # Main frame
        main_frame = ttk.Frame(self.dialog, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Message
        self.message_var = tk.StringVar(value=message)
        message_label = ttk.Label(main_frame, textvariable=self.message_var)
        message_label.pack(pady=(0, 10))
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, orient=tk.HORIZONTAL, 
                                      length=260, mode='determinate')
        self.progress.pack(pady=10, fill=tk.X)
        
        # Status text
        self.status_var = tk.StringVar(value="")
        status_label = ttk.Label(main_frame, textvariable=self.status_var)
        status_label.pack()
        
        # Cancel button (optional)
        self.cancel_callback = None
        self.cancel_button = ttk.Button(main_frame, text="Cancel", 
                                      state=tk.DISABLED, command=self.cancel)
        self.cancel_button.pack(pady=(10, 0))
    
    def set_progress(self, value, maximum=100):
        """
        Set progress bar value
        
        Args:
            value: Current progress value
            maximum: Maximum progress value
        """
        percent = (value / maximum) * 100 if maximum > 0 else 0
        self.progress['value'] = percent
        self.status_var.set(f"{value} of {maximum} ({percent:.1f}%)")
        self.dialog.update_idletasks()
    
    def set_message(self, message):
        """
        Set dialog message
        
        Args:
            message: Message to display
        """
        self.message_var.set(message)
        self.dialog.update_idletasks()
    
    def enable_cancel(self, callback):
        """
        Enable cancel button with callback
        
        Args:
            callback: Function to call on cancel
        """
        self.cancel_callback = callback
        self.cancel_button.configure(state=tk.NORMAL)
    
    def cancel(self):
        """Handle cancel button press"""
        if self.cancel_callback:
            self.cancel_callback()
    
    def close(self):
        """Close the dialog"""
        self.dialog.destroy()