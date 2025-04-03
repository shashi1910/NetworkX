"""
NetworkX - Main Window Module
The main application window
"""

import time
import threading
import webbrowser
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, Menu, scrolledtext

# Import from core modules
from core.constants import APP_NAME
from core.packet_capture import PacketCapture
from core.packet_analyzer import PacketAnalyzer

# Import from UI modules
from ui.dialogs import FilterHelperDialog, AboutDialog

# Import from utils modules
from utils.formatting import format_bytes, format_packet_rate
from utils.pcap_handler import read_pcap, write_pcap
from utils.export import export_statistics


class NetworkAnalyzerApp:
    """Main application window for NetworkX"""
    
    def __init__(self, root):
        """
        Initialize the main application window
        
        Args:
            root: Tkinter root window
        """
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("1200x800")
        
        # Set app icon if available
        try:
            self.root.iconphoto(True, tk.PhotoImage(data=b'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAACXBIWXMAAAsTAAALEwEAmpwYAAAAIGNIUk0AAHolAACAgwAA+f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAAAI1SURBVHjaYvz//z8DJQAggFiIVfh0WQrD9bpEBmYODoZ/P38x/P71N0pF/9DZuDWr9gACCKsB9+oSGBhYmBl+fPvD8P//f4bvX/4y/Pn5j0FKXkL4wKJDXjgNAAggtAM2l0Uy3D28l+HdCzGGJ9c5GW4c/8jw9MYbhu8fvzP8+yfCIKzUzSDQfYzh93VhhvdZMgzfG24yAAQQ48NZkf+ZOXgY+KUYGDh4IoG4mIGN95yJkjrD/7+/GH48fsTw8/lFhh+PbjMwCygzMIvKM3x7+pDhyZU9DN+++jCw8aoxMLEwAAQQ47xIPob/vxkYhGVetVrZer9+/ev0ty+/vr57/lnj34+PDDyCwgz/vr9n+P/nOwMDIyMDw//fDJ/uH2S4sb2f4ceHLwzMrHwAAcTCyMDCwPDjPQMzG9vxueuPHN+288p/Nk7m/0/uvmP49fUrAyMTIwMzOycDEysbw+NLuxi4RC0Ybu7vZmDlYmH4/fMpQACxvHj2mUFQTufN5bOPb3759HM6GyczA8P3LwxfPv5l+POXC2iACAPDn/8MDx6xMDCyCDOw8ogyvHzxhYGN/SkDQACxvH7zhIFFWO/Dx3c/DZ/cec3w/fMfBiZmRgYWNiYGdm5mhps3fzD8/PuPgYtHkEFA3Jzh3snVDL9/CjD8+/uAAScACCAmNnbO/z+/fxN6/egdw/ePvxmYmJkY2DmZGbj5WBi+ffjDYOrmxvD97QeGH69vMjy+vo+Bk/8tAw4AEGAAp++FdJbDLBAAAAAASUVORK5CYII='))
        except:
            pass
        
        # Create instances of core components
        self.packet_analyzer = PacketAnalyzer()
        self.packet_capture = PacketCapture(self.process_packet_callback)
        
        # App state variables
        self.running = False
        self.dark_mode = False
        self.auto_scroll = True
        
        # Create the application menu
        self.create_menu()
        
        # Build the main UI
        self.create_ui()
        
        # Set up periodic update for statistics display
        self.root.after(500, self.update_stats_display)
    
    def create_menu(self):
        """Create the application menu"""
        menu_bar = Menu(self.root)
        self.root.config(menu=menu_bar)
        
        # File menu
        file_menu = Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="File", menu=file_menu)
        
        file_menu.add_command(label="Open PCAP...", command=self.open_pcap)
        file_menu.add_command(label="Save PCAP...", command=self.save_pcap)
        file_menu.add_separator()
        file_menu.add_command(label="Export Statistics...", command=self.export_statistics)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_exit)
        
        # Capture menu
        capture_menu = Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="Capture", menu=capture_menu)
        
        capture_menu.add_command(label="Start Capture", command=self.start_capture)
        capture_menu.add_command(label="Stop Capture", command=self.stop_capture)
        capture_menu.add_separator()
        capture_menu.add_command(label="Filter Helper...", command=self.open_filter_helper)
        capture_menu.add_command(label="Clear Packets", command=self.clear_data)
        
        # View menu
        view_menu = Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="View", menu=view_menu)
        
        self.auto_scroll_var = tk.BooleanVar(value=True)
        view_menu.add_checkbutton(label="Auto-scroll", variable=self.auto_scroll_var, 
                                command=self.toggle_auto_scroll)
        
        self.dark_mode_var = tk.BooleanVar(value=False)
        view_menu.add_checkbutton(label="Dark Mode", variable=self.dark_mode_var, 
                                command=self.toggle_theme)
        
        # Help menu
        help_menu = Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="Help", menu=help_menu)
        
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Online Documentation", 
                            command=lambda: webbrowser.open("https://github.com/secdev/scapy"))
    
    def create_ui(self):
        """Create the main user interface"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding=5)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Top control panel
        control_frame = ttk.LabelFrame(main_frame, text="Capture Controls", padding=5)
        control_frame.pack(fill=tk.X, pady=5)
        
        # First row controls
        row1 = ttk.Frame(control_frame)
        row1.pack(fill=tk.X, pady=5)
        
        ttk.Label(row1, text="Interface:").grid(row=0, column=0, padx=5)
        self.interface_var = tk.StringVar()
        
        # Get available interfaces
        ifaces = self.packet_capture.get_interfaces()
            
        self.interface_combo = ttk.Combobox(row1, textvariable=self.interface_var, values=ifaces, width=20)
        if ifaces:
            self.interface_combo.current(0)
        self.interface_combo.grid(row=0, column=1, padx=5)
        
        ttk.Label(row1, text="Filter:").grid(row=0, column=2, padx=5)
        self.filter_var = tk.StringVar()
        self.filter_entry = ttk.Entry(row1, textvariable=self.filter_var, width=30)
        self.filter_entry.grid(row=0, column=3, padx=5)
        
        ttk.Button(row1, text="?", width=2, command=self.open_filter_helper).grid(row=0, column=4)
        
        self.start_button = ttk.Button(row1, text="Start Capture", command=self.start_capture)
        self.start_button.grid(row=0, column=5, padx=5)
        
        self.stop_button = ttk.Button(row1, text="Stop Capture", command=self.stop_capture, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=6, padx=5)
        
        ttk.Button(row1, text="Clear", command=self.clear_data).grid(row=0, column=7, padx=5)
        
        # Status display
        status_frame = ttk.Frame(control_frame)
        status_frame.pack(fill=tk.X, pady=5)
        
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(status_frame, textvariable=self.status_var)
        status_label.pack(side=tk.LEFT, padx=5)
        
        self.packet_count_var = tk.StringVar(value="Packets: 0")
        ttk.Label(status_frame, textvariable=self.packet_count_var).pack(side=tk.LEFT, padx=20)
        
        self.packet_rate_var = tk.StringVar(value="Rate: 0 pkts/s")
        ttk.Label(status_frame, textvariable=self.packet_rate_var).pack(side=tk.LEFT, padx=20)
        
        self.bytes_var = tk.StringVar(value="Data: 0 KB")
        ttk.Label(status_frame, textvariable=self.bytes_var).pack(side=tk.LEFT, padx=20)
        
        # DNS Test button
        ttk.Button(status_frame, text="Test DNS", command=self.test_dns_lookup).pack(side=tk.RIGHT, padx=5)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Packet list tab
        packet_frame = ttk.Frame(self.notebook)
        self.notebook.add(packet_frame, text="Packets")
        
        # Create packet listview with paned window for packet details
        paned = ttk.PanedWindow(packet_frame, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True)
        
        # Top frame for packet list
        list_frame = ttk.Frame(paned)
        paned.add(list_frame, weight=60)
        
        # Create packet listview
        columns = ("No", "Time", "Source", "Destination", "Protocol", "Length", "Info")
        self.packet_tree = ttk.Treeview(list_frame, columns=columns, show="headings")
        
        # Configure columns
        for col in columns:
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=100)
        
        self.packet_tree.column("No", width=60, anchor=tk.E)
        self.packet_tree.column("Time", width=100)
        self.packet_tree.column("Length", width=70, anchor=tk.E)
        self.packet_tree.column("Info", width=300)
        
        # Add scrollbars
        vsb = ttk.Scrollbar(list_frame, orient="vertical", command=self.packet_tree.yview)
        hsb = ttk.Scrollbar(list_frame, orient="horizontal", command=self.packet_tree.xview)
        self.packet_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout
        self.packet_tree.grid(column=0, row=0, sticky='nsew')
        vsb.grid(column=1, row=0, sticky='ns')
        hsb.grid(column=0, row=1, sticky='ew')
        
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        
        # Bottom frame for packet details
        details_frame = ttk.Frame(paned)
        paned.add(details_frame, weight=40)
        
        # Create notebook for packet details views
        details_notebook = ttk.Notebook(details_frame)
        details_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Details tab
        details_tab = ttk.Frame(details_notebook)
        details_notebook.add(details_tab, text="Details")
        
        self.details_text = tk.scrolledtext.ScrolledText(details_tab, wrap=tk.WORD)
        self.details_text.pack(fill=tk.BOTH, expand=True)
        
        # Hex view tab
        hex_tab = ttk.Frame(details_notebook)
        details_notebook.add(hex_tab, text="Hex View")
        
        self.hex_text = tk.scrolledtext.ScrolledText(hex_tab, font=('Courier', 10))
        self.hex_text.pack(fill=tk.BOTH, expand=True)
        
        # Bind event for packet selection
        self.packet_tree.bind('<<TreeviewSelect>>', self.on_packet_select)
        
        # Statistics tab
        stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(stats_frame, text="Statistics")
        
        # Create statistics notebook
        stats_notebook = ttk.Notebook(stats_frame)
        stats_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Protocol stats tab
        proto_frame = ttk.Frame(stats_notebook)
        stats_notebook.add(proto_frame, text="Protocols")
        
        self.proto_text = tk.scrolledtext.ScrolledText(proto_frame, height=25, wrap=tk.WORD)
        self.proto_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # IP stats tab
        ip_frame = ttk.Frame(stats_notebook)
        stats_notebook.add(ip_frame, text="IP Addresses")
        
        self.ip_text = tk.scrolledtext.ScrolledText(ip_frame, height=25, wrap=tk.WORD)
        self.ip_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # DNS tab
        dns_frame = ttk.Frame(self.notebook)
        self.notebook.add(dns_frame, text="DNS")
        
        # DNS query list
        dns_columns = ("No", "Time", "Query", "Type", "Answers", "TTL")
        self.dns_tree = ttk.Treeview(dns_frame, columns=dns_columns, show="headings")
        
        # Configure columns
        for col in dns_columns:
            self.dns_tree.heading(col, text=col)
        
        self.dns_tree.column("No", width=60, anchor=tk.E)
        self.dns_tree.column("Time", width=100)
        self.dns_tree.column("Query", width=200)
        self.dns_tree.column("Type", width=60)
        self.dns_tree.column("Answers", width=300)
        self.dns_tree.column("TTL", width=60, anchor=tk.E)
        
        # Scrollbar for DNS tree
        dns_vsb = ttk.Scrollbar(dns_frame, orient="vertical", command=self.dns_tree.yview)
        dns_hsb = ttk.Scrollbar(dns_frame, orient="horizontal", command=self.dns_tree.xview)
        self.dns_tree.configure(yscrollcommand=dns_vsb.set, xscrollcommand=dns_hsb.set)
        
        self.dns_tree.grid(column=0, row=0, sticky='nsew')
        dns_vsb.grid(column=1, row=0, sticky='ns')
        dns_hsb.grid(column=0, row=1, sticky='ew')
        
        dns_frame.columnconfigure(0, weight=1)
        dns_frame.rowconfigure(0, weight=1)
        
        # HTTP tab
        http_frame = ttk.Frame(self.notebook)
        self.notebook.add(http_frame, text="HTTP")
        
        # HTTP requests list
        http_columns = ("No", "Time", "Method", "Host", "Path", "Status")
        self.http_tree = ttk.Treeview(http_frame, columns=http_columns, show="headings")
        
        # Configure columns
        for col in http_columns:
            self.http_tree.heading(col, text=col)
        
        self.http_tree.column("No", width=60, anchor=tk.E)
        self.http_tree.column("Time", width=100)
        self.http_tree.column("Method", width=70)
        self.http_tree.column("Host", width=200)
        self.http_tree.column("Path", width=300)
        self.http_tree.column("Status", width=70, anchor=tk.E)
        
        # Scrollbar for HTTP tree
        http_vsb = ttk.Scrollbar(http_frame, orient="vertical", command=self.http_tree.yview)
        http_hsb = ttk.Scrollbar(http_frame, orient="horizontal", command=self.http_tree.xview)
        self.http_tree.configure(yscrollcommand=http_vsb.set, xscrollcommand=http_hsb.set)
        
        self.http_tree.grid(column=0, row=0, sticky='nsew')
        http_vsb.grid(column=1, row=0, sticky='ns')
        http_hsb.grid(column=0, row=1, sticky='ew')
        
        http_frame.columnconfigure(0, weight=1)
        http_frame.rowconfigure(0, weight=1)
        
        # Add double-click binding for HTTP tree
        self.http_tree.bind('<Double-1>', self.on_http_double_click)
        
        # Apply dark mode if needed
        if self.dark_mode:
            self.apply_dark_theme()
    
    def toggle_theme(self):
        """Toggle between light and dark themes"""
        self.dark_mode = self.dark_mode_var.get()
        if self.dark_mode:
            self.apply_dark_theme()
        else:
            self.apply_light_theme()
    
    def apply_dark_theme(self):
        """Apply dark theme to the application"""
        style = ttk.Style()
        style.theme_use('clam')
        
        bg_color = "#2d2d2d"
        fg_color = "#e0e0e0"
        select_color = "#4286f4"
        
        style.configure(".", background=bg_color, foreground=fg_color)
        style.configure("TFrame", background=bg_color)
        style.configure("TLabel", background=bg_color, foreground=fg_color)
        style.configure("TButton", background="#3d3d3d", foreground=fg_color)
        style.map("TButton", background=[("active", select_color)])
        
        style.configure("TLabelframe", background=bg_color, foreground=fg_color)
        style.configure("TLabelframe.Label", background=bg_color, foreground=fg_color)
        
        style.configure("TNotebook", background=bg_color)
        style.configure("TNotebook.Tab", background="#3d3d3d", foreground=fg_color)
        style.map("TNotebook.Tab", background=[("selected", select_color)])
        
        style.configure("Treeview", 
                      background=bg_color, 
                      foreground=fg_color,
                      fieldbackground=bg_color)
        style.map("Treeview", 
                background=[("selected", select_color)],
                foreground=[("selected", "white")])
        
        # Configure text widgets
        text_widgets = [self.details_text, self.hex_text, self.proto_text, self.ip_text]
        for widget in text_widgets:
            widget.config(bg="#2d2d2d", fg="#e0e0e0", insertbackground="#e0e0e0")
    
    def apply_light_theme(self):
        """Apply light theme to the application"""
        style = ttk.Style()
        style.theme_use('clam')
        
        bg_color = "#f0f0f0"
        fg_color = "#000000"
        
        style.configure(".", background=bg_color, foreground=fg_color)
        style.configure("TFrame", background=bg_color)
        style.configure("TLabel", background=bg_color, foreground=fg_color)
        style.configure("TButton", background="#e0e0e0", foreground=fg_color)
        style.map("TButton", background=[("active", "#d0d0d0")])
        
        style.configure("TLabelframe", background=bg_color, foreground=fg_color)
        style.configure("TLabelframe.Label", background=bg_color, foreground=fg_color)
        
        style.configure("TNotebook", background=bg_color)
        style.configure("TNotebook.Tab", background="#e0e0e0", foreground=fg_color)
        style.map("TNotebook.Tab", background=[("selected", "#4286f4")], 
                foreground=[("selected", "white")])
        
        style.configure("Treeview", 
                      background="white", 
                      foreground=fg_color,
                      fieldbackground="white")
        style.map("Treeview", 
                background=[("selected", "#4286f4")],
                foreground=[("selected", "white")])
        
        # Configure text widgets
        text_widgets = [self.details_text, self.hex_text, self.proto_text, self.ip_text]
        for widget in text_widgets:
            widget.config(bg="white", fg="black", insertbackground="black")
    
    def toggle_auto_scroll(self):
        """Toggle auto-scroll for packet list"""
        self.auto_scroll = self.auto_scroll_var.get()
    
    def update_stats_display(self):
        """Update statistics displays"""
        if self.packet_analyzer.packets:
            # Update packet count
            packet_count = self.packet_analyzer.packet_count
            self.packet_count_var.set(f"Packets: {packet_count}")
            
            # Calculate packet rate
            if self.packet_analyzer.start_time:
                elapsed = time.time() - self.packet_analyzer.start_time
                if elapsed > 0:
                    self.packet_rate_var.set(format_packet_rate(packet_count, elapsed))
            
            # Calculate total bytes
            total_bytes = sum(pkt.get('length', 0) for pkt in self.packet_analyzer.packets)
            self.bytes_var.set(f"Data: {format_bytes(total_bytes)}")
            
            # Update protocol statistics
            if self.packet_analyzer.protocol_stats:
                self.proto_text.configure(state='normal')
                self.proto_text.delete(1.0, tk.END)
                
                for proto, count in sorted(self.packet_analyzer.protocol_stats.items(), 
                                         key=lambda x: x[1], reverse=True):
                    percent = (count / packet_count) * 100 if packet_count else 0
                    self.proto_text.insert(tk.END, f"{proto}: {count} ({percent:.1f}%)\n")
                    
                self.proto_text.configure(state='disabled')
            
            # Update IP statistics
            if self.packet_analyzer.ip_stats:
                self.ip_text.configure(state='normal')
                self.ip_text.delete(1.0, tk.END)
                
                sorted_ips = sorted(self.packet_analyzer.ip_stats.items(), 
                                  key=lambda x: x[1]['sent'] + x[1]['received'], 
                                  reverse=True)[:30]
                                  
                for ip, data in sorted_ips:
                    total = data['sent'] + data['received']
                    percent = (total / packet_count) * 100 if packet_count else 0
                    self.ip_text.insert(tk.END, 
                                      f"{ip}: {total} ({percent:.1f}%) [↑:{data['sent']} ↓:{data['received']}]\n")
                    
                self.ip_text.configure(state='disabled')
        
        # Schedule next update
        self.root.after(1000, self.update_stats_display)
    
    def start_capture(self):
        """Start packet capture"""
        interface = self.interface_var.get()
        if not interface:
            messagebox.showerror("Error", "Please select a network interface")
            return
        
        # Clear existing data if needed
        if self.packet_analyzer.packets and messagebox.askyesno("Confirm", "Clear existing packets?"):
            self.clear_data()
        
        self.packet_analyzer.start_time = time.time()
        self.status_var.set(f"Capturing on {interface}...")
        
        # Update button states
        self.start_button.configure(state=tk.DISABLED)
        self.stop_button.configure(state=tk.NORMAL)
        
        # Get filter
        bpf_filter = self.filter_var.get().strip()
        
        # Start capture
        success = self.packet_capture.start(interface, bpf_filter)
        if not success:
            self.status_var.set("Failed to start capture")
            self.start_button.configure(state=tk.NORMAL)
            self.stop_button.configure(state=tk.DISABLED)
    
    def stop_capture(self):
        """Stop packet capture"""
        self.packet_capture.stop()
        self.status_var.set("Capture stopped")
        
        # Update button states
        self.start_button.configure(state=tk.NORMAL)
        self.stop_button.configure(state=tk.DISABLED)
    
    def process_packet_callback(self, packet, timestamp=None, error=None):
        """
        Callback for packet processing
        
        Args:
            packet: Scapy packet object
            timestamp: Packet timestamp
            error: Error message if any
        """
        if error:
            # Handle capture errors
            self.root.after(0, lambda: messagebox.showerror("Capture Error", str(error)))
            self.root.after(0, lambda: self.status_var.set(f"Error: {str(error)}"))
            self.root.after(0, lambda: self.start_button.configure(state=tk.NORMAL))
            self.root.after(0, lambda: self.stop_button.configure(state=tk.DISABLED))
            return
            
        if not packet:
            return
            
        # Process the packet with analyzer
        packet_info = self.packet_analyzer.process_packet(packet, timestamp)
        
        # Add to UI (must be done in the main thread)
        self.root.after(0, lambda: self.add_packet_to_ui(packet_info))
        
        # Handle updating the HTTP UI explicitly when HTTP traffic is detected
        if 'HTTP' in packet_info['protocol']:
            self.root.after(0, self.update_http_ui)
        
        # Handle updating the DNS UI
        dns_updated = False
        
        # Update DNS UI
        # First check if this packet has added a new DNS record
        if 'DNS' in packet_info['protocol']:
            # Check all DNS records and add any new ones to the UI
            for pkt_id, dns_info in list(self.packet_analyzer.dns_records.items()):
                # Only add DNS records that don't already have a UI ID
                if 'ui_id' not in dns_info:
                    self.root.after(0, lambda d=dns_info: self.add_dns_to_ui(d))
                    dns_updated = True
        
        # Also check for any DNS updates even if this wasn't a DNS packet
        # (for responses that might have been triggered by other packets)
        if not dns_updated and self.packet_analyzer.dns_records:
            self.root.after(0, self.update_dns_ui)
            
    def add_packet_to_ui(self, packet_info):
        """
        Add a packet to the UI packet list
        
        Args:
            packet_info: Dictionary with packet information
        """
        from core.constants import PROTOCOL_COLORS
        
        # Get protocol color for visual distinction
        protocol_name = packet_info['protocol'].split(' ')[0]  # Remove any service info
        color = PROTOCOL_COLORS.get(protocol_name, "")
        
        values = (
            packet_info['no'],
            packet_info['time'],
            packet_info['src'],
            packet_info['dst'],
            packet_info['protocol'],
            packet_info['length'],
            packet_info['info']
        )
        
        # Insert into the treeview
        item_id = self.packet_tree.insert("", "end", values=values, tags=(protocol_name,))
        
        # Apply color if available
        if color:
            self.packet_tree.tag_configure(protocol_name, background=color)
        
        # Store the item ID for later reference
        packet_info['item_id'] = item_id
        
        # Auto-scroll if enabled
        if self.auto_scroll:
            self.packet_tree.see(item_id)
    
    def add_http_to_ui(self, http_info):
        """
        Add HTTP request to UI
        
        Args:
            http_info: HTTP request information
        """
        values = (
            http_info['no'],
            http_info['time'],
            http_info['method'],
            http_info['host'],
            http_info['path'],
            http_info['status']
        )
        
        item_id = self.http_tree.insert("", "end", values=values)
        http_info['ui_id'] = item_id
        http_info['ui_added'] = True
        
        # Auto-scroll if enabled
        if self.auto_scroll:
            self.http_tree.see(item_id)
    
    def update_http_ui(self):
        """Update HTTP UI with requests and responses"""
        updated = False
        
        for req in self.packet_analyzer.http_requests:
            # If this request/response hasn't been added to the UI yet
            if not req.get('ui_added', False):
                values = (
                    req['no'],
                    req['time'],
                    req['method'],
                    req['host'],
                    req['path'],
                    req['status']
                )
                
                item_id = self.http_tree.insert("", "end", values=values)
                req['ui_id'] = item_id
                req['ui_added'] = True
                updated = True
                
            # If this request/response has been added but needs an update (e.g., status added)
            elif not req.get('ui_updated', True) and 'ui_id' in req:
                values = (
                    req['no'],
                    req['time'],
                    req['method'],
                    req['host'],
                    req['path'],
                    req['status']
                )
                try:
                    if self.http_tree.exists(req['ui_id']):
                        self.http_tree.item(req['ui_id'], values=values)
                        req['ui_updated'] = True
                        updated = True
                except Exception as e:
                    print(f"Error updating HTTP tree item: {e}")
        
        # Auto-scroll if needed
        if updated and self.auto_scroll and self.http_tree.get_children():
            self.http_tree.see(self.http_tree.get_children()[-1])
    
    def add_dns_to_ui(self, dns_info):
        """
        Add DNS query to UI
        
        Args:
            dns_info: DNS query information
        """
        # Make sure answers is always a list
        if 'answers' not in dns_info:
            dns_info['answers'] = []
        
        # Format answers for display
        answers_str = ", ".join(dns_info['answers']) if dns_info['answers'] else ""
        
        values = (
            dns_info['no'],
            dns_info['time'],
            dns_info['query'],
            dns_info['type'],
            answers_str,
            dns_info['ttl']
        )
        
        item_id = self.dns_tree.insert("", "end", values=values)
        dns_info['ui_id'] = item_id
        dns_info['ui_added'] = True
        
        # Auto-scroll if enabled
        if self.auto_scroll:
            self.dns_tree.see(item_id)
    
    def update_dns_ui(self):
        """Update DNS UI with responses"""
        updated = False
        
        for packet_id, dns_info in list(self.packet_analyzer.dns_records.items()):
            # If we have no UI entry yet, add it
            if 'ui_id' not in dns_info:
                self.add_dns_to_ui(dns_info)
                updated = True
            # If we have a UI entry already and there are answers, update it
            elif dns_info.get('ui_updated', True) == False and 'ui_id' in dns_info:
                answers_str = ", ".join(dns_info['answers']) if dns_info['answers'] else ""
                
                values = (
                    dns_info['no'],
                    dns_info['time'],
                    dns_info['query'],
                    dns_info['type'],
                    answers_str,
                    dns_info['ttl']
                )
                
                try:
                    # Check if the item still exists before updating
                    if self.dns_tree.exists(dns_info['ui_id']):
                        self.dns_tree.item(dns_info['ui_id'], values=values)
                        dns_info['ui_updated'] = True
                        updated = True
                except Exception as e:
                    print(f"Error updating DNS tree item: {e}")
        
        # Auto-scroll if needed
        if updated and self.auto_scroll and self.dns_tree.get_children():
            self.dns_tree.see(self.dns_tree.get_children()[-1])
    
    def on_packet_select(self, event):
        """
        Handle packet selection in the packet list
        
        Args:
            event: Selection event
        """
        selection = self.packet_tree.selection()
        if not selection:
            return
            
        # Get the selected packet
        item_id = selection[0]
        values = self.packet_tree.item(item_id, "values")
        packet_no = int(values[0])
        
        # Find the packet in our list
        for packet_info in self.packet_analyzer.packets:
            if packet_info['no'] == packet_no:
                self.display_packet_details(packet_info)
                break
    
    def on_http_double_click(self, event):
        """Handle double-click on HTTP request in the tree"""
        selection = self.http_tree.selection()
        if not selection:
            return
            
        # Get the selected HTTP entry
        item_id = selection[0]
        values = self.http_tree.item(item_id, "values")
        packet_no = int(values[0])
        
        # Find the packet and display its details
        for packet_info in self.packet_analyzer.packets:
            if packet_info['no'] == packet_no:
                # Switch to the packets tab
                self.notebook.select(0)
                
                # Select the packet in the packet tree
                for item in self.packet_tree.get_children():
                    if self.packet_tree.item(item, "values")[0] == str(packet_no):
                        self.packet_tree.selection_set(item)
                        self.packet_tree.see(item)
                        self.on_packet_select(None)  # Trigger the packet details display
                        break
                break
    
    def display_packet_details(self, packet_info):
        """
        Display detailed packet information
        
        Args:
            packet_info: Dictionary with packet information
        """
        # Get packet details from analyzer
        details_text, hex_dump = self.packet_analyzer.get_packet_details(packet_info)
        
        # Display detailed view
        self.details_text.configure(state='normal')
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(tk.END, details_text)
        self.details_text.configure(state='disabled')
        
        # Display hex view
        self.hex_text.configure(state='normal')
        self.hex_text.delete(1.0, tk.END)
        self.hex_text.insert(tk.END, hex_dump)
        self.hex_text.configure(state='disabled')
    
    def clear_data(self):
        """Clear all captured packets and statistics"""
        # Reset analyzer
        self.packet_analyzer.reset()
        
        # Clear UI elements
        self.packet_tree.delete(*self.packet_tree.get_children())
        self.dns_tree.delete(*self.dns_tree.get_children())
        self.http_tree.delete(*self.http_tree.get_children())
        
        self.details_text.configure(state='normal')
        self.details_text.delete(1.0, tk.END)
        self.details_text.configure(state='disabled')
        
        self.hex_text.configure(state='normal')
        self.hex_text.delete(1.0, tk.END)
        self.hex_text.configure(state='disabled')
        
        self.proto_text.configure(state='normal')
        self.proto_text.delete(1.0, tk.END)
        self.proto_text.configure(state='disabled')
        
        self.ip_text.configure(state='normal')
        self.ip_text.delete(1.0, tk.END)
        self.ip_text.configure(state='disabled')
        
        # Reset counters
        self.packet_count_var.set("Packets: 0")
        self.packet_rate_var.set("Rate: 0 pkts/s")
        self.bytes_var.set("Data: 0 bytes")
        
        # Reset status
        self.status_var.set("Ready")
    
    def open_filter_helper(self):
        """Open the filter helper dialog"""
        current_filter = self.filter_var.get()
        helper = FilterHelperDialog(self.root, current_filter)
        new_filter = helper.get_result()
        
        if new_filter is not None:
            self.filter_var.set(new_filter)
    
    def save_pcap(self):
        """Save captured packets to a PCAP file"""
        if not self.packet_analyzer.packets:
            messagebox.showinfo("Save PCAP", "No packets to save.")
            return
            
        filename = filedialog.asksaveasfilename(
            title="Save PCAP",
            filetypes=(("PCAP files", "*.pcap"), ("All files", "*.*")),
            defaultextension=".pcap"
        )
        
        if not filename:
            return
            
        success, message = write_pcap(filename, self.packet_analyzer.packets)
        if success:
            messagebox.showinfo("Save PCAP", message)
        else:
            messagebox.showerror("Save Error", message)
    
    def open_pcap(self):
        """Open and read packets from a PCAP file"""
        filename = filedialog.askopenfilename(
            title="Open PCAP",
            filetypes=(("PCAP files", "*.pcap"), ("All files", "*.*"))
        )
        
        if not filename:
            return
            
        # Confirm if we should clear existing data
        if self.packet_analyzer.packets and not messagebox.askyesno("Confirm", "This will clear existing packets. Continue?"):
            return
            
        self.clear_data()
        self.status_var.set(f"Loading {filename}...")
        self.root.update()
        
        # Start reading
        read_pcap(filename, self.process_pcap_callback, self.pcap_progress_callback)
    
    def process_pcap_callback(self, packet, error=None, completed=False):
        """
        Callback for PCAP file reading
        
        Args:
            packet: Scapy packet object
            error: Error message if any
            completed: True if reading is complete
            
        Returns:
            bool: True to continue, False to abort
        """
        if error:
            self.root.after(0, lambda: messagebox.showerror("Load Error", str(error)))
            self.root.after(0, lambda: self.status_var.set("Ready"))
            return False
            
        if completed:
            self.root.after(0, lambda: self.status_var.set(
                f"Loaded {self.packet_analyzer.packet_count} packets"))
            # Make sure to update HTTP UI when PCAP load completes
            self.root.after(0, self.update_http_ui)
            return True
            
        if packet:
            # Process the packet as we do for live capture
            self.process_packet_callback(packet)
            
        return True
    
    def pcap_progress_callback(self, current, total):
        """
        Update progress for PCAP file reading
        
        Args:
            current: Current packet count
            total: Total packet count
        """
        percent = (current / total) * 100 if total > 0 else 0
        self.status_var.set(f"Loading... {current}/{total} packets ({percent:.1f}%)")
        self.root.update()
    
    def export_statistics(self):
        """Export packet statistics to a file"""
        if not self.packet_analyzer.packets:
            messagebox.showinfo("Export Statistics", "No data to export.")
            return
            
        filename = filedialog.asksaveasfilename(
            title="Export Statistics",
            filetypes=(("CSV files", "*.csv"), ("JSON files", "*.json"), ("All files", "*.*")),
            defaultextension=".csv"
        )
        
        if not filename:
            return
            
        # Prepare data for export
        export_data = {
            'packets': self.packet_analyzer.packets,
            'protocol_stats': self.packet_analyzer.protocol_stats,
            'ip_stats': self.packet_analyzer.ip_stats,
            'port_stats': self.packet_analyzer.port_stats,
            'packet_count': self.packet_analyzer.packet_count,
            'capture_time': time.time() - self.packet_analyzer.start_time if self.packet_analyzer.start_time else 0
        }
        
        # Export based on file extension
        format_type = 'json' if filename.lower().endswith('.json') else 'csv'
        success, message = export_statistics(filename, export_data, format_type)
        
        if success:
            messagebox.showinfo("Export Successful", message)
        else:
            messagebox.showerror("Export Error", message)
    
    def show_about(self):
        """Show about dialog"""
        AboutDialog(self.root)
    
    def test_dns_lookup(self):
        """Perform a test DNS lookup to verify DNS capture"""
        import socket
        import threading
        
        def do_lookup():
            try:
                # Perform several DNS lookups
                domains = ["example.com", "google.com", "github.com", "microsoft.com", "apple.com"]
                for domain in domains:
                    print(f"Looking up {domain}...")
                    result = socket.gethostbyname(domain)
                    print(f"Result for {domain}: {result}")
                    # Small delay between lookups
                    import time
                    time.sleep(1)
            except Exception as e:
                print(f"DNS lookup test error: {e}")
        
        # Run lookups in background thread
        threading.Thread(target=do_lookup, daemon=True).start()
        
        # Update status
        self.status_var.set("Performing test DNS lookups...")
        
        # Schedule a check to make sure DNS records appear in the UI
        self.root.after(1000, self.check_dns_records)
    
    def check_dns_records(self):
        """Check if DNS records have been added to the UI after test lookups"""
        dns_count = len(self.packet_analyzer.dns_records)
        dns_ui_count = len(self.dns_tree.get_children())
        
        print(f"DNS records in analyzer: {dns_count}, DNS records in UI: {dns_ui_count}")
        
        # If we have DNS records but none in the UI, force an update
        if dns_count > 0 and dns_ui_count == 0:
            print("Forcing DNS UI update...")
            for packet_id, dns_info in list(self.packet_analyzer.dns_records.items()):
                if 'ui_id' not in dns_info:
                    self.add_dns_to_ui(dns_info)
        
        # Check again in a second if we're still doing lookups
        if self.status_var.get() == "Performing test DNS lookups...":
            self.root.after(1000, self.check_dns_records)
    
    def on_exit(self):
        """Handle application exit"""
        if self.packet_capture.is_running():
            if not messagebox.askyesno("Confirm Exit", "Capture is still running. Are you sure you want to exit?"):
                return
            self.packet_capture.stop()
        
        self.root.destroy()


