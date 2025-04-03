#!/usr/bin/env python3
"""
NetworkX - Network Packet Analyzer
Main entry point for the application
"""

import tkinter as tk
import os
import sys

# Add current directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Check for required dependencies
try:
    from scapy.all import conf as scapy_conf
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    print("Scapy library is required. Install it with: pip install scapy")

# Import main application window
try:
    from ui.main_window import NetworkAnalyzerApp
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Make sure all required directories and modules are available.")
    sys.exit(1)


def main():
    """Main entry point for the application"""
    # Check if Scapy is available
    if not HAS_SCAPY:
        if tk._default_root:
            from tkinter import messagebox
            messagebox.showerror("Error", "Scapy library is required. Install it with: pip install scapy")
        return

    # Create main window
    root = tk.Tk()
    app = NetworkAnalyzerApp(root)
    
    # Handle window close event
    root.protocol("WM_DELETE_WINDOW", app.on_exit)
    
    # Start the main event loop
    root.mainloop()


if __name__ == "__main__":
    main()