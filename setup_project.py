#!/usr/bin/env python3
"""
Setup script for NetworkX project
Creates necessary directory structure and placeholder files
"""

import os
import sys

def create_directory(dir_path):
    """Create directory if it doesn't exist"""
    if not os.path.exists(dir_path):
        print(f"Creating directory: {dir_path}")
        os.makedirs(dir_path)
    return dir_path

def create_file(file_path, content=""):
    """Create a file with optional content"""
    if not os.path.exists(file_path):
        print(f"Creating file: {file_path}")
        with open(file_path, 'w') as f:
            f.write(content)
    return file_path

def create_init_file(dir_path):
    """Create __init__.py file in directory"""
    init_file = os.path.join(dir_path, "__init__.py")
    return create_file(init_file, f'"""\n{os.path.basename(dir_path)} package\n"""\n\n')

def setup_project():
    """Set up the NetworkX project structure"""
    # Create directory structure
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Main packages
    core_dir = create_directory(os.path.join(base_dir, "core"))
    ui_dir = create_directory(os.path.join(base_dir, "ui"))
    utils_dir = create_directory(os.path.join(base_dir, "utils"))
    
    # Create __init__.py files
    create_init_file(core_dir)
    create_init_file(ui_dir)
    create_init_file(utils_dir)
    
    # Verify core files exist
    core_files = ["constants.py", "packet_analyzer.py", "packet_capture.py"]
    for file in core_files:
        file_path = os.path.join(core_dir, file)
        if not os.path.exists(file_path):
            print(f"Warning: Missing core file: {file_path}")
            if file == "constants.py":
                create_constants_file(file_path)
    
    # Verify ui files
    ui_files = ["main_window.py", "dialogs.py"]
    for file in ui_files:
        file_path = os.path.join(ui_dir, file)
        if not os.path.exists(file_path):
            print(f"Warning: Missing UI file: {file_path}")
    
    # Verify utils files
    utils_files = ["formatting.py", "pcap_handler.py", "export.py"]
    for file in utils_files:
        file_path = os.path.join(utils_dir, file)
        if not os.path.exists(file_path):
            print(f"Warning: Missing utils file: {file_path}")
    
    print("\nProject structure setup completed.")
    print("Run the following command to install dependencies:")
    print("pip install -r requirements.txt")
    print("\nTo run the application:")
    print("python app.py")

def create_constants_file(file_path):
    """Create the constants.py file with default values"""
    content = '''"""
NetworkX - Constants Module
Shared constants for the application
"""

# Common services mapping
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP (server)", 68: "DHCP (client)", 80: "HTTP", 110: "POP3", 
    123: "NTP", 143: "IMAP", 161: "SNMP", 443: "HTTPS", 445: "SMB",
    1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    8080: "HTTP Proxy", 8443: "HTTPS Alt"
}

# Protocol colors for visualization
PROTOCOL_COLORS = {
    "TCP": "#4caf50",
    "UDP": "#2196f3",
    "HTTP": "#9c27b0", 
    "HTTPS": "#673ab7",
    "DNS": "#ff9800",
    "ICMP": "#ff5722",
    "ARP": "#795548"
}

# Application information
APP_NAME = "NetworkX"
APP_VERSION = "1.0"
APP_DESCRIPTION = "A lightweight network packet analyzer for capturing, analyzing, and monitoring network traffic."
APP_FEATURES = [
    "Live packet capture",
    "PCAP file analysis",
    "Protocol statistics",
    "DNS and HTTP monitoring"
]

# Light theme colors
LIGHT_THEME = {
    "bg_color": "#f0f0f0",
    "fg_color": "#000000",
    "button_bg": "#e0e0e0",
    "button_active": "#d0d0d0",
    "tab_selected": "#4286f4",
    "selected_fg": "white"
}

# Dark theme colors
DARK_THEME = {
    "bg_color": "#2d2d2d",
    "fg_color": "#e0e0e0",
    "button_bg": "#3d3d3d",
    "button_active": "#4286f4",
    "tab_selected": "#4286f4",
    "selected_fg": "white"
}
'''
    create_file(file_path, content)

if __name__ == "__main__":
    setup_project()