"""
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
