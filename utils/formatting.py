"""
NetworkX - Formatting Module
Utility functions for formatting data
"""


def format_bytes(bytes_value):
    """
    Format bytes into a human-readable string (B, KB, MB)
    
    Args:
        bytes_value: Number of bytes
        
    Returns:
        str: Formatted bytes string
    """
    if bytes_value < 1024:
        return f"{bytes_value} bytes"
    elif bytes_value < 1024*1024:
        return f"{bytes_value/1024:.1f} KB"
    else:
        return f"{bytes_value/(1024*1024):.1f} MB"


def format_packet_rate(count, elapsed_time):
    """
    Format a packet rate
    
    Args:
        count: Number of packets
        elapsed_time: Elapsed time in seconds
        
    Returns:
        str: Formatted packet rate string
    """
    if elapsed_time <= 0:
        return "0 pkts/s"
    
    rate = count / elapsed_time
    return f"{rate:.1f} pkts/s"


def format_protocol_stats(protocol_stats, packet_count):
    """
    Format protocol statistics into a report string
    
    Args:
        protocol_stats: Dictionary of protocol to count
        packet_count: Total packet count
        
    Returns:
        str: Formatted statistics text
    """
    lines = []
    
    for proto, count in sorted(protocol_stats.items(), key=lambda x: x[1], reverse=True):
        percent = (count / packet_count) * 100 if packet_count else 0
        lines.append(f"{proto}: {count} ({percent:.1f}%)")
    
    return "\n".join(lines)


def format_ip_stats(ip_stats, packet_count, limit=30):
    """
    Format IP address statistics into a report string
    
    Args:
        ip_stats: Dictionary of IP address to stats
        packet_count: Total packet count
        limit: Maximum number of IPs to include
        
    Returns:
        str: Formatted statistics text
    """
    lines = []
    
    sorted_ips = sorted(ip_stats.items(), 
                      key=lambda x: x[1]['sent'] + x[1]['received'], 
                      reverse=True)[:limit]
                      
    for ip, data in sorted_ips:
        total = data['sent'] + data['received']
        percent = (total / packet_count) * 100 if packet_count else 0
        lines.append(f"{ip}: {total} ({percent:.1f}%) [↑:{data['sent']} ↓:{data['received']}]")
    
    return "\n".join(lines)


def format_hex_dump(data):
    """
    Format binary data as a hex dump
    
    Args:
        data: Binary data (bytes)
        
    Returns:
        str: Formatted hex dump
    """
    result = []
    
    # Format in hex dump style (offset, hex, ascii)
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        
        # Format hex part
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        hex_part = hex_part.ljust(47)  # Pad to align ASCII
        
        # Format ASCII part
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        
        # Add line
        result.append(f"{i:04x}:  {hex_part}  |{ascii_part}|")
    
    return "\n".join(result)