"""
NetworkX - Export Module
Functions for exporting capture data to various formats
"""

import csv
import json
import time


def export_to_csv(filename, packets):
    """
    Export packet data to CSV file
    
    Args:
        filename: Output filename
        packets: List of packet_info dictionaries
        
    Returns:
        tuple: (success, message)
    """
    try:
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write header
            writer.writerow(["No", "Time", "Source", "Destination", "Protocol", "Length", "Info"])
            
            # Write packet data
            for pkt in packets:
                writer.writerow([
                    pkt.get('no', ''),
                    pkt.get('time', ''),
                    pkt.get('src', ''),
                    pkt.get('dst', ''),
                    pkt.get('protocol', ''),
                    pkt.get('length', ''),
                    pkt.get('info', '')
                ])
        
        return True, f"Successfully exported {len(packets)} packets to CSV"
    except Exception as e:
        return False, f"Error exporting to CSV: {str(e)}"


def export_to_json(filename, data):
    """
    Export data to JSON file
    
    Args:
        filename: Output filename
        data: Dictionary of data to export
            - packets: List of packet info dicts
            - protocol_stats: Protocol statistics
            - ip_stats: IP address statistics
            - port_stats: Port statistics
            - packet_count: Total packet count
            - capture_time: Capture duration
            
    Returns:
        tuple: (success, message)
    """
    try:
        # Prepare data (can't include actual packet objects)
        export_data = {
            "packets": [
                {k: v for k, v in pkt.items() if k != 'packet' and k != 'item_id'} 
                for pkt in data.get('packets', [])
            ],
            "stats": {
                "protocol_stats": dict(data.get('protocol_stats', {})),
                "ip_stats": {ip: dict(stats) for ip, stats in data.get('ip_stats', {}).items()},
                "port_stats": dict(data.get('port_stats', {})),
                "packet_count": data.get('packet_count', 0),
                "capture_time": data.get('capture_time', 0)
            },
            "metadata": {
                "exported_at": time.time(),
                "exporter": "NetworkX"
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        return True, f"Successfully exported data to JSON"
    except Exception as e:
        return False, f"Error exporting to JSON: {str(e)}"


def export_statistics(filename, data, format='csv'):
    """
    Export statistics to a file
    
    Args:
        filename: Output filename
        data: Dictionary of data to export
        format: Output format ('csv' or 'json')
        
    Returns:
        tuple: (success, message)
    """
    if format.lower() == 'csv':
        return export_to_csv(filename, data.get('packets', []))
    elif format.lower() == 'json':
        return export_to_json(filename, data)
    else:
        return False, f"Unsupported format: {format}"