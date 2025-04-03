"""
NetworkX - PCAP Handler Module
Functions for reading and writing PCAP files
"""

import os
import threading

try:
    from scapy.all import rdpcap, wrpcap
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


def read_pcap(filename, callback, progress_callback=None):
    """
    Read packets from a PCAP file
    
    Args:
        filename: Path to PCAP file
        callback: Function to call for each packet (packet, error)
        progress_callback: Optional function to report progress (current, total)
        
    Returns:
        bool: True if file reading started, False on error
    """
    if not HAS_SCAPY or not os.path.exists(filename):
        callback(None, error=f"File not found: {filename}")
        return False
    
    # Start reading in a thread
    thread = threading.Thread(
        target=_read_pcap_thread,
        args=(filename, callback, progress_callback),
        daemon=True
    )
    thread.start()
    
    return True


def _read_pcap_thread(filename, callback, progress_callback):
    """
    Thread function for reading PCAP file
    
    Args:
        filename: Path to PCAP file
        callback: Function to call for each packet (packet, error)
        progress_callback: Optional function to report progress (current, total)
    """
    try:
        # Read the PCAP file
        packets = rdpcap(filename)
        total = len(packets)
        
        # Report total packet count
        if progress_callback:
            progress_callback(0, total)
        
        # Process each packet
        for i, packet in enumerate(packets):
            # Send to callback
            if not callback(packet):
                break  # Stop if callback returns False
            
            # Update progress
            if progress_callback and i % 100 == 0:
                progress_callback(i, total)
        
        # Final progress update
        if progress_callback:
            progress_callback(total, total)
            
        # Signal completion
        callback(None, completed=True)
        
    except Exception as e:
        callback(None, error=str(e))


def write_pcap(filename, packets):
    """
    Write packets to a PCAP file
    
    Args:
        filename: Path to output PCAP file
        packets: List of packet objects or packet_info dicts
        
    Returns:
        tuple: (success, error_message)
    """
    if not HAS_SCAPY:
        return False, "Scapy library not available"
    
    try:
        # Extract actual packet objects if needed
        packet_list = []
        for pkt in packets:
            if isinstance(pkt, dict) and 'packet' in pkt:
                packet_list.append(pkt['packet'])
            else:
                packet_list.append(pkt)
        
        # Write to PCAP file
        wrpcap(filename, packet_list)
        return True, f"Successfully saved {len(packet_list)} packets"
        
    except Exception as e:
        return False, f"Error saving PCAP: {str(e)}"