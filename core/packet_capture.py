"""
NetworkX - Packet Capture Module
Functions and classes for capturing network packets
"""

import threading
import time
from datetime import datetime

# Scapy imports
try:
    from scapy.all import sniff, get_if_list
    from scapy.arch import get_if_list
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


class PacketCapture:
    """Class for capturing network packets"""
    
    def __init__(self, packet_callback):
        """
        Initialize the packet capture
        
        Args:
            packet_callback: Function called when a packet is captured
        """
        self.running = False
        self.capture_thread = None
        self.start_time = None
        self.packet_callback = packet_callback
    
    def get_interfaces(self):
        """
        Get a list of available network interfaces
        
        Returns:
            list: Available interfaces
        """
        if not HAS_SCAPY:
            return []
            
        try:
            return get_if_list()
        except Exception:
            return []
    
    def start(self, interface, bpf_filter=""):
        """
        Start packet capture on the specified interface
        
        Args:
            interface: Network interface to capture on
            bpf_filter: BPF filter string
            
        Returns:
            bool: True if capture started successfully, False otherwise
        """
        if self.running:
            return False
            
        if not HAS_SCAPY:
            return False
            
        self.running = True
        self.start_time = time.time()
        
        # Start capture thread
        self.capture_thread = threading.Thread(
            target=self._capture_thread,
            args=(interface, bpf_filter),
            daemon=True
        )
        self.capture_thread.start()
        
        return True
    
    def stop(self):
        """
        Stop packet capture
        
        Returns:
            bool: True if capture was stopped, False if not running
        """
        if not self.running:
            return False
            
        self.running = False
        
        # Wait for capture thread to finish
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=1.0)
            
        return True
    
    def is_running(self):
        """
        Check if capture is running
        
        Returns:
            bool: True if capture is running
        """
        return self.running
    
    def _capture_thread(self, interface, bpf_filter):
        """
        Thread function for packet capture
        
        Args:
            interface: Network interface to capture on
            bpf_filter: BPF filter string
        """
        try:
            # Use Scapy's sniff function
            sniff(
                iface=interface,
                filter=bpf_filter if bpf_filter else None,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda x: not self.running
            )
        except Exception as e:
            self.running = False
            # Pass error to callback
            self.packet_callback(None, error=str(e))
    
    def _process_packet(self, packet):
        """
        Process a captured packet and pass to callback
        
        Args:
            packet: Scapy packet object
        """
        if not self.running:
            return
            
        # Get timestamp
        timestamp = time.time()
        
        # Pass to callback
        self.packet_callback(packet, timestamp=timestamp)