"""
NetworkX - Packet Analyzer Module
Functions and classes for analyzing network packets
"""

from collections import defaultdict
from datetime import datetime
from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP, raw
from scapy.layers import http, dns

from core.constants import COMMON_PORTS


class PacketAnalyzer:
    """Analyzer for network packets - extracts info and maintains statistics"""
    
    def __init__(self):
        """Initialize the packet analyzer"""
        self.reset()
    
    def reset(self):
        """Reset all statistics and counters"""
        # Packet storage and counting
        self.packets = []
        self.packet_count = 0
        self.start_time = None
        
        # Statistics
        self.protocol_stats = defaultdict(int)
        self.ip_stats = defaultdict(lambda: {"sent": 0, "received": 0, "bytes": 0})
        self.port_stats = defaultdict(int)
        self.dns_records = {}
        self.http_requests = []
    
    def extract_packet_info(self, packet):
        """
        Extract basic information from a packet
        
        Args:
            packet: Scapy packet object
            
        Returns:
            tuple: (source, destination, protocol, info)
        """
        src = "Unknown"
        dst = "Unknown"
        protocol = "Unknown"
        info = ""
        
        # Layer 2 - Ethernet
        if Ether in packet:
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
            
            # ARP
            if ARP in packet:
                protocol = "ARP"
                src = packet[ARP].psrc
                dst = packet[ARP].pdst
                op = "request" if packet[ARP].op == 1 else "reply"
                info = f"Who has {dst}? Tell {src}" if op == "request" else f"{src} is at {packet[ARP].hwsrc}"
                
            # IP
            elif IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
                
                # ICMP
                if ICMP in packet:
                    protocol = "ICMP"
                    icmp_type = packet[ICMP].type
                    if icmp_type == 8:
                        info = "Echo (ping) request"
                    elif icmp_type == 0:
                        info = "Echo (ping) reply"
                    else:
                        info = f"Type: {icmp_type}, Code: {packet[ICMP].code}"
                
                # TCP
                elif TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    src = f"{src}:{src_port}"
                    dst = f"{dst}:{dst_port}"
                    
                    # HTTP
                    if (dst_port == 80 or src_port == 80) and packet.haslayer(http.HTTPRequest):
                        protocol = "HTTP"
                        http_layer = packet.getlayer(http.HTTPRequest)
                        host = http_layer.Host.decode() if hasattr(http_layer, 'Host') else ""
                        path = http_layer.Path.decode() if hasattr(http_layer, 'Path') else ""
                        method = http_layer.Method.decode() if hasattr(http_layer, 'Method') else "GET"
                        info = f"{method} {host}{path}"
                        
                    elif (dst_port == 80 or src_port == 80) and packet.haslayer(http.HTTPResponse):
                        protocol = "HTTP"
                        http_layer = packet.getlayer(http.HTTPResponse)
                        status = http_layer.Status_Code if hasattr(http_layer, 'Status_Code') else "?"
                        reason = http_layer.Reason_Phrase.decode() if hasattr(http_layer, 'Reason_Phrase') else ""
                        info = f"Response: {status} {reason}"
                        
                    # HTTPS
                    elif dst_port == 443 or src_port == 443:
                        protocol = "HTTPS"
                        info = "Encrypted data"
                            
                    # Other TCP
                    else:
                        protocol = "TCP"
                        flags = []
                        if packet[TCP].flags & 0x01: flags.append("FIN")
                        if packet[TCP].flags & 0x02: flags.append("SYN")
                        if packet[TCP].flags & 0x04: flags.append("RST")
                        if packet[TCP].flags & 0x08: flags.append("PSH")
                        if packet[TCP].flags & 0x10: flags.append("ACK")
                        if packet[TCP].flags & 0x20: flags.append("URG")
                        
                        flag_str = " ".join(flags)
                        info = f"{flag_str} Seq={packet[TCP].seq} Ack={packet[TCP].ack}"
                        
                        # Add service name if known
                        src_service = COMMON_PORTS.get(src_port, "")
                        dst_service = COMMON_PORTS.get(dst_port, "")
                        
                        if src_service or dst_service:
                            service = src_service or dst_service
                            protocol = f"TCP ({service})"
                
                # UDP
                elif UDP in packet:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    src = f"{src}:{src_port}"
                    dst = f"{dst}:{dst_port}"
                    
                    # DNS
                    if (dst_port == 53 or src_port == 53) and packet.haslayer(dns.DNS):
                        protocol = "DNS"
                        dns_layer = packet.getlayer(dns.DNS)
                        
                        if dns_layer.qr == 0:  # Query
                            if dns_layer.qd:
                                # Handle both single and list-type qd field
                                qd = dns_layer.qd
                                if isinstance(qd, list) and len(qd) > 0:
                                    qd = qd[0]
                                if hasattr(qd, 'qname'):
                                    qname = qd.qname.decode() if isinstance(qd.qname, bytes) else str(qd.qname)
                                    qtype = qd.qtype
                                    qtype_str = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 28: "AAAA"}.get(qtype, str(qtype))
                                    info = f"Standard query {qname} ({qtype_str})"
                                else:
                                    info = "Standard query (unknown)"
                        else:  # Response
                            if dns_layer.qd:
                                # Handle both single and list-type qd field
                                qd = dns_layer.qd
                                if isinstance(qd, list) and len(qd) > 0:
                                    qd = qd[0]
                                if hasattr(qd, 'qname'):
                                    qname = qd.qname.decode() if isinstance(qd.qname, bytes) else str(qd.qname)
                                    info = f"Standard response {qname} (answers: {dns_layer.ancount})"
                                else:
                                    info = f"Standard response (answers: {dns_layer.ancount})"
                    
                    # Other UDP
                    else:
                        protocol = "UDP"
                        
                        # Add service name if known
                        src_service = COMMON_PORTS.get(src_port, "")
                        dst_service = COMMON_PORTS.get(dst_port, "")
                        
                        if src_service or dst_service:
                            service = src_service or dst_service
                            protocol = f"UDP ({service})"
                            
                        info = f"Src Port: {src_port}, Dst Port: {dst_port}"
            
            # Other protocol
            else:
                src = src_mac
                dst = dst_mac
                protocol = f"ETH 0x{packet[Ether].type:04x}"
                info = "Unknown Ethernet protocol"
                
        return src, dst, protocol, info
    
    def process_packet(self, packet, timestamp=None):
        """
        Process a captured packet
        
        Args:
            packet: Scapy packet object
            timestamp: Optional packet timestamp
            
        Returns:
            dict: Processed packet information
        """
        # Increment packet count
        self.packet_count += 1
        
        # Get timestamp if not provided
        if timestamp is None:
            timestamp = packet.time if hasattr(packet, 'time') else datetime.now().timestamp()
        
        # Format time string
        time_str = datetime.fromtimestamp(timestamp).strftime('%H:%M:%S.%f')[:-3]
        
        # Basic packet info
        packet_info = {
            'no': self.packet_count,
            'time': time_str,
            'timestamp': timestamp,
            'packet': packet,
            'length': len(packet)
        }
        
        # Extract source and destination
        src, dst, protocol, info = self.extract_packet_info(packet)
        packet_info['src'] = src
        packet_info['dst'] = dst
        packet_info['protocol'] = protocol
        packet_info['info'] = info
        
        # Store the packet
        self.packets.append(packet_info)
        
        # Update statistics
        self.update_statistics(packet_info)
        
        # Explicitly mark HTTP packets for UI updating
        if 'HTTP' in packet_info['protocol']:
            packet_info['http_updated'] = False
        
        return packet_info
    
    def update_statistics(self, packet_info):
        """
        Update statistics based on the packet
        
        Args:
            packet_info: Dictionary with packet information
        """
        packet = packet_info['packet']
        protocol = packet_info['protocol']
        src = packet_info['src']
        dst = packet_info['dst']
        length = packet_info['length']
        
        # Update protocol statistics
        self.protocol_stats[protocol] += 1
        
        # Update IP statistics (strip port if present)
        src_ip = src.split(':')[0] if ':' in src else src
        dst_ip = dst.split(':')[0] if ':' in dst else dst
        
        # Only count valid IP addresses
        if '.' in src_ip and not src_ip.startswith("Unknown"):
            self.ip_stats[src_ip]['sent'] += 1
            self.ip_stats[src_ip]['bytes'] += length
        
        if '.' in dst_ip and not dst_ip.startswith("Unknown"):
            self.ip_stats[dst_ip]['received'] += 1
            self.ip_stats[dst_ip]['bytes'] += length
        
        # Update port statistics
        if TCP in packet:
            self.port_stats[f"TCP/{packet[TCP].sport}"] += 1
            self.port_stats[f"TCP/{packet[TCP].dport}"] += 1
            
            # Track HTTP requests/responses - improved handling
            if packet.haslayer(http.HTTPRequest):
                http_layer = packet.getlayer(http.HTTPRequest)
                
                # Extract HTTP request details
                method = http_layer.Method.decode() if hasattr(http_layer, 'Method') else "GET"
                host = http_layer.Host.decode() if hasattr(http_layer, 'Host') else ""
                path = http_layer.Path.decode() if hasattr(http_layer, 'Path') else ""
                
                http_info = {
                    'no': packet_info['no'],
                    'time': packet_info['time'],
                    'method': method,
                    'host': host,
                    'path': path,
                    'status': "",
                    'packet_id': id(packet),  # For tracking related response
                    'ui_added': False  # Flag for UI tracking
                }
                
                self.http_requests.append(http_info)
                
            elif packet.haslayer(http.HTTPResponse):
                http_layer = packet.getlayer(http.HTTPResponse)
                status = http_layer.Status_Code if hasattr(http_layer, 'Status_Code') else ""
                reason = http_layer.Reason_Phrase.decode() if hasattr(http_layer, 'Reason_Phrase') else ""
                status_text = f"{status} {reason}".strip()
                
                # Try to match with a request - improved matching logic
                found_match = False
                for req in reversed(self.http_requests):
                    if not req['status'] and dst.split(':')[0] == src.split(':')[0]:
                        req['status'] = status_text
                        req['ui_updated'] = False  # Flag that this needs UI updating
                        found_match = True
                        break
                        
                # If no matching request found, create a standalone response entry
                if not found_match:
                    http_info = {
                        'no': packet_info['no'],
                        'time': packet_info['time'],
                        'method': "RESPONSE",
                        'host': src.split(':')[0] if ':' in src else src,
                        'path': "",
                        'status': status_text,
                        'packet_id': id(packet),
                        'ui_added': False
                    }
                    self.http_requests.append(http_info)
        
        # Track DNS queries/responses - check both protocol string and packet layer
        is_dns = False
        if 'DNS' in protocol:
            is_dns = True
        elif UDP in packet and packet.haslayer(dns.DNS):
            is_dns = True
            
        if is_dns:
            dns_layer = packet.getlayer(dns.DNS)
            
            # Process DNS query
            if dns_layer.qr == 0 and dns_layer.qd:  # Query
                # Handle both single and list-type qd field
                qd = dns_layer.qd
                if isinstance(qd, list) and len(qd) > 0:
                    qd = qd[0]
                    
                if hasattr(qd, 'qname'):
                    try:
                        qname = qd.qname.decode() if isinstance(qd.qname, bytes) else str(qd.qname)
                        
                        # Get query type
                        qtype = qd.qtype
                        qtype_str = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 28: "AAAA"}.get(qtype, str(qtype))
                        
                        dns_info = {
                            'no': packet_info['no'],
                            'time': packet_info['time'],
                            'query': qname,
                            'type': qtype_str,
                            'answers': [],
                            'ttl': 0,
                            'ui_added': False  # Flag for UI tracking
                        }
                        
                        # Add to DNS records
                        self.dns_records[packet_info['no']] = dns_info
                    except Exception as e:
                        print(f"Error processing DNS query: {e}")
            
            # Process DNS response
            elif dns_layer.qr == 1:  # Response
                if dns_layer.qd:
                    # Handle both single and list-type qd field
                    qd = dns_layer.qd
                    if isinstance(qd, list) and len(qd) > 0:
                        qd = qd[0]
                        
                    if hasattr(qd, 'qname'):
                        try:
                            qname = qd.qname.decode() if isinstance(qd.qname, bytes) else str(qd.qname)
                            
                            # Extract answers
                            answers = []
                            ttl = 0
                            
                            if dns_layer.ancount > 0 and hasattr(dns_layer, 'an'):
                                ans = dns_layer.an
                                if not isinstance(ans, list):
                                    ans = [ans]
                                    
                                for an in ans:
                                    if hasattr(an, 'rdata'):
                                        try:
                                            if isinstance(an.rdata, bytes):
                                                rdata = an.rdata.decode(errors='replace')
                                            else:
                                                rdata = str(an.rdata)
                                            answers.append(rdata)
                                            
                                            if hasattr(an, 'ttl'):
                                                ttl = max(ttl, an.ttl)
                                        except Exception:
                                            # Handle any decoding errors
                                            answers.append(str(an.rdata))
                            
                            # Look for matching query
                            match_found = False
                            for packet_id, dns_info in list(self.dns_records.items()):
                                if dns_info['query'] == qname and not dns_info['answers']:
                                    dns_info['answers'] = answers
                                    dns_info['ttl'] = ttl
                                    dns_info['ui_updated'] = False  # Flag that this needs UI updating
                                    match_found = True
                                    break
                            
                            # If no matching query found, create new entry for response
                            if not match_found and answers:
                                dns_info = {
                                    'no': packet_info['no'],
                                    'time': packet_info['time'],
                                    'query': qname,
                                    'type': "A",  # Default type for responses without matching query
                                    'answers': answers,
                                    'ttl': ttl,
                                    'ui_added': False  # Flag for UI tracking
                                }
                                self.dns_records[packet_info['no']] = dns_info
                        except Exception as e:
                            print(f"Error processing DNS response: {e}")
    
    def get_packet_details(self, packet_info):
        """
        Generate detailed information about a packet for display
        
        Args:
            packet_info: Dictionary with packet information
            
        Returns:
            tuple: (details_text, hex_dump)
        """
        packet = packet_info['packet']
        details = []
        
        # Basic info
        details.append(f"Packet #{packet_info['no']}")
        details.append(f"Time: {packet_info['time']}")
        details.append(f"Length: {packet_info['length']} bytes")
        details.append("")
        
        # Protocol info
        details.append(f"Protocol: {packet_info['protocol']}")
        details.append(f"Source: {packet_info['src']}")
        details.append(f"Destination: {packet_info['dst']}")
        details.append(f"Info: {packet_info['info']}")
        details.append("")
        
        # Ethernet layer
        if Ether in packet:
            details.append("Ethernet:")
            details.append(f"  Source MAC: {packet[Ether].src}")
            details.append(f"  Destination MAC: {packet[Ether].dst}")
            details.append(f"  Type: 0x{packet[Ether].type:04x}")
            details.append("")
        
        # IP layer
        if IP in packet:
            details.append("Internet Protocol:")
            details.append(f"  Version: {packet[IP].version}")
            details.append(f"  TTL: {packet[IP].ttl}")
            details.append(f"  Protocol: {packet[IP].proto}")
            details.append(f"  Source IP: {packet[IP].src}")
            details.append(f"  Destination IP: {packet[IP].dst}")
            details.append("")
        
        # TCP layer
        if TCP in packet:
            details.append("Transmission Control Protocol:")
            details.append(f"  Source Port: {packet[TCP].sport}")
            details.append(f"  Destination Port: {packet[TCP].dport}")
            details.append(f"  Sequence Number: {packet[TCP].seq}")
            details.append(f"  Acknowledgment: {packet[TCP].ack}")
            
            # Flags
            flags = []
            if packet[TCP].flags & 0x01: flags.append("FIN")
            if packet[TCP].flags & 0x02: flags.append("SYN")
            if packet[TCP].flags & 0x04: flags.append("RST")
            if packet[TCP].flags & 0x08: flags.append("PSH")
            if packet[TCP].flags & 0x10: flags.append("ACK")
            if packet[TCP].flags & 0x20: flags.append("URG")
            
            details.append(f"  Flags: {' '.join(flags)}")
            details.append(f"  Window Size: {packet[TCP].window}")
            details.append("")
            
            # HTTP layer
            if packet.haslayer(http.HTTPRequest):
                http_layer = packet.getlayer(http.HTTPRequest)
                details.append("HTTP Request:")
                
                for field in http_layer.fields:
                    if not field.startswith('_'):
                        value = getattr(http_layer, field)
                        if isinstance(value, bytes):
                            try:
                                value = value.decode(errors='replace')
                            except Exception:
                                value = str(value)
                        details.append(f"  {field}: {value}")
                details.append("")
                
            elif packet.haslayer(http.HTTPResponse):
                http_layer = packet.getlayer(http.HTTPResponse)
                details.append("HTTP Response:")
                
                for field in http_layer.fields:
                    if not field.startswith('_'):
                        value = getattr(http_layer, field)
                        if isinstance(value, bytes):
                            try:
                                value = value.decode(errors='replace')
                            except Exception:
                                value = str(value)
                        details.append(f"  {field}: {value}")
                details.append("")
        
        # UDP layer
        elif UDP in packet:
            details.append("User Datagram Protocol:")
            details.append(f"  Source Port: {packet[UDP].sport}")
            details.append(f"  Destination Port: {packet[UDP].dport}")
            details.append(f"  Length: {packet[UDP].len} bytes")
            details.append("")
            
            # DNS layer
            if packet.haslayer(dns.DNS):
                dns_layer = packet.getlayer(dns.DNS)
                details.append("Domain Name System:")
                details.append(f"  Transaction ID: 0x{dns_layer.id:04x}")
                details.append(f"  Type: {'Response' if dns_layer.qr else 'Query'}")
                
                # Display queries
                if dns_layer.qd:
                    details.append("  Queries:")
                    queries = dns_layer.qd if isinstance(dns_layer.qd, list) else [dns_layer.qd]
                    
                    for qd in queries:
                        if hasattr(qd, 'qname'):
                            qname = qd.qname.decode() if isinstance(qd.qname, bytes) else str(qd.qname)
                            qtype = qd.qtype
                            qtype_str = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 28: "AAAA"}.get(qtype, str(qtype))
                            details.append(f"    {qname} ({qtype_str})")
                
                # Display answers
                if dns_layer.ancount > 0 and hasattr(dns_layer, 'an'):
                    details.append("  Answers:")
                    answers = dns_layer.an if isinstance(dns_layer.an, list) else [dns_layer.an]
                    
                    for an in answers:
                        if hasattr(an, 'rrname'):
                            name = an.rrname.decode() if isinstance(an.rrname, bytes) else str(an.rrname)
                            
                            if hasattr(an, 'rdata'):
                                try:
                                    if isinstance(an.rdata, bytes):
                                        rdata = an.rdata.decode(errors='replace')
                                    else:
                                        rdata = str(an.rdata)
                                    
                                    ttl = an.ttl if hasattr(an, 'ttl') else 0
                                    details.append(f"    {name}: {rdata} (TTL: {ttl})")
                                except Exception:
                                    rdata = str(an.rdata)
                                    ttl = an.ttl if hasattr(an, 'ttl') else 0
                                    details.append(f"    {name}: {rdata} (TTL: {ttl})")
                
                details.append("")
        
        # ARP layer
        elif ARP in packet:
            details.append("Address Resolution Protocol:")
            details.append(f"  Operation: {'request' if packet[ARP].op == 1 else 'reply'}")
            details.append(f"  Sender MAC: {packet[ARP].hwsrc}")
            details.append(f"  Sender IP: {packet[ARP].psrc}")
            details.append(f"  Target MAC: {packet[ARP].hwdst}")
            details.append(f"  Target IP: {packet[ARP].pdst}")
            details.append("")
        
        # Generate hex dump
        hex_dump = []
        try:
            raw_packet = raw(packet)
            
            # Format in hex dump style (offset, hex, ascii)
            for i in range(0, len(raw_packet), 16):
                chunk = raw_packet[i:i+16]
                
                # Format hex part
                hex_part = " ".join(f"{b:02x}" for b in chunk)
                hex_part = hex_part.ljust(47)  # Pad to align ASCII
                
                # Format ASCII part
                ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                
                # Add line to hex view
                hex_dump.append(f"{i:04x}:  {hex_part}  |{ascii_part}|")
                
        except Exception as e:
            hex_dump.append(f"Error displaying hex data: {str(e)}")
            
        return "\n".join(details), "\n".join(hex_dump)