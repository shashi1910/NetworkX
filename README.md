# NetworkX - Network Packet Analyzer

NetworkX is a lightweight yet powerful network packet analyzer with an intuitive graphical interface. It provides real-time capture, analysis, and visualization of network traffic.

## Features

- Live packet capture with BPF filtering
- Detailed packet inspection
- Protocol statistics
- IP address analysis
- DNS query monitoring
- HTTP transaction tracking
- Save and load PCAP files
- Export statistics to CSV/JSON
- Dark mode support

## Requirements

- Python 3.6 or higher
- Scapy library
- Tkinter (included with most Python distributions)

## Installation

1. Clone the repository:

   ```
   git clone https://github.com/yourusername/networkx.git
   cd networkx
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

Run the application:

```
python app.py
```

### Capture Options

1. Select a network interface from the dropdown menu
2. Optionally set a BPF filter (click the "?" button for help)
3. Click "Start Capture" to begin capturing packets
4. Click "Stop Capture" to stop

### Analysis Features

- **Packets Tab**: View and inspect captured packets
- **Statistics Tab**: View protocol and IP address statistics
- **DNS Tab**: Monitor DNS queries and responses
- **HTTP Tab**: Track HTTP requests and responses

### File Operations

- **Open PCAP**: Load packets from a PCAP file
- **Save PCAP**: Save captured packets to a PCAP file
- **Export Statistics**: Export data to CSV or JSON format

## Project Structure

```
networkx/
├── app.py                  # Main entry point
├── requirements.txt        # Dependencies
├── README.md               # Project documentation
├── core/                   # Core functionality
│   ├── __init__.py
│   ├── packet_capture.py   # Packet capture and processing
│   ├── packet_analyzer.py  # Packet analysis and statistics
│   └── constants.py        # Shared constants (ports, colors, etc.)
├── ui/                     # User interface components
│   ├── __init__.py
│   ├── main_window.py      # Main application window
│   ├── packet_view.py      # Packet list and details view
│   ├── statistics_view.py  # Statistics views
│   ├── http_view.py        # HTTP requests/responses view
│   ├── dns_view.py         # DNS queries/responses view
│   └── dialogs.py          # Helper dialogs (filter helper, about)
└── utils/                  # Utility functions
    ├── __init__.py
    ├── formatting.py       # Formatting utilities
    ├── pcap_handler.py     # PCAP file operations
    └── export.py           # Export functionality
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built with [Scapy](https://scapy.net/) for packet manipulation
- Uses Python's Tkinter for the user interface
