# Router Security Tool

A Python-based tool for connecting to and assessing the security of network devices (routers, switches, wireless routers) via USB/console or SSH connections.

## Features

- **Connection Detection**: Auto-detect USB/serial ports and network interfaces
- **Multiple Connection Types**: Support for serial/USB console and SSH connections
- **File System Exploration**: Scrape and analyze Linux-based device file systems
- **Security Assessment**: Preliminary security analysis and vulnerability detection
- **Real-time GUI**: PyQt5-based interface with progress tracking
- **Report Generation**: Detailed security assessment reports

## Supported Devices

- Cisco routers and switches
- Linksys routers
- TP-Link devices
- Netgear equipment
- Other Linux-based network devices

## Installation

### Prerequisites

- Python 3.7 or higher
- macOS (for .dmg packaging)

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd router-security-tool
```

2. Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On macOS/Linux
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Running the Tool

```bash
python main.py
```

### Basic Workflow

1. **Scan for Connections**: Click "Scan for Connections" to detect available USB/serial ports and network interfaces
2. **Select Connection**: Choose a connection from the detected list
3. **Enter Credentials**: Provide username and password for the target device
4. **Connect**: Establish connection to the device
5. **Scan File System**: Start file system exploration and analysis
6. **Generate Report**: Create a detailed security assessment report

### Connection Types

#### Serial/USB Console
- Auto-detects FTDI, Prolific, CP210x, CH340 adapters
- Supports common baud rates (9600, 115200, etc.)
- Fallback parameter detection

#### SSH Network
- Scans common router IP addresses
- Tests SSH (port 22) and Telnet (port 23)
- Authentication via username/password

## Development

### Project Structure

```
router-security-tool/
├── main.py                 # Application entry point
├── requirements.txt        # Python dependencies
├── src/
│   ├── connections/       # Connection management
│   │   ├── detector.py    # Port/network detection
│   │   └── manager.py     # Connection handling
│   ├── gui/              # PyQt5 interface
│   │   └── main_window.py # Main application window
│   ├── scraper/          # File system exploration
│   │   └── filesystem.py  # Directory scanning and analysis
│   ├── auth/             # Authentication handling
│   └── reports/          # Report generation
├── tests/                # Unit tests
└── docs/                 # Documentation
```

### Phase Development Plan

#### Phase 1 (Current) ✅
- Connection detection and management
- Basic GUI framework
- File system scraping
- Initial security checks

#### Phase 2 (Next)
- Advanced security assessment engine
- Vulnerability scanning
- Configuration analysis
- Enhanced reporting

#### Phase 3 (Future)
- Device-specific modules
- Manufacturer-specific checks
- Advanced exploitation detection
- Custom assessment rules

## Testing

Run the test suite:
```bash
pytest tests/
```

## Building for Distribution

### macOS .dmg Package

```bash
python setup.py py2app
```

## Security Considerations

This tool is intended for:
- Authorized security assessments
- Network device auditing
- Educational purposes

**Important**: Only use this tool on devices you own or have explicit permission to test.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

[License details to be added]

## Acknowledgments

- Built with PyQt5 for the GUI framework
- Uses pyserial for USB/serial communication
- SSH connections via paramiko library