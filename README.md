# Router Security Tool

A Python-based tool for connecting to and assessing the security of network devices (routers, switches, wireless routers) via USB/console or SSH connections.

## Features

### Core Functionality
- **Connection Detection**: Auto-detect USB/serial ports and network interfaces
- **Multiple Connection Types**: Support for serial/USB console and SSH connections
- **Vulnerability Scanning**: Comprehensive port scanning and service detection
- **Security Assessment**: Advanced vulnerability analysis with CVE database integration
- **Real-time GUI**: PyQt5-based interface with progress tracking and notifications

### Phase 2 Features ✅
- **Report Export**: Export scan results to JSON, HTML, and PDF formats
- **Scan History**: SQLite database storing all historical scans
- **History Viewer**: Interactive UI to view, filter, and compare past scans
- **Demo Mode**: Test functionality with realistic mock data
- **Statistics Dashboard**: Overview of scan history and trends

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

1. **Scan for Connections**: Click "Scan for Connections" to detect available network devices
2. **Demo Mode** (optional): Click "Demo Mode" to test with mock data without real devices
3. **Select Connection**: Choose a connection from the detected list
4. **Enter Credentials**: Provide username and password for the target device (if connecting)
5. **Connect**: Establish connection to the device
6. **Run Vulnerability Scan**: Click "Run Vulnerability Scan" to analyze security
7. **View Results**: See detailed vulnerability report with risk scores and recommendations
8. **Export Report**: Export results to JSON, HTML, or PDF format
9. **View History**: Check past scans in the History tab

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
├── main.py                      # Application entry point
├── requirements.txt             # Python dependencies
├── src/
│   ├── connections/            # Connection management
│   │   ├── detector.py         # Port/network detection
│   │   └── manager.py          # Connection handling
│   ├── assessment/             # Security assessment
│   │   ├── vulnerability_scanner.py  # Vulnerability scanning
│   │   └── service_scanner.py  # Port and service detection
│   ├── database/               # Data persistence
│   │   ├── scan_history.py     # SQLite scan history
│   │   └── cve_manager.py      # CVE database management
│   ├── gui/                    # PyQt5 interface
│   │   └── main_window.py      # Main application window
│   ├── reports/                # Report generation
│   │   └── export.py           # JSON/HTML/PDF export
│   ├── utils/                  # Utilities
│   │   └── mock_data.py        # Mock data generator
│   └── scraper/                # File system exploration
│       └── filesystem.py       # Directory scanning
├── scripts/                    # Utility scripts
│   └── populate_history.py     # Seed database with test data
├── data/                       # Database files (gitignored)
├── tests/                      # Unit tests
└── docs/                       # Documentation
```

### Phase Development Plan

#### Phase 1 ✅
- Connection detection and management
- Basic GUI framework
- File system scraping
- Initial security checks

#### Phase 2 ✅
- Advanced security assessment engine
- Vulnerability scanning with service detection
- CVE database integration
- Export functionality (JSON/HTML/PDF)
- Scan history database
- History viewer UI
- Demo mode for testing

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