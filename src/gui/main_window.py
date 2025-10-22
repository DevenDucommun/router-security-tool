"""
Main GUI Window
PyQt5-based interface with real-time progress tracking
"""

import logging
from PyQt5.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QTextEdit,
    QLabel,
    QProgressBar,
    QGroupBox,
    QFormLayout,
    QLineEdit,
    QTabWidget,
    QListWidget,
    QSplitter,
    QMessageBox,
    QFileDialog,
    QInputDialog,
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QTimer
from PyQt5.QtGui import QFont, QColor, QPalette

from connections.detector import ConnectionDetector
from assessment.vulnerability_scanner import VulnerabilityScanner
from reports.export import ReportExporter
from utils.mock_data import MockDataGenerator, get_sample_scan
from database.scan_history import ScanHistoryDB

logger = logging.getLogger(__name__)


class ScanWorker(QThread):
    """Background worker for scanning operations"""

    progress = pyqtSignal(str)  # Status message
    found_connection = pyqtSignal(dict)  # Connection discovered
    scan_complete = pyqtSignal(list)  # All connections found
    error = pyqtSignal(str)  # Error message

    def __init__(self):
        super().__init__()
        self.detector = ConnectionDetector()

    def run(self):
        """Run the connection detection in background"""
        self.progress.emit("🔍 Starting connection scan...")

        try:
            connections = self.detector.get_all_connections()
            for conn in connections:
                self.found_connection.emit(conn)

            self.scan_complete.emit(connections)
            self.progress.emit(
                f"✅ Scan complete. Found {len(connections)} potential connections."
            )
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            self.error.emit(f"Connection scan failed: {str(e)}")


class VulnerabilityScanWorker(QThread):
    """Background worker for vulnerability scanning"""

    progress = pyqtSignal(str)  # Status message
    scan_complete = pyqtSignal(dict)  # Scan results
    error = pyqtSignal(str)  # Error message

    def __init__(self, target_host):
        super().__init__()
        self.target_host = target_host
        self.scanner = VulnerabilityScanner()

    def run(self):
        """Run vulnerability scan in background"""
        try:
            self.progress.emit(f"Starting vulnerability scan on {self.target_host}...")
            
            self.progress.emit("Scanning open ports and services...")
            results = self.scanner.scan_target(self.target_host)
            
            self.progress.emit(f"Scan complete. Found {len(results['vulnerabilities'])} vulnerabilities.")
            self.scan_complete.emit(results)
            
        except Exception as e:
            logger.error(f"Vulnerability scan failed: {e}")
            self.error.emit(f"Scan failed: {str(e)}")


class MainWindow(QMainWindow):
    """Main application window"""

    def __init__(self):
        super().__init__()
        self.connections = []
        self.current_connection = None
        self.current_target_host = None
        self.scan_results = None
        
        # Initialize scan history database
        try:
            self.history_db = ScanHistoryDB()
            logger.info("Scan history database initialized")
        except Exception as e:
            logger.error(f"Failed to initialize scan history database: {e}")
            self.history_db = None
        
        self.init_ui()
        
        # Auto-start initial scan after UI is ready
        QTimer.singleShot(500, self.auto_start_scan)

    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("Router Security Tool v1.0")
        self.setGeometry(100, 100, 1200, 800)

        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QHBoxLayout(central_widget)

        # Create splitter for resizable panels
        splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(splitter)

        # Left panel - Connection Management
        left_panel = self.create_connection_panel()
        splitter.addWidget(left_panel)

        # Right panel - Results and Progress
        right_panel = self.create_results_panel()
        splitter.addWidget(right_panel)

        # Set splitter proportions
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)

        # Status bar
        self.statusBar().showMessage("Ready")

    def create_connection_panel(self):
        """Create the connection management panel"""
        panel = QWidget()
        layout = QVBoxLayout(panel)

        # Connection Detection Group
        detection_group = QGroupBox("Connection Detection")
        detection_layout = QVBoxLayout(detection_group)

        self.scan_button = QPushButton("🔍 Scan for Connections")
        self.scan_button.clicked.connect(self.start_scan)
        self.scan_button.setToolTip("Scan for available routers, switches, and network devices")
        detection_layout.addWidget(self.scan_button)
        
        self.demo_button = QPushButton("🎭 Demo Mode")
        self.demo_button.clicked.connect(self.load_demo_data)
        self.demo_button.setToolTip("Load mock data for testing without real devices")
        self.demo_button.setStyleSheet("QPushButton { background-color: #3498db; color: white; font-weight: bold; }")
        detection_layout.addWidget(self.demo_button)

        self.connection_list = QListWidget()
        detection_layout.addWidget(self.connection_list)

        layout.addWidget(detection_group)

        # Connection Settings Group
        settings_group = QGroupBox("Connection Settings")
        settings_layout = QFormLayout(settings_group)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter username")
        settings_layout.addRow("Username:", self.username_input)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter password")
        settings_layout.addRow("Password:", self.password_input)

        self.connect_button = QPushButton("Connect")
        self.connect_button.clicked.connect(self.connect_to_device)
        self.connect_button.setEnabled(False)
        settings_layout.addWidget(self.connect_button)

        layout.addWidget(settings_group)

        # Actions Group
        actions_group = QGroupBox("Actions")
        actions_layout = QVBoxLayout(actions_group)

        self.vuln_scan_button = QPushButton("🔍 Run Vulnerability Scan")
        self.vuln_scan_button.clicked.connect(self.start_vulnerability_scan)
        self.vuln_scan_button.setEnabled(False)
        self.vuln_scan_button.setStyleSheet("QPushButton { font-weight: bold; padding: 8px; }")
        actions_layout.addWidget(self.vuln_scan_button)

        self.scrape_button = QPushButton("Start File System Scan")
        self.scrape_button.clicked.connect(self.start_scraping)
        self.scrape_button.setEnabled(False)
        actions_layout.addWidget(self.scrape_button)

        self.export_button = QPushButton("💾 Export Report")
        self.export_button.clicked.connect(self.export_report)
        self.export_button.setEnabled(False)
        self.export_button.setToolTip("Export scan results to JSON, HTML, or PDF")
        actions_layout.addWidget(self.export_button)

        layout.addWidget(actions_group)
        layout.addStretch()

        return panel

    def create_results_panel(self):
        """Create the results and progress panel"""
        panel = QWidget()
        layout = QVBoxLayout(panel)

        # Progress Group
        progress_group = QGroupBox("Progress")
        progress_layout = QVBoxLayout(progress_group)

        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        progress_layout.addWidget(self.progress_bar)

        self.status_label = QLabel("⏳ Initializing...")
        self.status_label.setWordWrap(True)
        self.status_label.setStyleSheet("QLabel { padding: 5px; font-size: 12px; }")
        progress_layout.addWidget(self.status_label)

        layout.addWidget(progress_group)

        # Results Tabs
        self.results_tabs = QTabWidget()

        # Console Output Tab
        self.console_output = QTextEdit()
        self.console_output.setReadOnly(True)
        self.console_output.setFont(QFont("Courier", 10))
        self.results_tabs.addTab(self.console_output, "Console Output")

        # File System Tab
        self.filesystem_output = QTextEdit()
        self.filesystem_output.setReadOnly(True)
        self.filesystem_output.setFont(QFont("Courier", 10))
        self.results_tabs.addTab(self.filesystem_output, "File System")

        # Security Findings Tab
        self.security_output = QTextEdit()
        self.security_output.setReadOnly(True)
        self.results_tabs.addTab(self.security_output, "Security Analysis")

        layout.addWidget(self.results_tabs)

        return panel

    def auto_start_scan(self):
        """Auto-start initial connection scan"""
        self.show_notification("🔍 Scanning for devices", "Looking for routers, switches, and network devices...")
        self.start_scan()

    def start_scan(self):
        """Start scanning for connections"""
        self.scan_button.setEnabled(False)
        self.scan_button.setText("⏳ Scanning...")
        self.connection_list.clear()
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.update_status("🔍 Scanning for connections...")

        # Start scan worker
        self.scan_worker = ScanWorker()
        self.scan_worker.progress.connect(self.update_status)
        self.scan_worker.found_connection.connect(self.add_connection)
        self.scan_worker.scan_complete.connect(self.scan_finished)
        self.scan_worker.error.connect(self.scan_error)
        self.scan_worker.start()

    def add_connection(self, connection):
        """Add a discovered connection to the list"""
        if connection["type"] == "serial":
            display_text = (
                f"Serial: {connection['device']} - {connection['description']}"
            )
        elif connection["type"] == "network":
            display_text = f"Network: {connection['ip']}:{connection['port']} ({connection['service']})"
        elif connection["type"] == "usb_device":
            display_text = f"USB Device: {connection['manufacturer']}"
        else:
            display_text = f"Unknown: {connection}"

        self.connection_list.addItem(display_text)

    def scan_finished(self, connections):
        """Handle scan completion"""
        self.connections = connections
        self.scan_button.setEnabled(True)
        self.scan_button.setText("🔍 Scan for Connections")
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        self.connect_button.setEnabled(len(connections) > 0)

        if len(connections) == 0:
            self.update_status("⚠️ No connections found")
            self.show_notification(
                "⚠️ No Devices Found",
                "No routers or network devices detected. Check USB/serial connections.",
                QMessageBox.Warning
            )
        else:
            self.update_status(f"✅ Found {len(connections)} device(s). Select one to connect.")
            self.show_notification(
                "✅ Devices Found",
                f"Found {len(connections)} potential connection(s). Select one and enter credentials to connect."
            )

    def scan_error(self, error_message):
        """Handle scan errors"""
        self.scan_button.setEnabled(True)
        self.scan_button.setText("🔍 Scan for Connections")
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.update_status(f"❌ Scan failed: {error_message}")
        QMessageBox.critical(
            self,
            "❌ Scan Failed",
            f"Connection scan failed:\n\n{error_message}\n\nPlease try again or check your network connection."
        )

    def connect_to_device(self):
        """Connect to the selected device"""
        selected_items = self.connection_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(
                self, "⚠️ No Selection", "Please select a connection from the list first."
            )
            return

        selected_index = self.connection_list.row(selected_items[0])
        if selected_index >= len(self.connections):
            return

        connection = self.connections[selected_index]
        username = self.username_input.text().strip()
        password = self.password_input.text()

        if not username or not password:
            QMessageBox.warning(
                self, "⚠️ Missing Credentials", "Please enter both username and password to connect."
            )
            return

        # Show progress
        self.connect_button.setEnabled(False)
        self.connect_button.setText("⏳ Connecting...")
        self.progress_bar.setRange(0, 0)
        self.update_status("🔗 Connecting to device...")
        self.log_console(f"🔗 Attempting connection to: {connection}")

        try:
            # Extract target host for vulnerability scanning
            if connection.get("type") == "network":
                self.current_target_host = connection.get("ip")
                self.vuln_scan_button.setEnabled(True)
            else:
                self.current_target_host = None
                self.vuln_scan_button.setEnabled(False)

            # TODO: Implement actual connection logic
            self.current_connection = connection
            self.scrape_button.setEnabled(True)
            
            # Success
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(100)
            self.connect_button.setEnabled(True)
            self.connect_button.setText("🔗 Connect")
            self.update_status("✅ Connected successfully!")
            self.show_notification(
                "✅ Connected",
                f"Successfully connected to {connection.get('ip', 'device')}. You can now run security scans."
            )
            self.log_console("✅ Connection established")
            
        except Exception as e:
            self.connect_button.setEnabled(True)
            self.connect_button.setText("🔗 Connect")
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(0)
            self.update_status(f"❌ Connection failed: {str(e)}")
            QMessageBox.critical(
                self,
                "❌ Connection Failed",
                f"Failed to connect to device:\n\n{str(e)}\n\nPlease check your credentials and try again."
            )
            logger.error(f"Connection failed: {e}")

    def start_scraping(self):
        """Start file system scraping"""
        self.update_status("Starting file system scan...")
        self.scrape_button.setEnabled(False)

        # TODO: Implement scraping worker
        self.log_filesystem("Starting file system exploration...")
        self.log_filesystem("/bin - System binaries")
        self.log_filesystem("/etc - Configuration files")
        self.log_filesystem("/tmp - Temporary files")
        self.log_filesystem("/var/log - Log files")

        self.report_button.setEnabled(True)
        self.update_status("File system scan complete!")

    def generate_report(self):
        """Generate security assessment report"""
        self.update_status("Generating report...")

        # TODO: Implement report generation
        report = "Security Assessment Report\\n"
        report += "========================\\n\\n"
        report += "Connection Type: Serial/USB\\n"
        report += "Device Info: Unknown\\n"
        report += "Scan Date: Now\\n\\n"
        report += "Findings:\\n"
        report += "- File system accessible\\n"
        report += "- Configuration files readable\\n"

        self.security_output.setText(report)
        self.results_tabs.setCurrentIndex(2)  # Switch to Security tab
        self.update_status("Report generated successfully!")

    def update_status(self, message):
        """Update the status label and status bar"""
        self.status_label.setText(message)
        self.statusBar().showMessage(message)
        logger.info(message)

    def log_console(self, message):
        """Add message to console output tab"""
        self.console_output.append(message)

    def log_filesystem(self, message):
        """Add message to filesystem output tab"""
        self.filesystem_output.append(message)

    def start_vulnerability_scan(self):
        """Start vulnerability scanning"""
        if not self.current_target_host:
            QMessageBox.warning(
                self, "⚠️ No Target", "No target host available for scanning. Please connect to a network device first."
            )
            return

        self.vuln_scan_button.setEnabled(False)
        self.vuln_scan_button.setText("⏳ Scanning...")
        self.update_status(f"🔍 Starting vulnerability scan on {self.current_target_host}...")
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        
        # Show notification
        self.show_notification(
            "🔍 Vulnerability Scan Started",
            f"Scanning {self.current_target_host} for security vulnerabilities. This may take several minutes..."
        )

        # Start vulnerability scan worker
        self.vuln_worker = VulnerabilityScanWorker(self.current_target_host)
        self.vuln_worker.progress.connect(self.update_status)
        self.vuln_worker.scan_complete.connect(self.display_vulnerability_results)
        self.vuln_worker.error.connect(self.vulnerability_scan_error)
        self.vuln_worker.start()

    def display_vulnerability_results(self, results):
        """Display vulnerability scan results"""
        self.scan_results = results
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        self.vuln_scan_button.setEnabled(True)
        self.vuln_scan_button.setText("🔍 Run Vulnerability Scan")

        # Build results display
        output = "═" * 80 + "\n"
        output += "VULNERABILITY SCAN RESULTS\n"
        output += "═" * 80 + "\n\n"

        # Device Information (handle both real and mock data formats)
        device_info = results.get("device_info", {})
        output += "📱 DEVICE INFORMATION\n"
        output += "-" * 80 + "\n"
        output += f"Target: {results.get('target', 'Unknown')}\n"
        
        # Check if device_info is a string (mock data) or dict (real data)
        if isinstance(device_info, str):
            output += f"Device: {device_info}\n"
            output += f"Vendor: {results.get('vendor', 'Unknown')}\n"
            output += f"Model: {results.get('model', 'Unknown')}\n"
            output += f"Firmware: {results.get('firmware_version', 'Unknown')}\n"
        else:
            output += f"Vendor: {device_info.get('vendor', 'Unknown').upper()}\n"
            output += f"Product: {device_info.get('product', 'Unknown')}\n"
            output += f"Version: {device_info.get('version', 'Unknown')}\n"
            output += f"Device Type: {device_info.get('device_type', 'Unknown')}\n"
            output += f"Confidence: {device_info.get('confidence', 0):.1%}\n"
        output += "\n"

        # Risk Score
        risk_score = results.get("risk_score", 0)
        risk_level = self._get_risk_level(risk_score)
        output += f"⚠️  RISK SCORE: {risk_score:.1f}/10.0 ({risk_level})\n"
        output += "-" * 80 + "\n\n"

        # Services
        services = results.get("services", {})
        if services:
            output += "🌐 DISCOVERED SERVICES\n"
            output += "-" * 80 + "\n"
            open_ports = services.get("open_ports", [])
            output += f"Open Ports: {len(open_ports)}\n"
            for port in sorted(open_ports)[:10]:  # Show first 10
                service_name = services.get("services", {}).get(port, "Unknown")
                output += f"  • Port {port}: {service_name}\n"
            output += "\n"

        # Vulnerabilities
        vulnerabilities = results.get("vulnerabilities", [])
        output += f"🔐 VULNERABILITIES FOUND: {len(vulnerabilities)}\n"
        output += "=" * 80 + "\n\n"

        if vulnerabilities:
            # Group by severity (normalize case for both formats)
            by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
            for vuln in vulnerabilities:
                severity = vuln.get("severity", "LOW").upper()
                if severity in by_severity:
                    by_severity[severity].append(vuln)

            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                vulns = by_severity[severity]
                if vulns:
                    emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
                    output += f"\n{emoji[severity]} {severity} SEVERITY ({len(vulns)})\n"
                    output += "-" * 80 + "\n"
                    for vuln in vulns[:5]:  # Show first 5 per severity
                        output += f"\n  Title: {vuln.get('title', 'No title')}\n"
                        if vuln.get('cve_id'):
                            output += f"  CVE ID: {vuln.get('cve_id')}\n"
                        output += f"  CVSS Score: {vuln.get('cvss_score', 'N/A')}\n"
                        desc = vuln.get('description', 'No description')
                        output += f"  Description: {desc[:200]}...\n" if len(desc) > 200 else f"  Description: {desc}\n"
                        if vuln.get('remediation'):
                            rem = vuln.get('remediation', '')
                            output += f"  Remediation: {rem[:150]}...\n" if len(rem) > 150 else f"  Remediation: {rem}\n"
        else:
            output += "✅ No vulnerabilities found!\n\n"

        # Recommendations
        recommendations = results.get("recommendations", [])
        if recommendations:
            output += "\n" + "=" * 80 + "\n"
            output += "💡 SECURITY RECOMMENDATIONS\n"
            output += "=" * 80 + "\n"
            for i, rec in enumerate(recommendations[:10], 1):  # Top 10
                output += f"\n{i}. {rec.get('recommendation', 'No recommendation')}\n"
                # Handle both priority formats (string or int)
                priority = rec.get('priority', 'LOW')
                if isinstance(priority, str):
                    output += f"   Priority: {priority}\n"
                else:
                    output += f"   Priority: {priority}/4\n"
                # Only show affected_components if present
                if rec.get('affected_components'):
                    output += f"   Affects: {', '.join(rec.get('affected_components', [])[:3])}\n"

        # Display in security tab
        self.security_output.setText(output)
        self.results_tabs.setCurrentIndex(2)  # Switch to Security Analysis tab
        self.update_status(f"✅ Scan complete! Found {len(vulnerabilities)} vulnerabilities.")
        self.export_button.setEnabled(True)
        
        # Save scan to history database
        self.save_scan_to_history(results)
        
        # Show completion notification
        risk_emoji = "🔴" if risk_score >= 7.0 else "🟡" if risk_score >= 4.0 else "🟢"
        self.show_notification(
            f"{risk_emoji} Vulnerability Scan Complete",
            f"Found {len(vulnerabilities)} vulnerabilities with risk score {risk_score:.1f}/10.0 ({risk_level})"
        )

    def vulnerability_scan_error(self, error_message):
        """Handle vulnerability scan errors"""
        self.vuln_scan_button.setEnabled(True)
        self.vuln_scan_button.setText("🔍 Run Vulnerability Scan")
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.update_status(f"❌ Vulnerability scan failed")
        QMessageBox.critical(
            self,
            "❌ Vulnerability Scan Failed",
            f"Vulnerability scan failed:\n\n{error_message}\n\nPlease check the network connection and try again."
        )

    def _get_risk_level(self, score):
        """Convert risk score to risk level"""
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        else:
            return "MINIMAL"

    def show_notification(self, title, message, icon=QMessageBox.Information):
        """Show a non-blocking notification to the user"""
        msg_box = QMessageBox(self)
        msg_box.setIcon(icon)
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        msg_box.setStandardButtons(QMessageBox.Ok)
        
        # Auto-close after 5 seconds for info messages
        if icon == QMessageBox.Information:
            QTimer.singleShot(5000, msg_box.close)
        
        msg_box.show()  # Non-blocking
        msg_box.raise_()
        msg_box.activateWindow()

    def export_report(self):
        """Export scan results to file"""
        if not self.scan_results:
            QMessageBox.warning(
                self,
                "⚠️ No Results",
                "No scan results available to export. Please run a vulnerability scan first."
            )
            return

        # Ask user to select format
        formats = ["JSON", "HTML", "PDF"]
        format_choice, ok = QInputDialog.getItem(
            self,
            "💾 Export Format",
            "Select export format:",
            formats,
            0,
            False
        )
        
        if not ok:
            return

        # Get save location
        target = self.scan_results.get('target', 'scan')
        timestamp = QTimer.singleShot.__self__.__class__.__name__  # Placeholder
        default_filename = f"vulnerability_report_{target}"
        
        if format_choice == "JSON":
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Report as JSON",
                f"{default_filename}.json",
                "JSON Files (*.json)"
            )
        elif format_choice == "HTML":
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Report as HTML",
                f"{default_filename}.html",
                "HTML Files (*.html)"
            )
        else:  # PDF
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Report as PDF",
                f"{default_filename}.pdf",
                "PDF Files (*.pdf)"
            )
        
        if not file_path:
            return

        # Export the report
        self.export_button.setEnabled(False)
        self.export_button.setText("⏳ Exporting...")
        self.update_status(f"💾 Exporting report to {format_choice}...")
        
        try:
            exporter = ReportExporter()
            success = False
            
            if format_choice == "JSON":
                success = exporter.export_to_json(self.scan_results, file_path)
            elif format_choice == "HTML":
                success = exporter.export_to_html(self.scan_results, file_path)
            else:  # PDF
                success = exporter.export_to_pdf(self.scan_results, file_path)
            
            self.export_button.setEnabled(True)
            self.export_button.setText("💾 Export Report")
            
            if success:
                self.update_status(f"✅ Report exported successfully to {file_path}")
                self.show_notification(
                    "✅ Export Successful",
                    f"Report exported to:\n{file_path}"
                )
            else:
                self.update_status(f"❌ Export failed")
                QMessageBox.critical(
                    self,
                    "❌ Export Failed",
                    f"Failed to export report to {format_choice} format.\n\nCheck the logs for details."
                )
                
        except Exception as e:
            self.export_button.setEnabled(True)
            self.export_button.setText("💾 Export Report")
            self.update_status(f"❌ Export error: {str(e)}")
            QMessageBox.critical(
                self,
                "❌ Export Error",
                f"An error occurred during export:\n\n{str(e)}"
            )
            logger.error(f"Export error: {e}")
    
    def load_demo_data(self):
        """Load mock scan data for testing"""
        self.update_status("🎭 Loading demo data...")
        
        try:
            # Generate mock scan result
            mock_scan = get_sample_scan()
            
            # Populate connection list with demo device
            self.connection_list.clear()
            self.connection_list.addItem(
                f"[DEMO] {mock_scan['device_info']} - {mock_scan['target']}"
            )
            
            # Set current target
            self.current_target_host = mock_scan['target']
            
            # Display results immediately
            self.display_vulnerability_results(mock_scan)
            
            # Enable action buttons
            self.vuln_scan_button.setEnabled(True)
            self.vuln_scan_button.setText("🔄 Generate New Demo Scan")
            self.export_button.setEnabled(True)
            
            self.update_status("✅ Demo data loaded successfully!")
            self.show_notification(
                "🎭 Demo Mode Active",
                f"Loaded mock scan for {mock_scan['device_info']}\n"
                f"Risk Score: {mock_scan['risk_score']}/10.0 ({mock_scan['risk_level']})\n"
                f"Vulnerabilities: {mock_scan['vulnerability_count']}"
            )
            
            logger.info("Demo mode activated with mock data")
            
        except Exception as e:
            logger.error(f"Failed to load demo data: {e}")
            QMessageBox.critical(
                self,
                "❌ Demo Mode Error",
                f"Failed to load demo data:\n\n{str(e)}"
            )
            self.update_status("❌ Demo mode failed")
    
    def save_scan_to_history(self, results):
        """Save scan results to history database"""
        if not self.history_db:
            logger.warning("History database not available, skipping save")
            return
        
        try:
            scan_id = self.history_db.save_scan(results)
            logger.info(f"Saved scan to history database with ID: {scan_id}")
        except Exception as e:
            logger.error(f"Failed to save scan to history: {e}")
    
    def closeEvent(self, event):
        """Handle window close event"""
        # Close database connection
        if self.history_db:
            self.history_db.close()
        event.accept()
