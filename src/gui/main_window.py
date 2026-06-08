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
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QComboBox,
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QTimer
from PyQt5.QtGui import QFont, QColor

from connections.detector import ConnectionDetector
from connections.manager import ConnectionManager
from assessment.vulnerability_scanner import VulnerabilityScanner
from assessment.ssh_assessor import SSHAssessor
from reports.export import ReportExporter
from scraper.filesystem import FileSystemScraper
from utils.mock_data import get_sample_scan
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


class SSHAssessmentWorker(QThread):
    """Background worker for live SSH security assessment"""

    progress = pyqtSignal(str)
    scan_complete = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, connection_manager: ConnectionManager):
        super().__init__()
        self.connection_manager = connection_manager

    def run(self):
        """Run SSH assessment in background"""
        try:
            assessor = SSHAssessor(self.connection_manager)
            results = assessor.run_assessment(
                progress_callback=lambda msg: self.progress.emit(msg)
            )
            self.scan_complete.emit(results)
        except Exception as e:
            logger.error(f"SSH assessment failed: {e}")
            self.error.emit(str(e))


class FileScraperWorker(QThread):
    """Background worker for filesystem exploration over SSH"""

    progress = pyqtSignal(str)
    scan_complete = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, connection_manager: ConnectionManager):
        super().__init__()
        self.connection_manager = connection_manager

    def run(self):
        """Run filesystem scraping in background"""
        try:
            self.progress.emit("Exploring filesystem...")
            scraper = FileSystemScraper(self.connection_manager)
            results = scraper.explore_filesystem()
            self.scan_complete.emit(results)
        except Exception as e:
            logger.error(f"Filesystem scraping failed: {e}")
            self.error.emit(str(e))


class MainWindow(QMainWindow):
    """Main application window"""

    def __init__(self):
        super().__init__()
        self.connections = []
        self.current_connection = None
        self.current_target_host = None
        self.scan_results = None
        self.connection_manager = ConnectionManager()
        
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
        
        # History Tab
        history_tab = self.create_history_tab()
        self.results_tabs.addTab(history_tab, "📜 History")

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
        self.log_console(f"🔗 Attempting SSH connection to: {connection.get('ip', 'device')}")

        host = connection.get("ip")
        port = connection.get("port", 22)

        if connection.get("type") == "network" and host:
            success = self.connection_manager.connect_ssh(host, username, password, port=port)
        elif connection.get("type") == "serial":
            success = self.connection_manager.connect_serial(connection.get("device", ""))
        else:
            success = False

        self.progress_bar.setRange(0, 100)
        self.connect_button.setEnabled(True)

        if success:
            self.current_connection = connection
            self.current_target_host = host
            self.vuln_scan_button.setEnabled(True)
            self.scrape_button.setEnabled(True)
            self.progress_bar.setValue(100)
            self.connect_button.setText("🔌 Disconnect")
            self.connect_button.clicked.disconnect()
            self.connect_button.clicked.connect(self.disconnect_device)
            self.update_status(f"✅ Connected to {host}")
            self.log_console(f"✅ SSH connection established to {host}")
            self.show_notification(
                "✅ Connected",
                f"SSH session active on {host}. You can now run assessments."
            )
        else:
            self.progress_bar.setValue(0)
            self.connect_button.setText("🔗 Connect")
            self.update_status("❌ Connection failed")
            self.log_console(f"❌ Failed to connect to {host}")
            QMessageBox.critical(
                self, "Connection Failed",
                f"Could not connect to {host}.\n\nCheck credentials and ensure SSH is enabled on the device."
            )

    def disconnect_device(self):
        """Disconnect from the current device"""
        self.connection_manager.disconnect()
        self.current_connection = None
        self.vuln_scan_button.setEnabled(False)
        self.scrape_button.setEnabled(False)
        self.connect_button.setText("🔗 Connect")
        self.connect_button.clicked.disconnect()
        self.connect_button.clicked.connect(self.connect_to_device)
        self.update_status("🔌 Disconnected")
        self.log_console("🔌 SSH session closed")

    def start_scraping(self):
        """Start file system scraping over SSH"""
        if not self.connection_manager.is_connected():
            QMessageBox.warning(self, "Not Connected", "Connect to a device first.")
            return

        self.scrape_button.setEnabled(False)
        self.update_status("Exploring filesystem...")
        self.progress_bar.setRange(0, 0)

        self.scraper_worker = FileScraperWorker(self.connection_manager)
        self.scraper_worker.progress.connect(self.update_status)
        self.scraper_worker.scan_complete.connect(self.display_filesystem_results)
        self.scraper_worker.error.connect(self.filesystem_scan_error)
        self.scraper_worker.start()

    def display_filesystem_results(self, results):
        """Display filesystem scraping results"""
        self.scrape_button.setEnabled(True)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)

        self.filesystem_output.clear()
        file_structure = results.get("file_structure", {})
        interesting = results.get("interesting_files", [])
        findings = results.get("security_findings", [])

        self.log_filesystem(f"Explored {len(file_structure)} directories\n")
        for path, files in file_structure.items():
            self.log_filesystem(f"{path}/ ({len(files)} entries)")
            for f in files[:10]:
                self.log_filesystem(f"  {f['permissions']}  {f['name']}")
            if len(files) > 10:
                self.log_filesystem(f"  ... and {len(files) - 10} more")
            self.log_filesystem("")

        if interesting:
            self.log_filesystem(f"\n--- Interesting Files ({len(interesting)}) ---")
            for f in interesting:
                self.log_filesystem(f"  {f['path']}  ({f['reason']})")

        if findings:
            self.log_filesystem(f"\n--- Security Findings ({len(findings)}) ---")
            for f in findings:
                self.log_filesystem(f"  [{f['severity'].upper()}] {f['description']}")
                if f.get("file"):
                    self.log_filesystem(f"    File: {f['file']}")

        self.results_tabs.setCurrentIndex(1)
        self.update_status(f"Filesystem scan complete: {len(findings)} findings")

    def filesystem_scan_error(self, error_message):
        """Handle filesystem scan errors"""
        self.scrape_button.setEnabled(True)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.update_status(f"❌ Filesystem scan failed: {error_message}")

    def generate_report(self):
        """Generate security assessment report from last scan results"""
        if not hasattr(self, "last_scan_results") or not self.last_scan_results:
            QMessageBox.warning(
                self, "No Data", "Run a vulnerability scan first before generating a report."
            )
            return

        self.update_status("Generating report...")

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Report", "", "HTML Files (*.html);;JSON Files (*.json);;PDF Files (*.pdf)"
        )
        if not file_path:
            return

        try:
            exporter = ReportExporter()
            if file_path.endswith(".json"):
                exporter.export_json(self.last_scan_results, file_path)
            elif file_path.endswith(".pdf"):
                exporter.export_pdf(self.last_scan_results, file_path)
            else:
                exporter.export_html(self.last_scan_results, file_path)
            self.update_status(f"Report saved: {file_path}")
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            QMessageBox.critical(self, "Export Failed", f"Could not generate report:\n{e}")

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
        """Start vulnerability scanning — uses SSH assessment if connected, network scan otherwise"""
        if not self.current_target_host:
            QMessageBox.warning(
                self, "⚠️ No Target", "No target host available for scanning. Please connect to a network device first."
            )
            return

        self.vuln_scan_button.setEnabled(False)
        self.vuln_scan_button.setText("⏳ Scanning...")
        self.progress_bar.setRange(0, 0)

        if self.connection_manager.is_connected():
            # Live SSH assessment — deeper checks via active session
            self.update_status(f"🔍 Running live SSH assessment on {self.current_target_host}...")
            self.log_console(f"🔍 Starting SSH-based security assessment...")
            self.ssh_assessment_worker = SSHAssessmentWorker(self.connection_manager)
            self.ssh_assessment_worker.progress.connect(self.update_status)
            self.ssh_assessment_worker.progress.connect(self.log_console)
            self.ssh_assessment_worker.scan_complete.connect(self.display_ssh_assessment_results)
            self.ssh_assessment_worker.error.connect(self.vulnerability_scan_error)
            self.ssh_assessment_worker.start()
        else:
            # Network-only scan (port scan + CVE correlation)
            self.update_status(f"🔍 Starting network vulnerability scan on {self.current_target_host}...")
            self.show_notification(
                "🔍 Vulnerability Scan Started",
                f"Scanning {self.current_target_host} for security vulnerabilities. This may take several minutes..."
            )
            self.vuln_worker = VulnerabilityScanWorker(self.current_target_host)
            self.vuln_worker.progress.connect(self.update_status)
            self.vuln_worker.scan_complete.connect(self.display_vulnerability_results)
            self.vuln_worker.error.connect(self.vulnerability_scan_error)
            self.vuln_worker.start()

    def display_ssh_assessment_results(self, results):
        """Display SSH assessment results in the vulnerability results format"""
        # Convert SSH assessment format to the standard vulnerability display format
        scan_results = {
            "target": self.current_target_host,
            "device_info": results.get("device_info", {}),
            "services": {},
            "vulnerabilities": results.get("findings", []),
            "risk_score": self._calculate_ssh_risk_score(results.get("findings", [])),
            "recommendations": [],
        }

        # Store for export
        self.last_scan_results = scan_results
        self.scan_results = scan_results

        # Build display output
        findings = results.get("findings", [])
        device_info = results.get("device_info", {})
        severity_summary = results.get("severity_summary", {})

        output = "═" * 80 + "\n"
        output += "SSH SECURITY ASSESSMENT RESULTS\n"
        output += "═" * 80 + "\n\n"

        output += "📱 DEVICE INFORMATION\n"
        output += "-" * 80 + "\n"
        output += f"Target: {self.current_target_host}\n"
        if device_info.get("hostname"):
            output += f"Hostname: {device_info['hostname']}\n"
        if device_info.get("uname"):
            output += f"System: {device_info['uname']}\n"
        if device_info.get("firmware_version"):
            output += f"Firmware: {device_info['firmware_version']}\n"
        if device_info.get("uptime"):
            output += f"Uptime: {device_info['uptime']}\n"
        output += "\n"

        risk_score = scan_results["risk_score"]
        risk_level = self._get_risk_level(risk_score)
        output += f"⚠️  RISK SCORE: {risk_score:.1f}/10.0 ({risk_level})\n"
        output += f"Findings: {severity_summary.get('Critical', 0)} critical, "
        output += f"{severity_summary.get('High', 0)} high, "
        output += f"{severity_summary.get('Medium', 0)} medium, "
        output += f"{severity_summary.get('Low', 0)} low\n"
        output += "-" * 80 + "\n\n"

        if findings:
            output += f"🔐 FINDINGS ({len(findings)})\n"
            output += "=" * 80 + "\n"

            by_severity = {"Critical": [], "High": [], "Medium": [], "Low": [], "Info": []}
            for f in findings:
                sev = f.get("severity", "Low")
                if sev in by_severity:
                    by_severity[sev].append(f)

            emoji_map = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢", "Info": "ℹ️"}
            for severity in ["Critical", "High", "Medium", "Low", "Info"]:
                items = by_severity[severity]
                if not items:
                    continue
                output += f"\n{emoji_map[severity]} {severity.upper()} ({len(items)})\n"
                output += "-" * 80 + "\n"
                for f in items:
                    output += f"\n  [{f.get('id', '')}] {f.get('title', '')}\n"
                    output += f"  {f.get('description', '')}\n"
                    if f.get("evidence"):
                        output += f"  Evidence: {f['evidence'][:150]}\n"
                    if f.get("remediation"):
                        output += f"  Fix: {f['remediation']}\n"
        else:
            output += "✅ No security issues found!\n"

        self.security_output.setText(output)
        self.results_tabs.setCurrentIndex(2)
        self.vuln_scan_button.setEnabled(True)
        self.vuln_scan_button.setText("🔍 Run Vulnerability Scan")
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        self.export_button.setEnabled(True)
        self.update_status(f"✅ SSH assessment complete: {len(findings)} findings")
        self.save_scan_to_history(scan_results)

        risk_emoji = "🔴" if risk_score >= 7.0 else "🟡" if risk_score >= 4.0 else "🟢"
        self.show_notification(
            f"{risk_emoji} SSH Assessment Complete",
            f"Found {len(findings)} issues (risk: {risk_score:.1f}/10.0)"
        )

    def _calculate_ssh_risk_score(self, findings: list) -> float:
        """Calculate risk score from SSH assessment findings"""
        if not findings:
            return 0.0
        severity_weights = {"Critical": 10.0, "High": 7.5, "Medium": 5.0, "Low": 2.0, "Info": 0.5}
        total = sum(severity_weights.get(f.get("severity", "Low"), 2.0) for f in findings)
        avg = total / len(findings)
        multiplier = min(len(findings) / 8.0, 1.5)
        return min(avg * multiplier, 10.0)

    def display_vulnerability_results(self, results):
        """Display vulnerability scan results"""
        self.scan_results = results
        self.last_scan_results = results
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
    
    def create_history_tab(self):
        """Create the scan history viewer tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Controls row
        controls_layout = QHBoxLayout()
        
        # Target filter
        controls_layout.addWidget(QLabel("Target:"))
        self.history_target_filter = QComboBox()
        self.history_target_filter.addItem("All Targets")
        self.history_target_filter.currentTextChanged.connect(self.filter_history)
        controls_layout.addWidget(self.history_target_filter)
        
        # Risk level filter
        controls_layout.addWidget(QLabel("Risk Level:"))
        self.history_risk_filter = QComboBox()
        self.history_risk_filter.addItems(["All Levels", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        self.history_risk_filter.currentTextChanged.connect(self.filter_history)
        controls_layout.addWidget(self.history_risk_filter)
        
        controls_layout.addStretch()
        
        # Refresh button
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self.load_scan_history)
        controls_layout.addWidget(refresh_btn)
        
        # Statistics button
        stats_btn = QPushButton("📊 Statistics")
        stats_btn.clicked.connect(self.show_history_statistics)
        controls_layout.addWidget(stats_btn)
        
        layout.addLayout(controls_layout)
        
        # History table
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(7)
        self.history_table.setHorizontalHeaderLabels([
            "ID", "Date/Time", "Target", "Device", "Risk Score", "Vulnerabilities", "Duration (s)"
        ])
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.history_table.horizontalHeader().setStretchLastSection(True)
        self.history_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.history_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.history_table.doubleClicked.connect(self.view_historical_scan)
        layout.addWidget(self.history_table)
        
        # Action buttons
        history_actions = QHBoxLayout()
        
        view_btn = QPushButton("👁️ View Scan")
        view_btn.clicked.connect(self.view_historical_scan)
        history_actions.addWidget(view_btn)
        
        delete_btn = QPushButton("🗑️ Delete Scan")
        delete_btn.clicked.connect(self.delete_historical_scan)
        history_actions.addWidget(delete_btn)
        
        history_actions.addStretch()
        
        export_history_btn = QPushButton("💾 Export Selected")
        export_history_btn.clicked.connect(self.export_historical_scan)
        history_actions.addWidget(export_history_btn)
        
        layout.addLayout(history_actions)
        
        # Load initial history
        QTimer.singleShot(1000, self.load_scan_history)
        
        return tab
    
    def load_scan_history(self):
        """Load scan history from database"""
        if not self.history_db:
            return
        
        try:
            # Get all scans
            scans = self.history_db.get_all_scans(limit=100)
            
            # Update target filter
            current_target = self.history_target_filter.currentText()
            self.history_target_filter.clear()
            self.history_target_filter.addItem("All Targets")
            targets = self.history_db.get_unique_targets()
            self.history_target_filter.addItems(targets)
            self.history_target_filter.setCurrentText(current_target)
            
            # Store all scans
            self.all_scans = scans
            
            # Apply filters
            self.filter_history()
            
            logger.info(f"Loaded {len(scans)} scans from history")
            
        except Exception as e:
            logger.error(f"Failed to load scan history: {e}")
    
    def filter_history(self):
        """Filter history table based on selected criteria"""
        if not hasattr(self, 'all_scans'):
            return
        
        target_filter = self.history_target_filter.currentText()
        risk_filter = self.history_risk_filter.currentText()
        
        # Filter scans
        filtered_scans = self.all_scans
        
        if target_filter != "All Targets":
            filtered_scans = [s for s in filtered_scans if s['target'] == target_filter]
        
        if risk_filter != "All Levels":
            filtered_scans = [s for s in filtered_scans if s['risk_level'] == risk_filter]
        
        # Update table
        self.history_table.setRowCount(len(filtered_scans))
        
        for row, scan in enumerate(filtered_scans):
            # ID
            self.history_table.setItem(row, 0, QTableWidgetItem(str(scan['id'])))
            
            # Date/Time
            timestamp = scan['scan_timestamp'][:19].replace('T', ' ')
            self.history_table.setItem(row, 1, QTableWidgetItem(timestamp))
            
            # Target
            self.history_table.setItem(row, 2, QTableWidgetItem(scan['target']))
            
            # Device
            device = f"{scan['device_vendor']} {scan['device_model']}"
            self.history_table.setItem(row, 3, QTableWidgetItem(device))
            
            # Risk Score (with color)
            risk_score = scan['risk_score']
            risk_item = QTableWidgetItem(f"{risk_score:.1f}")
            if risk_score >= 7.0:
                risk_item.setBackground(QColor(255, 200, 200))  # Light red
            elif risk_score >= 4.0:
                risk_item.setBackground(QColor(255, 255, 200))  # Light yellow
            else:
                risk_item.setBackground(QColor(200, 255, 200))  # Light green
            self.history_table.setItem(row, 4, risk_item)
            
            # Vulnerabilities
            self.history_table.setItem(row, 5, QTableWidgetItem(str(scan['vulnerability_count'])))
            
            # Duration
            duration = scan.get('scan_duration', 0.0)
            self.history_table.setItem(row, 6, QTableWidgetItem(f"{duration:.1f}"))
    
    def view_historical_scan(self):
        """View a historical scan result"""
        selected_rows = self.history_table.selectedItems()
        if not selected_rows:
            QMessageBox.warning(self, "⚠️ No Selection", "Please select a scan to view.")
            return
        
        # Get scan ID from first column
        row = self.history_table.currentRow()
        scan_id = int(self.history_table.item(row, 0).text())
        
        # Retrieve full scan results
        scan_results = self.history_db.get_scan_by_id(scan_id)
        
        if scan_results:
            # Display in security tab
            self.display_vulnerability_results(scan_results)
            self.results_tabs.setCurrentIndex(2)  # Switch to Security Analysis tab
        else:
            QMessageBox.warning(self, "⚠️ Not Found", f"Scan #{scan_id} not found in database.")
    
    def delete_historical_scan(self):
        """Delete a historical scan"""
        selected_rows = self.history_table.selectedItems()
        if not selected_rows:
            QMessageBox.warning(self, "⚠️ No Selection", "Please select a scan to delete.")
            return
        
        row = self.history_table.currentRow()
        scan_id = int(self.history_table.item(row, 0).text())
        target = self.history_table.item(row, 2).text()
        
        # Confirm deletion
        reply = QMessageBox.question(
            self,
            "🗑️ Confirm Deletion",
            f"Are you sure you want to delete scan #{scan_id} for {target}?\n\nThis cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            if self.history_db.delete_scan(scan_id):
                self.load_scan_history()
                self.update_status(f"✅ Deleted scan #{scan_id}")
            else:
                QMessageBox.critical(self, "❌ Delete Failed", f"Failed to delete scan #{scan_id}.")
    
    def export_historical_scan(self):
        """Export a historical scan"""
        selected_rows = self.history_table.selectedItems()
        if not selected_rows:
            QMessageBox.warning(self, "⚠️ No Selection", "Please select a scan to export.")
            return
        
        row = self.history_table.currentRow()
        scan_id = int(self.history_table.item(row, 0).text())
        
        # Load scan results
        scan_results = self.history_db.get_scan_by_id(scan_id)
        
        if scan_results:
            # Temporarily set as current scan for export
            original_results = self.scan_results
            self.scan_results = scan_results
            self.export_report()
            self.scan_results = original_results
        else:
            QMessageBox.warning(self, "⚠️ Not Found", f"Scan #{scan_id} not found.")
    
    def show_history_statistics(self):
        """Show scan history statistics"""
        if not self.history_db:
            return
        
        stats = self.history_db.get_statistics()
        
        if not stats:
            QMessageBox.information(self, "📊 Statistics", "No statistics available.")
            return
        
        # Build statistics message
        msg = "📊 SCAN HISTORY STATISTICS\n"
        msg += "=" * 40 + "\n\n"
        msg += f"Total Scans: {stats['total_scans']}\n"
        msg += f"Unique Targets: {stats['unique_targets']}\n"
        msg += f"Total Vulnerabilities: {stats['total_vulnerabilities']}\n"
        msg += f"Average Risk Score: {stats['avg_risk_score']}/10.0\n\n"
        
        msg += "Risk Distribution:\n"
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = stats['risk_distribution'].get(level, 0)
            if count > 0:
                msg += f"  {level}: {count} scans\n"
        
        if stats.get('last_scan'):
            last_scan = stats['last_scan'][:19].replace('T', ' ')
            msg += f"\nLast Scan: {last_scan}"
        
        QMessageBox.information(self, "📊 Scan Statistics", msg)
    
    def closeEvent(self, event):
        """Handle window close event"""
        # Close database connection
        if self.history_db:
            self.history_db.close()
        event.accept()
