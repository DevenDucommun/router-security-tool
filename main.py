#!/usr/bin/env python3
"""
Router Security Tool - Main Entry Point
A tool for connecting to and assessing network devices via USB/console/SSH
"""

import sys
import logging
from pathlib import Path

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from PyQt5.QtWidgets import QApplication
from gui.main_window import MainWindow

def setup_logging():
    """Configure logging for the application"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('router_security_tool.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )

def main():
    """Main application entry point"""
    setup_logging()
    logger = logging.getLogger(__name__)
    logger.info("Starting Router Security Tool")
    
    app = QApplication(sys.argv)
    app.setApplicationName("Router Security Tool")
    app.setApplicationVersion("1.0.0")
    
    window = MainWindow()
    window.show()
    
    return app.exec_()

if __name__ == "__main__":
    sys.exit(main())