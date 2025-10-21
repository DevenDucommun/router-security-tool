"""
File System Scraper
Explores Linux-based device file systems and gathers information
"""

import logging
import re
from typing import Dict, List, Optional
from connections.manager import ConnectionManager

logger = logging.getLogger(__name__)

class FileSystemScraper:
    """Scrapes file system information from connected devices"""
    
    def __init__(self, connection_manager: ConnectionManager):
        self.connection = connection_manager
        self.file_structure = {}
        self.interesting_files = []
        self.security_findings = []
        
    def explore_filesystem(self) -> Dict:
        """Main entry point for file system exploration"""
        if not self.connection.is_connected():
            logger.error("No active connection for file system exploration")
            return {}
        
        logger.info("Starting file system exploration")
        
        # Common Linux directories to explore
        directories_to_check = [
            "/",           # Root
            "/bin",        # System binaries
            "/sbin",       # System admin binaries
            "/etc",        # Configuration files
            "/tmp",        # Temporary files
            "/var",        # Variable data
            "/var/log",    # Log files
            "/usr",        # User programs
            "/usr/bin",    # User binaries
            "/usr/sbin",   # User admin binaries
            "/home",       # User home directories
            "/root",       # Root user home
            "/proc",       # Process information
            "/sys",        # System information
            "/dev",        # Device files
            "/mnt",        # Mount points
        ]
        
        for directory in directories_to_check:
            self.explore_directory(directory)
            
        # Look for interesting files
        self.find_interesting_files()
        
        # Check for security issues
        self.check_security_issues()
        
        return {
            'file_structure': self.file_structure,
            'interesting_files': self.interesting_files,
            'security_findings': self.security_findings
        }
    
    def explore_directory(self, path: str, max_depth: int = 2, current_depth: int = 0):
        """Explore a specific directory"""
        if current_depth >= max_depth:
            return
            
        logger.debug(f"Exploring directory: {path}")
        
        # Try different listing commands
        commands = [
            f"ls -la {path}",
            f"ls -l {path}",
            f"ls {path}",
            f"dir {path}"  # Some devices might use DOS-style commands
        ]
        
        listing = None
        for cmd in commands:
            listing = self.connection.send_command(cmd)
            if listing and "No such file" not in listing and "not found" not in listing.lower():
                break
        
        if not listing:
            logger.debug(f"Could not list directory: {path}")
            return
            
        # Parse directory listing
        files = self.parse_directory_listing(listing)
        self.file_structure[path] = files
        
        # Recursively explore subdirectories (limited depth)
        for file_info in files:
            if file_info.get('type') == 'directory' and current_depth < max_depth - 1:
                subdir = f"{path.rstrip('/')}/{file_info['name']}"
                if file_info['name'] not in ['.', '..']:
                    self.explore_directory(subdir, max_depth, current_depth + 1)
    
    def parse_directory_listing(self, listing: str) -> List[Dict]:
        """Parse ls -la output into structured data"""
        files = []
        lines = listing.split('\\n')
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('total'):
                continue
                
            # Parse ls -la format: permissions, links, owner, group, size, date, name
            parts = line.split()
            if len(parts) < 9:
                continue
                
            permissions = parts[0]
            file_info = {
                'name': ' '.join(parts[8:]),  # Handle filenames with spaces
                'permissions': permissions,
                'owner': parts[2] if len(parts) > 2 else 'unknown',
                'group': parts[3] if len(parts) > 3 else 'unknown',
                'size': parts[4] if len(parts) > 4 else '0',
                'raw_line': line
            }
            
            # Determine file type
            if permissions.startswith('d'):
                file_info['type'] = 'directory'
            elif permissions.startswith('l'):
                file_info['type'] = 'symlink'
            elif permissions.startswith('-'):
                file_info['type'] = 'file'
            else:
                file_info['type'] = 'other'
            
            files.append(file_info)
            
        return files
    
    def find_interesting_files(self):
        """Find potentially interesting files for security assessment"""
        interesting_patterns = [
            # Configuration files
            r'.*\\.conf$',
            r'.*\\.cfg$',
            r'.*\\.ini$',
            r'config.*',
            r'settings.*',
            
            # Credential files
            r'.*passwd.*',
            r'.*shadow.*',
            r'.*\.key$',
            r'.*\.pem$',
            r'.*\.crt$',
            r'.*\.p12$',
            
            # Script files
            r'.*\\.sh$',
            r'.*\\.py$',
            r'.*\\.pl$',
            r'startup.*',
            r'init.*',
            
            # Log files
            r'.*\\.log$',
            r'.*\\.out$',
            r'syslog.*',
            r'messages.*',
            
            # Database files
            r'.*\\.db$',
            r'.*\\.sqlite$',
            
            # Backup files
            r'.*\\.bak$',
            r'.*\\.backup$',
            r'.*~$',
        ]
        
        for path, files in self.file_structure.items():
            for file_info in files:
                filename = file_info['name'].lower()
                
                for pattern in interesting_patterns:
                    if re.match(pattern, filename):
                        interesting_file = {
                            'path': f"{path.rstrip('/')}/{file_info['name']}",
                            'name': file_info['name'],
                            'type': file_info['type'],
                            'permissions': file_info['permissions'],
                            'reason': f'Matches pattern: {pattern}'
                        }
                        self.interesting_files.append(interesting_file)
                        break
    
    def check_security_issues(self):
        """Check for common security issues"""
        logger.info("Checking for security issues")
        
        # Check for world-writable files
        self.check_world_writable_files()
        
        # Check for SUID/SGID files
        self.check_suid_sgid_files()
        
        # Check for default passwords/configs
        self.check_default_configurations()
        
        # Check for running services
        self.check_running_services()
    
    def check_world_writable_files(self):
        """Find world-writable files (potential security risk)"""
        for path, files in self.file_structure.items():
            for file_info in files:
                perms = file_info.get('permissions', '')
                if len(perms) >= 10 and perms[9] == 'w':  # World-writable
                    self.security_findings.append({
                        'type': 'world_writable_file',
                        'severity': 'medium',
                        'file': f"{path.rstrip('/')}/{file_info['name']}",
                        'description': 'World-writable file found',
                        'permissions': perms
                    })
    
    def check_suid_sgid_files(self):
        """Find SUID/SGID files"""
        for path, files in self.file_structure.items():
            for file_info in files:
                perms = file_info.get('permissions', '')
                if len(perms) >= 4:
                    if 's' in perms[3:6]:  # SUID/SGID bits
                        self.security_findings.append({
                            'type': 'suid_sgid_file',
                            'severity': 'high',
                            'file': f"{path.rstrip('/')}/{file_info['name']}",
                            'description': 'SUID/SGID file found',
                            'permissions': perms
                        })
    
    def check_default_configurations(self):
        """Check for default configuration files that might contain default passwords"""
        default_indicators = [
            'admin/admin',
            'root/root',
            'admin/password',
            'user/user',
            'guest/guest',
            'default_password',
            'changeme'
        ]
        
        # Check interesting configuration files
        config_files = [f for f in self.interesting_files 
                       if any(ext in f['name'].lower() 
                             for ext in ['.conf', '.cfg', '.ini', 'config'])]
        
        for config_file in config_files[:5]:  # Limit to avoid too many requests
            content = self.connection.send_command(f"cat {config_file['path']}")
            if content:
                for indicator in default_indicators:
                    if indicator.lower() in content.lower():
                        self.security_findings.append({
                            'type': 'default_credentials',
                            'severity': 'critical',
                            'file': config_file['path'],
                            'description': f'Potential default credentials found: {indicator}',
                            'evidence': indicator
                        })
    
    def check_running_services(self):
        """Check for running services and open ports"""
        # Try different commands to get process info
        commands = [
            'ps aux',
            'ps -ef',
            'ps',
            'netstat -an',
            'netstat -l'
        ]
        
        for cmd in commands:
            result = self.connection.send_command(cmd)
            if result and len(result) > 50:  # Got substantial output
                self.security_findings.append({
                    'type': 'service_enumeration',
                    'severity': 'info',
                    'description': f'Process/service information gathered via {cmd}',
                    'data': result[:500]  # Truncate for storage
                })
                break
    
    def get_file_content(self, filepath: str, max_size: int = 1000) -> Optional[str]:
        """Get content of a specific file (limited size)"""
        commands = [
            f"head -n 50 {filepath}",
            f"cat {filepath} | head -c {max_size}",
            f"cat {filepath}"
        ]
        
        for cmd in commands:
            content = self.connection.send_command(cmd)
            if content and "No such file" not in content:
                return content
                
        return None