"""
Scan History Database
Stores and manages historical vulnerability scan results using SQLite.
"""

import sqlite3
import json
import logging
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class ScanHistoryDB:
    """Manage scan history database"""
    
    def __init__(self, db_path: str = None):
        """
        Initialize database connection.
        
        Args:
            db_path: Path to SQLite database file (default: data/scan_history.db)
        """
        if db_path is None:
            # ROUTER_SECURITY_DB overrides the location (tests point it at a temp file);
            # otherwise default to the data directory in the project root.
            db_path = os.environ.get("ROUTER_SECURITY_DB") or (
                Path(__file__).parent.parent.parent / "data" / "scan_history.db"
            )
        
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.conn = None
        self.init_database()
    
    def init_database(self):
        """Initialize database schema"""
        try:
            self.conn = sqlite3.connect(str(self.db_path))
            self.conn.row_factory = sqlite3.Row  # Enable column access by name
            
            cursor = self.conn.cursor()
            
            # Create scans table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    scan_timestamp TEXT NOT NULL,
                    device_vendor TEXT,
                    device_model TEXT,
                    firmware_version TEXT,
                    risk_score REAL NOT NULL,
                    risk_level TEXT NOT NULL,
                    vulnerability_count INTEGER NOT NULL,
                    scan_duration REAL,
                    full_results TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            
            # Create vulnerabilities table for easier querying
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    cvss_score REAL,
                    cve_id TEXT,
                    description TEXT,
                    remediation TEXT,
                    detected_at TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
                )
            """)
            
            # Create indexes for faster queries
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_target 
                ON scans(target)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_timestamp 
                ON scans(scan_timestamp DESC)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_id 
                ON vulnerabilities(scan_id)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity
                ON vulnerabilities(severity)
            """)

            self._migrate_annotations(cursor)

            self.conn.commit()
            logger.info(f"Database initialized at {self.db_path}")
            
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise
    
    def _migrate_annotations(self, cursor):
        """Add tags/notes columns to databases created before v1.1."""
        cursor.execute("PRAGMA table_info(scans)")
        columns = {row["name"] for row in cursor.fetchall()}
        for name, ddl in (
            ("tags", "ALTER TABLE scans ADD COLUMN tags TEXT NOT NULL DEFAULT '[]'"),
            ("notes", "ALTER TABLE scans ADD COLUMN notes TEXT NOT NULL DEFAULT ''"),
        ):
            if name in columns:
                continue
            try:
                cursor.execute(ddl)
            except sqlite3.OperationalError as e:
                # Another connection (parallel batch/scheduled scan) migrated first.
                if "duplicate column" not in str(e).lower():
                    raise

    @staticmethod
    def _row_to_summary(row) -> Dict[str, Any]:
        summary = dict(row)
        try:
            tags = json.loads(summary.get("tags") or "[]")
        except (TypeError, ValueError):
            tags = []
        summary["tags"] = [t for t in tags if isinstance(t, str)] if isinstance(tags, list) else []
        summary["notes"] = summary.get("notes") or ""
        return summary

    def save_scan(self, scan_results: Dict[str, Any]) -> int:
        """
        Save scan results to database.
        
        Args:
            scan_results: Complete scan results dictionary
        
        Returns:
            Scan ID of saved record
        """
        try:
            cursor = self.conn.cursor()
            
            # Extract main scan data
            target = scan_results.get('target', 'Unknown')
            scan_timestamp = scan_results.get('scan_timestamp', datetime.now().isoformat())
            
            # Handle device info (can be string or dict)
            device_info = scan_results.get('device_info', {})
            if isinstance(device_info, str):
                device_vendor = scan_results.get('vendor', 'Unknown')
                device_model = scan_results.get('model', 'Unknown')
                firmware_version = scan_results.get('firmware_version', 'Unknown')
            else:
                device_vendor = device_info.get('vendor', 'Unknown')
                device_model = device_info.get('product', 'Unknown')
                firmware_version = device_info.get('version', 'Unknown')
            
            risk_score = scan_results.get('risk_score', 0.0)
            risk_level = scan_results.get('risk_level', 'UNKNOWN')
            vulnerabilities = scan_results.get('vulnerabilities', [])
            vulnerability_count = len(vulnerabilities)
            scan_duration = scan_results.get('scan_duration', 0.0)
            
            # Serialize full results as JSON
            full_results = json.dumps(scan_results)
            created_at = datetime.now().isoformat()
            
            # Insert scan record
            cursor.execute("""
                INSERT INTO scans (
                    target, scan_timestamp, device_vendor, device_model,
                    firmware_version, risk_score, risk_level,
                    vulnerability_count, scan_duration, full_results, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                target, scan_timestamp, device_vendor, device_model,
                firmware_version, risk_score, risk_level,
                vulnerability_count, scan_duration, full_results, created_at
            ))
            
            scan_id = cursor.lastrowid
            
            # Insert individual vulnerabilities
            for vuln in vulnerabilities:
                cursor.execute("""
                    INSERT INTO vulnerabilities (
                        scan_id, title, severity, cvss_score, cve_id,
                        description, remediation, detected_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_id,
                    vuln.get('title', 'Unknown'),
                    vuln.get('severity', 'UNKNOWN'),
                    vuln.get('cvss_score'),
                    vuln.get('cve_id'),
                    vuln.get('description'),
                    vuln.get('remediation'),
                    vuln.get('detected_at', scan_timestamp)
                ))
            
            self.conn.commit()
            logger.info(f"Saved scan #{scan_id} for target {target} with {vulnerability_count} vulnerabilities")
            return scan_id
            
        except Exception as e:
            logger.error(f"Failed to save scan: {e}")
            self.conn.rollback()
            raise
    
    def get_all_scans(
        self,
        limit: int = 100,
        target: Optional[str] = None,
        risk_level: Optional[str] = None,
        tag: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get scans, most recent first, optionally filtered.

        Filters are applied in SQL before the limit, so a filtered view is not
        truncated by unrelated newer scans.

        Args:
            limit: Maximum number of scans to return
            target: Only scans of this target
            risk_level: Only scans with this risk level
            tag: Only scans carrying this tag (case-insensitive)

        Returns:
            List of scan summaries
        """
        try:
            cursor = self.conn.cursor()
            query = """
                SELECT
                    id, target, scan_timestamp, device_vendor, device_model,
                    firmware_version, risk_score, risk_level, vulnerability_count,
                    scan_duration, created_at, tags, notes
                FROM scans
                WHERE 1=1
            """
            params: List[Any] = []
            if target:
                query += " AND target = ?"
                params.append(target)
            if risk_level:
                query += " AND risk_level = ?"
                params.append(risk_level)
            if tag:
                query += (
                    " AND EXISTS (SELECT 1 FROM json_each(scans.tags)"
                    " WHERE lower(json_each.value) = lower(?))"
                )
                params.append(tag)
            query += " ORDER BY scan_timestamp DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            return [self._row_to_summary(row) for row in cursor.fetchall()]
            
        except Exception as e:
            logger.error(f"Failed to retrieve scans: {e}")
            return []
    
    def get_scans_by_target(self, target: str, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get all scans for a specific target.
        
        Args:
            target: Target IP or hostname
            limit: Maximum number of scans to return
        
        Returns:
            List of scan summaries for the target
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT 
                    id, target, scan_timestamp, device_vendor, device_model,
                    firmware_version, risk_score, risk_level, vulnerability_count,
                    scan_duration, created_at
                FROM scans
                WHERE target = ?
                ORDER BY scan_timestamp DESC
                LIMIT ?
            """, (target, limit))
            
            scans = []
            for row in cursor.fetchall():
                scans.append(dict(row))
            
            return scans
            
        except Exception as e:
            logger.error(f"Failed to retrieve scans for {target}: {e}")
            return []
    
    def get_scan_by_id(self, scan_id: int) -> Optional[Dict[str, Any]]:
        """
        Get complete scan results by ID.
        
        Args:
            scan_id: Scan ID
        
        Returns:
            Complete scan results or None if not found
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT full_results
                FROM scans
                WHERE id = ?
            """, (scan_id,))
            
            row = cursor.fetchone()
            if row:
                return json.loads(row['full_results'])
            return None
            
        except Exception as e:
            logger.error(f"Failed to retrieve scan #{scan_id}: {e}")
            return None
    
    def get_scan_summary(self, scan_id: int) -> Optional[Dict[str, Any]]:
        """
        Get the indexed metadata row for a scan (no full results).

        Args:
            scan_id: Scan ID

        Returns:
            Scan summary dictionary or None if not found
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT
                    id, target, scan_timestamp, device_vendor, device_model,
                    firmware_version, risk_score, risk_level, vulnerability_count,
                    scan_duration, created_at, tags, notes
                FROM scans
                WHERE id = ?
            """, (scan_id,))

            row = cursor.fetchone()
            return self._row_to_summary(row) if row else None

        except Exception as e:
            logger.error(f"Failed to retrieve summary for scan #{scan_id}: {e}")
            return None

    def update_annotations(
        self,
        scan_id: int,
        tags: Optional[List[str]] = None,
        notes: Optional[str] = None,
    ) -> bool:
        """
        Set the tags and/or notes on a scan. Fields left as None are unchanged.

        Returns:
            True if the scan exists and was updated, False otherwise
        """
        assignments = []
        params: List[Any] = []
        if tags is not None:
            assignments.append("tags = ?")
            params.append(json.dumps(tags))
        if notes is not None:
            assignments.append("notes = ?")
            params.append(notes)
        try:
            cursor = self.conn.cursor()
            if not assignments:
                cursor.execute("SELECT 1 FROM scans WHERE id = ?", (scan_id,))
                return cursor.fetchone() is not None
            params.append(scan_id)
            cursor.execute(f"UPDATE scans SET {', '.join(assignments)} WHERE id = ?", params)
            self.conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Failed to update annotations for scan #{scan_id}: {e}")
            self.conn.rollback()
            return False

    def get_all_tags(self) -> List[str]:
        """Distinct tags in use across all scans, sorted case-insensitively."""
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT DISTINCT json_each.value AS tag FROM scans, json_each(scans.tags)")
            return sorted({row["tag"] for row in cursor.fetchall()}, key=str.lower)
        except Exception as e:
            logger.error(f"Failed to list tags: {e}")
            return []

    def get_unique_targets(self) -> List[str]:
        """
        Get list of unique targets that have been scanned.
        
        Returns:
            List of unique target addresses
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT DISTINCT target
                FROM scans
                ORDER BY target
            """)
            
            return [row['target'] for row in cursor.fetchall()]
            
        except Exception as e:
            logger.error(f"Failed to retrieve unique targets: {e}")
            return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get overall scan statistics.
        
        Returns:
            Dictionary with statistics
        """
        try:
            cursor = self.conn.cursor()
            
            # Total scans
            cursor.execute("SELECT COUNT(*) as count FROM scans")
            total_scans = cursor.fetchone()['count']
            
            # Unique targets
            cursor.execute("SELECT COUNT(DISTINCT target) as count FROM scans")
            unique_targets = cursor.fetchone()['count']
            
            # Total vulnerabilities found
            cursor.execute("SELECT COUNT(*) as count FROM vulnerabilities")
            total_vulnerabilities = cursor.fetchone()['count']
            
            # Average risk score
            cursor.execute("SELECT AVG(risk_score) as avg FROM scans")
            avg_risk_score = cursor.fetchone()['avg'] or 0.0
            
            # Scans by risk level
            cursor.execute("""
                SELECT risk_level, COUNT(*) as count
                FROM scans
                GROUP BY risk_level
            """)
            risk_distribution = {row['risk_level']: row['count'] for row in cursor.fetchall()}
            
            # Most recent scan
            cursor.execute("""
                SELECT scan_timestamp
                FROM scans
                ORDER BY scan_timestamp DESC
                LIMIT 1
            """)
            row = cursor.fetchone()
            last_scan = row['scan_timestamp'] if row else None
            
            return {
                'total_scans': total_scans,
                'unique_targets': unique_targets,
                'total_vulnerabilities': total_vulnerabilities,
                'avg_risk_score': round(avg_risk_score, 2),
                'risk_distribution': risk_distribution,
                'last_scan': last_scan,
            }
            
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {}
    
    def delete_scan(self, scan_id: int) -> bool:
        """
        Delete a scan and its vulnerabilities.
        
        Args:
            scan_id: Scan ID to delete
        
        Returns:
            True if successful, False otherwise
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            self.conn.commit()
            
            if cursor.rowcount > 0:
                logger.info(f"Deleted scan #{scan_id}")
                return True
            return False
            
        except Exception as e:
            logger.error(f"Failed to delete scan #{scan_id}: {e}")
            self.conn.rollback()
            return False
    
    def search_vulnerabilities(
        self,
        severity: str = None,
        cve_id: str = None,
        keyword: str = None
    ) -> List[Dict[str, Any]]:
        """
        Search for vulnerabilities across all scans.
        
        Args:
            severity: Filter by severity level
            cve_id: Filter by CVE ID
            keyword: Search in title and description
        
        Returns:
            List of matching vulnerabilities with scan info
        """
        try:
            cursor = self.conn.cursor()
            
            query = """
                SELECT 
                    v.id, v.scan_id, v.title, v.severity, v.cvss_score,
                    v.cve_id, v.description, v.remediation, v.detected_at,
                    s.target, s.scan_timestamp, s.device_vendor, s.device_model
                FROM vulnerabilities v
                JOIN scans s ON v.scan_id = s.id
                WHERE 1=1
            """
            params = []
            
            if severity:
                query += " AND v.severity = ?"
                params.append(severity)
            
            if cve_id:
                query += " AND v.cve_id = ?"
                params.append(cve_id)
            
            if keyword:
                query += " AND (v.title LIKE ? OR v.description LIKE ?)"
                params.extend([f"%{keyword}%", f"%{keyword}%"])
            
            query += " ORDER BY v.detected_at DESC"
            
            cursor.execute(query, params)
            
            results = []
            for row in cursor.fetchall():
                results.append(dict(row))
            
            return results
            
        except Exception as e:
            logger.error(f"Failed to search vulnerabilities: {e}")
            return []
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            logger.info("Database connection closed")
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
