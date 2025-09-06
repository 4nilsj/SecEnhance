"""
SQLite database manager for storing scan results, performance metrics, and logs.
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from contextlib import contextmanager

from utils.logger import get_logger


class DatabaseManager:
    """Manages SQLite database operations for the API Security Scanner."""
    
    def __init__(self, db_path: str = "scan_results.db"):
        self.db_path = Path(db_path)
        self.logger = get_logger(__name__)
        self._init_database()
    
    def _init_database(self):
        """Initialize the database with required tables."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Create scans table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS scans (
                        scan_id TEXT PRIMARY KEY,
                        target_url TEXT NOT NULL,
                        start_time TIMESTAMP NOT NULL,
                        end_time TIMESTAMP,
                        total_duration REAL,
                        status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
                        error_message TEXT,
                        input_type TEXT,
                        input_source TEXT,
                        auth_type TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Create zap_alerts table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS zap_alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT NOT NULL,
                        alert_id INTEGER NOT NULL,
                        risk_level TEXT NOT NULL CHECK (risk_level IN ('High', 'Medium', 'Low', 'Informational')),
                        name TEXT NOT NULL,
                        description TEXT,
                        solution TEXT,
                        reference TEXT,
                        evidence TEXT,
                        confidence TEXT,
                        url TEXT,
                        method TEXT,
                        parameter TEXT,
                        attack TEXT,
                        other_info TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE CASCADE
                    )
                """)
                
                # Create vulnerabilities table (enhanced schema)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS vulnerabilities (
                        id TEXT PRIMARY KEY,
                        scan_id TEXT NOT NULL,
                        name TEXT NOT NULL,
                        description TEXT NOT NULL,
                        risk TEXT NOT NULL CHECK (risk IN ('High', 'Medium', 'Low', 'Informational')),
                        cvss_score REAL NOT NULL CHECK (cvss_score >= 0.0 AND cvss_score <= 10.0),
                        solution TEXT,
                        references TEXT,
                        cwe_id TEXT,
                        wasc_id TEXT,
                        request TEXT NOT NULL,
                        response TEXT NOT NULL,
                        url TEXT NOT NULL,
                        parameter TEXT,
                        evidence TEXT,
                        source TEXT NOT NULL CHECK (source IN ('ZAP', 'Custom Plugin')),
                        plugin_name TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE CASCADE
                    )
                """)
                
                # Create proof_of_concept table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS proof_of_concept (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        vulnerability_id TEXT NOT NULL,
                        request_method TEXT NOT NULL,
                        request_url TEXT NOT NULL,
                        request_headers TEXT NOT NULL,
                        request_body TEXT,
                        response_status INTEGER NOT NULL,
                        response_headers TEXT NOT NULL,
                        response_body TEXT,
                        evidence_description TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities (id) ON DELETE CASCADE
                    )
                """)
                
                # Create scan_metadata table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS scan_metadata (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT NOT NULL,
                        phase_name TEXT NOT NULL,
                        start_time TIMESTAMP NOT NULL,
                        end_time TIMESTAMP NOT NULL,
                        duration REAL NOT NULL,
                        tests_performed INTEGER,
                        details TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE CASCADE
                    )
                """)
                
                # Create performance_stats table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS performance_stats (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT NOT NULL,
                        phase_name TEXT NOT NULL,
                        start_time TIMESTAMP NOT NULL,
                        end_time TIMESTAMP NOT NULL,
                        duration REAL NOT NULL,
                        details TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE CASCADE
                    )
                """)
                
                # Create error_logs table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS error_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT,
                        error_type TEXT NOT NULL,
                        error_message TEXT NOT NULL,
                        stack_trace TEXT,
                        context TEXT,
                        severity TEXT NOT NULL CHECK (severity IN ('Critical', 'High', 'Medium', 'Low')),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE SET NULL
                    )
                """)
                
                # Create indexes for better performance
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_status ON scans (status)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_start_time ON scans (start_time)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_zap_alerts_scan_id ON zap_alerts (scan_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_zap_alerts_risk ON zap_alerts (risk_level)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_id ON vulnerabilities (scan_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_risk ON vulnerabilities (risk)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_source ON vulnerabilities (source)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_proof_of_concept_vuln_id ON proof_of_concept (vulnerability_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_metadata_scan_id ON scan_metadata (scan_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_performance_scan_id ON performance_stats (scan_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_error_logs_scan_id ON error_logs (scan_id)")
                
                conn.commit()
                self.logger.info("Database initialized successfully")
                
        except sqlite3.Error as e:
            self.logger.error(f"Failed to initialize database: {e}")
            raise
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections."""
        conn = None
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row  # Enable column access by name
            yield conn
        except sqlite3.Error as e:
            if conn:
                conn.rollback()
            self.logger.error(f"Database error: {e}")
            raise
        finally:
            if conn:
                conn.close()
    
    def create_scan(self, scan_id: str, target_url: str, input_type: str, 
                   input_source: str, auth_type: Optional[str] = None) -> bool:
        """Create a new scan record."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO scans (scan_id, target_url, start_time, status, input_type, input_source, auth_type)
                    VALUES (?, ?, ?, 'running', ?, ?, ?)
                """, (scan_id, target_url, datetime.now(), input_type, input_source, auth_type))
                conn.commit()
                self.logger.info(f"Created scan record: {scan_id}")
                return True
        except sqlite3.Error as e:
            self.logger.error(f"Failed to create scan record: {e}")
            return False
    
    def update_scan_completion(self, scan_id: str, status: str, 
                             error_message: Optional[str] = None) -> bool:
        """Update scan completion status."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Get start time to calculate duration
                cursor.execute("SELECT start_time FROM scans WHERE scan_id = ?", (scan_id,))
                result = cursor.fetchone()
                
                if result:
                    start_time = datetime.fromisoformat(result['start_time'])
                    end_time = datetime.now()
                    duration = (end_time - start_time).total_seconds()
                    
                    cursor.execute("""
                        UPDATE scans 
                        SET end_time = ?, total_duration = ?, status = ?, error_message = ?
                        WHERE scan_id = ?
                    """, (end_time, duration, status, error_message, scan_id))
                    conn.commit()
                    self.logger.info(f"Updated scan completion: {scan_id} - {status}")
                    return True
                else:
                    self.logger.error(f"Scan not found: {scan_id}")
                    return False
        except sqlite3.Error as e:
            self.logger.error(f"Failed to update scan completion: {e}")
            return False
    
    def add_zap_alert(self, scan_id: str, alert_data: Dict[str, Any]) -> bool:
        """Add a ZAP alert to the database."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO zap_alerts (
                        scan_id, alert_id, risk_level, name, description, solution,
                        reference, evidence, confidence, url, method, parameter,
                        attack, other_info
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_id,
                    alert_data.get('id'),
                    alert_data.get('risk'),
                    alert_data.get('name'),
                    alert_data.get('description'),
                    alert_data.get('solution'),
                    alert_data.get('reference'),
                    alert_data.get('evidence'),
                    alert_data.get('confidence'),
                    alert_data.get('url'),
                    alert_data.get('method'),
                    alert_data.get('param'),
                    alert_data.get('attack'),
                    alert_data.get('other')
                ))
                conn.commit()
                return True
        except sqlite3.Error as e:
            self.logger.error(f"Failed to add ZAP alert: {e}")
            return False
    
    def add_vulnerability(self, vulnerability_id: str, scan_id: str, name: str,
                         description: str, risk: str, cvss_score: float,
                         solution: str, references: List[str], cwe_id: str,
                         wasc_id: str, request: str, response: str, url: str,
                         parameter: str, evidence: str, source: str,
                         plugin_name: str = None) -> bool:
        """Add a vulnerability to the database."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO vulnerabilities (
                        id, scan_id, name, description, risk, cvss_score,
                        solution, references, cwe_id, wasc_id, request, response,
                        url, parameter, evidence, source, plugin_name
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    vulnerability_id, scan_id, name, description, risk, cvss_score,
                    solution, json.dumps(references), cwe_id, wasc_id, request, response,
                    url, parameter, evidence, source, plugin_name
                ))
                conn.commit()
                return True
        except sqlite3.Error as e:
            self.logger.error(f"Failed to add vulnerability: {e}")
            return False
    
    def add_proof_of_concept(self, vulnerability_id: str, request_method: str,
                           request_url: str, request_headers: Dict[str, str],
                           request_body: str, response_status: int,
                           response_headers: Dict[str, str], response_body: str,
                           evidence_description: str) -> bool:
        """Add proof-of-concept evidence to the database."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO proof_of_concept (
                        vulnerability_id, request_method, request_url, request_headers,
                        request_body, response_status, response_headers, response_body,
                        evidence_description
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    vulnerability_id, request_method, request_url,
                    json.dumps(request_headers), request_body, response_status,
                    json.dumps(response_headers), response_body, evidence_description
                ))
                conn.commit()
                return True
        except sqlite3.Error as e:
            self.logger.error(f"Failed to add proof of concept: {e}")
            return False
    
    def add_scan_metadata(self, scan_id: str, phase_name: str, start_time: datetime,
                         end_time: datetime, tests_performed: int = None,
                         details: str = None) -> bool:
        """Add scan metadata to the database."""
        try:
            duration = (end_time - start_time).total_seconds()
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO scan_metadata (
                        scan_id, phase_name, start_time, end_time, duration,
                        tests_performed, details
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (scan_id, phase_name, start_time, end_time, duration, tests_performed, details))
                conn.commit()
                return True
        except sqlite3.Error as e:
            self.logger.error(f"Failed to add scan metadata: {e}")
            return False
    
    def add_performance_stat(self, scan_id: str, phase_name: str, 
                           start_time: datetime, end_time: datetime,
                           details: Optional[str] = None) -> bool:
        """Add performance statistics for a scan phase."""
        try:
            duration = (end_time - start_time).total_seconds()
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO performance_stats (scan_id, phase_name, start_time, end_time, duration, details)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (scan_id, phase_name, start_time, end_time, duration, details))
                conn.commit()
                return True
        except sqlite3.Error as e:
            self.logger.error(f"Failed to add performance stat: {e}")
            return False
    
    def add_error_log(self, scan_id: Optional[str], error_type: str, 
                     error_message: str, stack_trace: Optional[str] = None,
                     context: Optional[str] = None, severity: str = "Medium") -> bool:
        """Add an error log entry."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO error_logs (scan_id, error_type, error_message, stack_trace, context, severity)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (scan_id, error_type, error_message, stack_trace, context, severity))
                conn.commit()
                return True
        except sqlite3.Error as e:
            self.logger.error(f"Failed to add error log: {e}")
            return False
    
    def get_scan_summary(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get a summary of a scan including all related data."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Get scan details
                cursor.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
                scan = cursor.fetchone()
                
                if not scan:
                    return None
                
                # Get ZAP alerts count by risk level
                cursor.execute("""
                    SELECT risk_level, COUNT(*) as count 
                    FROM zap_alerts 
                    WHERE scan_id = ? 
                    GROUP BY risk_level
                """, (scan_id,))
                zap_alerts = {row['risk_level']: row['count'] for row in cursor.fetchall()}
                
                # Get custom alerts count by severity
                cursor.execute("""
                    SELECT severity, COUNT(*) as count 
                    FROM custom_alerts 
                    WHERE scan_id = ? 
                    GROUP BY severity
                """, (scan_id,))
                custom_alerts = {row['severity']: row['count'] for row in cursor.fetchall()}
                
                # Get performance stats
                cursor.execute("""
                    SELECT phase_name, duration, details 
                    FROM performance_stats 
                    WHERE scan_id = ? 
                    ORDER BY start_time
                """, (scan_id,))
                performance_stats = [dict(row) for row in cursor.fetchall()]
                
                # Get error count
                cursor.execute("""
                    SELECT COUNT(*) as error_count 
                    FROM error_logs 
                    WHERE scan_id = ?
                """, (scan_id,))
                error_count = cursor.fetchone()['error_count']
                
                return {
                    'scan': dict(scan),
                    'zap_alerts': zap_alerts,
                    'custom_alerts': custom_alerts,
                    'performance_stats': performance_stats,
                    'error_count': error_count
                }
        except sqlite3.Error as e:
            self.logger.error(f"Failed to get scan summary: {e}")
            return None
    
    def get_all_scans(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get a list of all scans with basic information."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT scan_id, target_url, start_time, end_time, total_duration, status, input_type
                    FROM scans 
                    ORDER BY start_time DESC 
                    LIMIT ?
                """, (limit,))
                return [dict(row) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            self.logger.error(f"Failed to get scans list: {e}")
            return []
    
    def cleanup_old_scans(self, days: int = 30) -> int:
        """Clean up scans older than specified days."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    DELETE FROM scans 
                    WHERE start_time < datetime('now', '-{} days')
                """.format(days))
                deleted_count = cursor.rowcount
                conn.commit()
                self.logger.info(f"Cleaned up {deleted_count} old scans")
                return deleted_count
        except sqlite3.Error as e:
            self.logger.error(f"Failed to cleanup old scans: {e}")
            return 0
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                stats = {}
                
                # Count scans by status
                cursor.execute("SELECT status, COUNT(*) as count FROM scans GROUP BY status")
                stats['scans_by_status'] = {row['status']: row['count'] for row in cursor.fetchall()}
                
                # Count total alerts
                cursor.execute("SELECT COUNT(*) as count FROM zap_alerts")
                stats['total_zap_alerts'] = cursor.fetchone()['count']
                
                cursor.execute("SELECT COUNT(*) as count FROM custom_alerts")
                stats['total_custom_alerts'] = cursor.fetchone()['count']
                
                # Database size
                stats['database_size_mb'] = self.db_path.stat().st_size / (1024 * 1024)
                
                return stats
        except sqlite3.Error as e:
            self.logger.error(f"Failed to get database stats: {e}")
            return {}
