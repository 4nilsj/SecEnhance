"""
SQLite database manager for storing scan results, performance metrics, and logs.
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from contextlib import contextmanager

from ..utils.logger import get_logger
from .config import get_config


class DatabaseManager:
    """Manages SQLite database operations for the API Security Scanner."""
    
    def __init__(self, db_path: Optional[str] = None):
        config = get_config()
        self.db_path = Path(db_path or config.database.path)
        self.logger = get_logger(__name__)
        self.backup_enabled = config.database.backup_enabled
        self.backup_interval = config.database.backup_interval
        self.max_backups = config.database.max_backups
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
                        plugins_used TEXT,
                        template_used TEXT,
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
                        refs TEXT,
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
                
                # Create custom_alerts table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS custom_alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT NOT NULL,
                        plugin_name TEXT NOT NULL,
                        vulnerability_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        title TEXT NOT NULL,
                        description TEXT,
                        evidence TEXT,
                        recommendation TEXT,
                        url TEXT,
                        method TEXT,
                        headers TEXT,
                        response_code INTEGER,
                        response_body TEXT,
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
                
                # Add new columns to existing scans table if they don't exist
                try:
                    cursor.execute("ALTER TABLE scans ADD COLUMN plugins_used TEXT")
                except sqlite3.OperationalError:
                    pass  # Column already exists
                
                try:
                    cursor.execute("ALTER TABLE scans ADD COLUMN template_used TEXT")
                except sqlite3.OperationalError:
                    pass  # Column already exists
                
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
                   input_source: str, auth_type: Optional[str] = None,
                   plugins_used: Optional[str] = None, template_used: Optional[str] = None) -> bool:
        """Create a new scan record."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO scans (scan_id, target_url, start_time, status, input_type, input_source, auth_type, plugins_used, template_used)
                    VALUES (?, ?, ?, 'running', ?, ?, ?, ?, ?)
                """, (scan_id, target_url, datetime.now(), input_type, input_source, auth_type, plugins_used, template_used))
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
    
    def add_custom_alert(self, scan_id: str, plugin_name: str, vulnerability_type: str,
                        severity: str, title: str, description: Optional[str] = None,
                        evidence: Optional[str] = None, recommendation: Optional[str] = None,
                        url: Optional[str] = None, method: Optional[str] = None, headers: Optional[Dict[str, str]] = None,
                        response_code: Optional[int] = None, response_body: Optional[str] = None) -> bool:
        """Add a custom plugin alert to the database."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO custom_alerts (
                        scan_id, plugin_name, vulnerability_type, severity, title,
                        description, evidence, recommendation, url, method, headers,
                        response_code, response_body
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_id, plugin_name, vulnerability_type, severity, title,
                    description, evidence, recommendation, url, method,
                    json.dumps(headers) if headers else None, response_code, response_body
                ))
                conn.commit()
                return True
        except sqlite3.Error as e:
            self.logger.error(f"Failed to add custom alert: {e}")
            return False
    
    def add_vulnerability(self, vulnerability_id: str, scan_id: str, name: str,
                         description: str, risk: str, cvss_score: float,
                         solution: str, references: List[str], cwe_id: str,
                         wasc_id: str, request: str, response: str, url: str,
                         parameter: str, evidence: str, source: str,
                         plugin_name: Optional[str] = None) -> bool:
        """Add a vulnerability to the database."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO vulnerabilities (
                        id, scan_id, name, description, risk, cvss_score,
                        solution, refs, cwe_id, wasc_id, request, response,
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
                         end_time: datetime, tests_performed: Optional[int] = None,
                         details: Optional[str] = None) -> bool:
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
    
    def reset_database(self, backup: bool = True) -> bool:
        """Reset the entire database by dropping all tables and recreating them.
        
        Args:
            backup: Whether to create a backup before resetting
            
        Returns:
            bool: True if reset was successful, False otherwise
        """
        try:
            # Create backup if requested
            if backup and self.db_path.exists():
                backup_path = self.db_path.with_suffix(f'.backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db')
                import shutil
                shutil.copy2(self.db_path, backup_path)
                self.logger.info(f"Database backed up to: {backup_path}")
            
            # Close any existing connections
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Get list of all tables (excluding sqlite_sequence)
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name != 'sqlite_sequence'")
                tables = [row['name'] for row in cursor.fetchall()]
                
                # Drop all tables
                for table in tables:
                    cursor.execute(f"DROP TABLE IF EXISTS {table}")
                    self.logger.info(f"Dropped table: {table}")
                
                # Clear sqlite_sequence table
                cursor.execute("DELETE FROM sqlite_sequence")
                self.logger.info("Cleared sqlite_sequence table")
                
                conn.commit()
            
            # Reinitialize database with fresh tables
            self._init_database()
            self.logger.info("Database reset completed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to reset database: {e}")
            return False
    
    def clear_all_data(self) -> bool:
        """Clear all data from all tables but keep the table structure.
        
        Returns:
            bool: True if clearing was successful, False otherwise
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Get list of all tables
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row['name'] for row in cursor.fetchall()]
                
                # Clear all tables
                for table in tables:
                    cursor.execute(f"DELETE FROM {table}")
                    self.logger.info(f"Cleared table: {table}")
                
                # Reset auto-increment sequences
                cursor.execute("DELETE FROM sqlite_sequence")
                
                conn.commit()
                self.logger.info("All data cleared successfully")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to clear database data: {e}")
            return False
    
    def get_database_info(self) -> Dict[str, Any]:
        """Get comprehensive database information including table sizes."""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                info = {
                    'database_path': str(self.db_path),
                    'database_size_mb': self.db_path.stat().st_size / (1024 * 1024) if self.db_path.exists() else 0,
                    'tables': {}
                }
                
                # Get table information
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row['name'] for row in cursor.fetchall()]
                
                for table in tables:
                    cursor.execute(f"SELECT COUNT(*) as count FROM {table}")
                    count = cursor.fetchone()['count']
                    info['tables'][table] = count
                
                return info
                
        except Exception as e:
            self.logger.error(f"Failed to get database info: {e}")
            return {}


class ReportManager:
    """Manages report files and cleanup operations."""
    
    def __init__(self, reports_dir: str = "reports"):
        self.reports_dir = Path(reports_dir)
        self.logger = get_logger(__name__)
    
    def get_reports_info(self) -> Dict[str, Any]:
        """Get comprehensive information about all report files."""
        try:
            if not self.reports_dir.exists():
                return {
                    'reports_dir': str(self.reports_dir),
                    'total_files': 0,
                    'total_size_mb': 0,
                    'file_types': {},
                    'files': []
                }
            
            files_info = []
            total_size = 0
            file_types = {}
            
            for file_path in self.reports_dir.iterdir():
                if file_path.is_file():
                    stat = file_path.stat()
                    file_size = stat.st_size
                    total_size += file_size
                    
                    # Get file extension
                    ext = file_path.suffix.lower()
                    if ext:
                        file_types[ext] = file_types.get(ext, 0) + 1
                    else:
                        file_types['no_extension'] = file_types.get('no_extension', 0) + 1
                    
                    files_info.append({
                        'name': file_path.name,
                        'size_bytes': file_size,
                        'size_mb': file_size / (1024 * 1024),
                        'extension': ext,
                        'created': datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
                        'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                        'path': str(file_path)
                    })
            
            # Sort files by modification time (newest first)
            files_info.sort(key=lambda x: x['modified'], reverse=True)
            
            return {
                'reports_dir': str(self.reports_dir),
                'total_files': len(files_info),
                'total_size_mb': total_size / (1024 * 1024),
                'file_types': file_types,
                'files': files_info
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get reports info: {e}")
            return {}
    
    def clear_all_reports(self, backup: bool = True) -> bool:
        """Clear all report files from the reports directory.
        
        Args:
            backup: Whether to create a backup before clearing
            
        Returns:
            bool: True if clearing was successful, False otherwise
        """
        try:
            if not self.reports_dir.exists():
                self.logger.info("Reports directory does not exist")
                return True
            
            # Get current reports info
            reports_info = self.get_reports_info()
            if reports_info.get('total_files', 0) == 0:
                self.logger.info("No reports to clear")
                return True
            
            # Create backup if requested
            if backup:
                backup_dir = self.reports_dir.parent / f"reports_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                import shutil
                shutil.copytree(self.reports_dir, backup_dir)
                self.logger.info(f"Reports backed up to: {backup_dir}")
            
            # Delete all files
            deleted_count = 0
            for file_path in self.reports_dir.iterdir():
                if file_path.is_file():
                    file_path.unlink()
                    deleted_count += 1
                    self.logger.info(f"Deleted report: {file_path.name}")
            
            self.logger.info(f"Cleared {deleted_count} report files")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to clear reports: {e}")
            return False
    
    def clear_old_reports(self, days: int = 30) -> int:
        """Clear report files older than specified days.
        
        Args:
            days: Number of days to keep reports
            
        Returns:
            int: Number of files deleted
        """
        try:
            if not self.reports_dir.exists():
                return 0
            
            cutoff_time = datetime.now().timestamp() - (days * 24 * 60 * 60)
            deleted_count = 0
            
            for file_path in self.reports_dir.iterdir():
                if file_path.is_file() and file_path.stat().st_mtime < cutoff_time:
                    file_path.unlink()
                    deleted_count += 1
                    self.logger.info(f"Deleted old report: {file_path.name}")
            
            self.logger.info(f"Cleared {deleted_count} old report files")
            return deleted_count
            
        except Exception as e:
            self.logger.error(f"Failed to clear old reports: {e}")
            return 0
    
    def clear_reports_by_type(self, file_extensions: List[str]) -> int:
        """Clear report files by file extension.
        
        Args:
            file_extensions: List of file extensions to delete (e.g., ['.html', '.pdf'])
            
        Returns:
            int: Number of files deleted
        """
        try:
            if not self.reports_dir.exists():
                return 0
            
            deleted_count = 0
            extensions = [ext.lower() if ext.startswith('.') else f'.{ext.lower()}' for ext in file_extensions]
            
            for file_path in self.reports_dir.iterdir():
                if file_path.is_file() and file_path.suffix.lower() in extensions:
                    file_path.unlink()
                    deleted_count += 1
                    self.logger.info(f"Deleted {file_path.suffix} report: {file_path.name}")
            
            self.logger.info(f"Cleared {deleted_count} report files of specified types")
            return deleted_count
            
        except Exception as e:
            self.logger.error(f"Failed to clear reports by type: {e}")
            return 0
    
    def clear_reports_by_pattern(self, pattern: str) -> int:
        """Clear report files matching a specific pattern.
        
        Args:
            pattern: Pattern to match in filenames (supports wildcards)
            
        Returns:
            int: Number of files deleted
        """
        try:
            if not self.reports_dir.exists():
                return 0
            
            import fnmatch
            deleted_count = 0
            
            for file_path in self.reports_dir.iterdir():
                if file_path.is_file() and fnmatch.fnmatch(file_path.name, pattern):
                    file_path.unlink()
                    deleted_count += 1
                    self.logger.info(f"Deleted matching report: {file_path.name}")
            
            self.logger.info(f"Cleared {deleted_count} report files matching pattern: {pattern}")
            return deleted_count
            
        except Exception as e:
            self.logger.error(f"Failed to clear reports by pattern: {e}")
            return 0