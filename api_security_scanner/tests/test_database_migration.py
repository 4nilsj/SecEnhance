"""
Unit tests for database migration functionality.
Tests the migration logic for adding plugin and template columns to existing databases.
"""

import pytest
import sqlite3
from pathlib import Path
from unittest.mock import patch, Mock

from api_security_scanner.core.db_manager import DatabaseManager


class TestDatabaseMigration:
    """Test database migration for plugin and template columns."""
    
    def test_migration_adds_plugins_used_column(self, tmp_path):
        """Test that migration adds plugins_used column to existing scans table."""
        db_path = tmp_path / "test_migration.db"
        
        # Create a database with the old schema (without new columns)
        with sqlite3.connect(str(db_path)) as conn:
            cursor = conn.cursor()
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
            conn.commit()
        
        # Initialize DatabaseManager which should run migration
        db_manager = DatabaseManager(str(db_path))
        
        # Verify the column was added
        with db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(scans)")
            columns = [row[1] for row in cursor.fetchall()]
            
            assert 'plugins_used' in columns
    
    def test_migration_adds_template_used_column(self, tmp_path):
        """Test that migration adds template_used column to existing scans table."""
        db_path = tmp_path / "test_migration.db"
        
        # Create a database with the old schema (without new columns)
        with sqlite3.connect(str(db_path)) as conn:
            cursor = conn.cursor()
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
            conn.commit()
        
        # Initialize DatabaseManager which should run migration
        db_manager = DatabaseManager(str(db_path))
        
        # Verify the column was added
        with db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(scans)")
            columns = [row[1] for row in cursor.fetchall()]
            
            assert 'template_used' in columns
    
    def test_migration_handles_existing_columns(self, tmp_path):
        """Test that migration handles existing columns gracefully."""
        db_path = tmp_path / "test_migration.db"
        
        # Create a database with the new schema already present
        with sqlite3.connect(str(db_path)) as conn:
            cursor = conn.cursor()
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
            conn.commit()
        
        # Initialize DatabaseManager - should not fail even though columns already exist
        db_manager = DatabaseManager(str(db_path))
        
        # Verify the columns still exist
        with db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(scans)")
            columns = [row[1] for row in cursor.fetchall()]
            
            assert 'plugins_used' in columns
            assert 'template_used' in columns
    
    def test_migration_preserves_existing_data(self, tmp_path):
        """Test that migration preserves existing data in the scans table."""
        db_path = tmp_path / "test_migration.db"
        
        # Create a database with old schema and some data
        with sqlite3.connect(str(db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    target_url TEXT NOT NULL,
                    start_time TIMESTAMP NOT NULL,
                    status TEXT NOT NULL,
                    input_type TEXT,
                    input_source TEXT,
                    auth_type TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Insert some test data
            cursor.execute("""
                INSERT INTO scans (scan_id, target_url, start_time, status, input_type, input_source)
                VALUES (?, ?, ?, ?, ?, ?)
            """, ('test_scan_1', 'https://example.com', '2025-01-01 10:00:00', 'completed', 'curl', 'curl command'))
            
            conn.commit()
        
        # Initialize DatabaseManager which should run migration
        db_manager = DatabaseManager(str(db_path))
        
        # Verify existing data is preserved
        with db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans WHERE scan_id = ?", ('test_scan_1',))
            row = cursor.fetchone()
            
            assert row is not None
            assert row['scan_id'] == 'test_scan_1'
            assert row['target_url'] == 'https://example.com'
            assert row['input_type'] == 'curl'
            assert row['input_source'] == 'curl command'
            # New columns should be NULL for existing data
            assert row['plugins_used'] is None
            assert row['template_used'] is None
    
    def test_migration_handles_multiple_attempts(self, tmp_path):
        """Test that migration can be run multiple times safely."""
        db_path = tmp_path / "test_migration.db"
        
        # Create a database with old schema
        with sqlite3.connect(str(db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    target_url TEXT NOT NULL,
                    start_time TIMESTAMP NOT NULL,
                    status TEXT NOT NULL,
                    input_type TEXT,
                    input_source TEXT,
                    auth_type TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
        
        # Initialize DatabaseManager multiple times
        db_manager1 = DatabaseManager(str(db_path))
        db_manager2 = DatabaseManager(str(db_path))
        db_manager3 = DatabaseManager(str(db_path))
        
        # All should work without errors
        assert db_manager1 is not None
        assert db_manager2 is not None
        assert db_manager3 is not None
        
        # Verify columns exist
        with db_manager1.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(scans)")
            columns = [row[1] for row in cursor.fetchall()]
            
            assert 'plugins_used' in columns
            assert 'template_used' in columns
    
    def test_migration_with_existing_scans_data(self, tmp_path):
        """Test migration with existing scans and ability to add new data."""
        db_path = tmp_path / "test_migration.db"
        
        # Create database with old schema and data
        with sqlite3.connect(str(db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    target_url TEXT NOT NULL,
                    start_time TIMESTAMP NOT NULL,
                    status TEXT NOT NULL,
                    input_type TEXT,
                    input_source TEXT,
                    auth_type TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Insert existing data
            cursor.execute("""
                INSERT INTO scans (scan_id, target_url, start_time, status, input_type, input_source)
                VALUES (?, ?, ?, ?, ?, ?)
            """, ('old_scan', 'https://old.example.com', '2025-01-01 10:00:00', 'completed', 'file', 'old.json'))
            
            conn.commit()
        
        # Initialize DatabaseManager (runs migration)
        db_manager = DatabaseManager(str(db_path))
        
        # Add new scan with plugin and template info
        result = db_manager.create_scan(
            scan_id='new_scan',
            target_url='https://new.example.com',
            input_type='curl',
            input_source='curl -X GET https://new.example.com',
            plugins_used='SecurityHeadersChecker,CORSChecker',
            template_used='quick'
        )
        
        assert result is True
        
        # Verify both old and new data exist
        with db_manager.get_connection() as conn:
            cursor = conn.cursor()
            
            # Check old scan (should have NULL for new columns)
            cursor.execute("SELECT * FROM scans WHERE scan_id = ?", ('old_scan',))
            old_row = cursor.fetchone()
            assert old_row is not None
            assert old_row['plugins_used'] is None
            assert old_row['template_used'] is None
            
            # Check new scan (should have values for new columns)
            cursor.execute("SELECT * FROM scans WHERE scan_id = ?", ('new_scan',))
            new_row = cursor.fetchone()
            assert new_row is not None
            assert new_row['plugins_used'] == 'SecurityHeadersChecker,CORSChecker'
            assert new_row['template_used'] == 'quick'
    
    def test_migration_error_handling(self, tmp_path):
        """Test that migration handles errors gracefully."""
        db_path = tmp_path / "test_migration.db"
        
        # Create a database with old schema
        with sqlite3.connect(str(db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    target_url TEXT NOT NULL,
                    start_time TIMESTAMP NOT NULL,
                    status TEXT NOT NULL,
                    input_type TEXT,
                    input_source TEXT,
                    auth_type TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
        
        # Mock sqlite3.OperationalError to test error handling
        with patch('sqlite3.connect') as mock_connect:
            mock_conn = Mock()
            mock_cursor = Mock()
            mock_connect.return_value.__enter__.return_value = mock_conn
            mock_conn.cursor.return_value = mock_cursor
            
            # First call succeeds (table creation), second call raises error (column addition)
            mock_cursor.execute.side_effect = [
                None,  # Table creation succeeds
                sqlite3.OperationalError("column already exists")  # Column addition fails
            ]
            
            # Should not raise an exception
            db_manager = DatabaseManager(str(db_path))
            assert db_manager is not None
    
    def test_migration_column_types(self, tmp_path):
        """Test that migrated columns have correct types."""
        db_path = tmp_path / "test_migration.db"
        
        # Create database with old schema
        with sqlite3.connect(str(db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    target_url TEXT NOT NULL,
                    start_time TIMESTAMP NOT NULL,
                    status TEXT NOT NULL,
                    input_type TEXT,
                    input_source TEXT,
                    auth_type TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
        
        # Initialize DatabaseManager (runs migration)
        db_manager = DatabaseManager(str(db_path))
        
        # Check column types
        with db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(scans)")
            columns_info = cursor.fetchall()
            
            # Find the new columns and check their types
            plugins_used_info = None
            template_used_info = None
            
            for col_info in columns_info:
                if col_info[1] == 'plugins_used':
                    plugins_used_info = col_info
                elif col_info[1] == 'template_used':
                    template_used_info = col_info
            
            assert plugins_used_info is not None
            assert template_used_info is not None
            assert plugins_used_info[2] == 'TEXT'  # Column type
            assert template_used_info[2] == 'TEXT'  # Column type
            assert plugins_used_info[3] == 0  # Not null = 0 (nullable)
            assert template_used_info[3] == 0  # Not null = 0 (nullable)
