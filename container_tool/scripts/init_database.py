#!/usr/bin/env python3
"""
Database Initialization Script
Initializes the local vulnerability database and downloads initial NVD data.
"""

import sys
import os
import argparse
from datetime import datetime, timedelta

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from database.local_vulnerability_db import LocalVulnerabilityDB
from utils.debug_utils import setup_debug_logging, debug_print

def init_database(years: list = None, force_update: bool = False, debug: bool = False):
    """
    Initialize the local vulnerability database.
    
    Args:
        years: List of years to download NVD data for
        force_update: Force update even if data exists
        debug: Enable debug mode
    """
    
    if debug:
        setup_debug_logging()
        debug_print("Database initialization started in debug mode")
    
    print("🔧 Initializing Local Vulnerability Database")
    print("=" * 50)
    
    try:
        # Initialize database
        print("📊 Creating database tables...")
        db = LocalVulnerabilityDB(debug=debug)
        
        # Get database statistics
        stats = db.get_vulnerability_stats()
        print(f"✅ Database initialized successfully")
        print(f"   - Database path: {db.db_path}")
        print(f"   - Existing vulnerabilities: {stats.get('total_vulnerabilities', 0)}")
        print(f"   - Existing affected packages: {stats.get('total_affected_packages', 0)}")
        
        # Determine years to download
        if years is None:
            current_year = datetime.now().year
            # Download current year and previous 2 years
            years = list(range(current_year - 2, current_year + 1))
        
        print(f"\n📥 Downloading NVD data for years: {years}")
        print("-" * 50)
        
        successful_downloads = 0
        failed_downloads = 0
        
        for year in years:
            print(f"\n🔍 Processing year {year}...")
            
            try:
                success = db.download_nvd_data(year, force_update)
                
                if success:
                    print(f"   ✅ Successfully downloaded NVD data for {year}")
                    successful_downloads += 1
                else:
                    print(f"   ❌ Failed to download NVD data for {year}")
                    failed_downloads += 1
                    
            except Exception as e:
                print(f"   ❌ Error processing {year}: {str(e)}")
                failed_downloads += 1
                if debug:
                    debug_print(f"Exception for year {year}: {str(e)}")
        
        # Final statistics
        print(f"\n📊 Download Summary")
        print("-" * 30)
        print(f"   - Successful downloads: {successful_downloads}")
        print(f"   - Failed downloads: {failed_downloads}")
        print(f"   - Total years processed: {len(years)}")
        
        # Updated database statistics
        final_stats = db.get_vulnerability_stats()
        print(f"\n📈 Final Database Statistics")
        print("-" * 30)
        print(f"   - Total vulnerabilities: {final_stats.get('total_vulnerabilities', 0)}")
        print(f"   - Total affected packages: {final_stats.get('total_affected_packages', 0)}")
        
        # Severity breakdown
        severity_breakdown = final_stats.get('severity_breakdown', {})
        if severity_breakdown:
            print(f"   - Severity breakdown:")
            for severity, count in severity_breakdown.items():
                print(f"     • {severity}: {count}")
        
        # Package managers
        package_managers = final_stats.get('package_managers', {})
        if package_managers:
            print(f"   - Package managers:")
            for manager, count in package_managers.items():
                print(f"     • {manager}: {count}")
        
        # Recent vulnerabilities
        recent_vulns = final_stats.get('recent_vulnerabilities', 0)
        print(f"   - Recent vulnerabilities (30 days): {recent_vulns}")
        
        # Close database
        db.close()
        
        print(f"\n✅ Database initialization completed successfully!")
        
        if failed_downloads > 0:
            print(f"⚠️  {failed_downloads} downloads failed. Check the output above for details.")
        
        return successful_downloads > 0
        
    except Exception as e:
        print(f"❌ Database initialization failed: {str(e)}")
        if debug:
            debug_print(f"Initialization exception: {str(e)}")
        return False

def update_database(years: list = None, debug: bool = False):
    """
    Update existing database with new NVD data.
    
    Args:
        years: List of years to update (defaults to current year)
        debug: Enable debug mode
    """
    
    if debug:
        setup_debug_logging()
        debug_print("Database update started in debug mode")
    
    print("🔄 Updating Local Vulnerability Database")
    print("=" * 50)
    
    try:
        # Initialize database
        db = LocalVulnerabilityDB(debug=debug)
        
        # Get current statistics
        stats = db.get_vulnerability_stats()
        print(f"📊 Current database statistics:")
        print(f"   - Total vulnerabilities: {stats.get('total_vulnerabilities', 0)}")
        print(f"   - Total affected packages: {stats.get('total_affected_packages', 0)}")
        
        # Determine years to update
        if years is None:
            current_year = datetime.now().year
            years = [current_year]
        
        print(f"\n📥 Updating NVD data for years: {years}")
        print("-" * 50)
        
        successful_updates = 0
        failed_updates = 0
        
        for year in years:
            print(f"\n🔍 Updating year {year}...")
            
            try:
                # Force update for specified years
                success = db.download_nvd_data(year, force_update=True)
                
                if success:
                    print(f"   ✅ Successfully updated NVD data for {year}")
                    successful_updates += 1
                else:
                    print(f"   ❌ Failed to update NVD data for {year}")
                    failed_updates += 1
                    
            except Exception as e:
                print(f"   ❌ Error updating {year}: {str(e)}")
                failed_updates += 1
                if debug:
                    debug_print(f"Update exception for year {year}: {str(e)}")
        
        # Final statistics
        print(f"\n📊 Update Summary")
        print("-" * 30)
        print(f"   - Successful updates: {successful_updates}")
        print(f"   - Failed updates: {failed_updates}")
        
        # Updated database statistics
        final_stats = db.get_vulnerability_stats()
        print(f"\n📈 Updated Database Statistics")
        print("-" * 30)
        print(f"   - Total vulnerabilities: {final_stats.get('total_vulnerabilities', 0)}")
        print(f"   - Total affected packages: {final_stats.get('total_affected_packages', 0)}")
        
        # Recent vulnerabilities
        recent_vulns = final_stats.get('recent_vulnerabilities', 0)
        print(f"   - Recent vulnerabilities (30 days): {recent_vulns}")
        
        # Close database
        db.close()
        
        print(f"\n✅ Database update completed successfully!")
        
        if failed_updates > 0:
            print(f"⚠️  {failed_updates} updates failed. Check the output above for details.")
        
        return successful_updates > 0
        
    except Exception as e:
        print(f"❌ Database update failed: {str(e)}")
        if debug:
            debug_print(f"Update exception: {str(e)}")
        return False

def show_database_info(debug: bool = False):
    """
    Show current database information and statistics.
    
    Args:
        debug: Enable debug mode
    """
    
    if debug:
        setup_debug_logging()
        debug_print("Database info started in debug mode")
    
    print("📊 Local Vulnerability Database Information")
    print("=" * 50)
    
    try:
        # Initialize database
        db = LocalVulnerabilityDB(debug=debug)
        
        # Database path
        print(f"📁 Database Path: {db.db_path}")
        
        # Check if database exists and has data
        if os.path.exists(db.db_path):
            file_size = os.path.getsize(db.db_path)
            print(f"📏 Database Size: {file_size / (1024*1024):.2f} MB")
        else:
            print("📏 Database Size: Not created yet")
            return
        
        # Get statistics
        stats = db.get_vulnerability_stats()
        
        print(f"\n📈 Database Statistics")
        print("-" * 30)
        print(f"   - Total vulnerabilities: {stats.get('total_vulnerabilities', 0)}")
        print(f"   - Total affected packages: {stats.get('total_affected_packages', 0)}")
        
        # Severity breakdown
        severity_breakdown = stats.get('severity_breakdown', {})
        if severity_breakdown:
            print(f"\n🚨 Severity Breakdown")
            print("-" * 30)
            for severity, count in severity_breakdown.items():
                print(f"   - {severity}: {count}")
        
        # Package managers
        package_managers = stats.get('package_managers', {})
        if package_managers:
            print(f"\n📦 Package Managers")
            print("-" * 30)
            for manager, count in package_managers.items():
                print(f"   - {manager}: {count}")
        
        # Recent vulnerabilities
        recent_vulns = stats.get('recent_vulnerabilities', 0)
        print(f"\n🕒 Recent Activity")
        print("-" * 30)
        print(f"   - Recent vulnerabilities (30 days): {recent_vulns}")
        
        # Scan history
        scan_history = db.get_scan_history(limit=5)
        if scan_history:
            print(f"\n🔍 Recent Scans")
            print("-" * 30)
            for scan in scan_history:
                print(f"   - {scan['image_name']} ({scan['scan_date'][:10]})")
                print(f"     • Vulnerable packages: {scan['vulnerable_packages']}/{scan['total_packages']}")
                print(f"     • Critical: {scan['critical_vulnerabilities']}, High: {scan['high_vulnerabilities']}")
        
        # Close database
        db.close()
        
        print(f"\n✅ Database information retrieved successfully!")
        
    except Exception as e:
        print(f"❌ Error retrieving database information: {str(e)}")
        if debug:
            debug_print(f"Info exception: {str(e)}")

def main():
    """Main function for database initialization."""
    parser = argparse.ArgumentParser(description="Local Vulnerability Database Initialization")
    
    # Command options
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Init command
    init_parser = subparsers.add_parser('init', help='Initialize database with NVD data')
    init_parser.add_argument('--years', nargs='+', type=int, 
                           help='Years to download (default: current year and previous 2 years)')
    init_parser.add_argument('--force', action='store_true', 
                           help='Force update even if data exists')
    
    # Update command
    update_parser = subparsers.add_parser('update', help='Update existing database')
    update_parser.add_argument('--years', nargs='+', type=int,
                             help='Years to update (default: current year)')
    
    # Info command
    info_parser = subparsers.add_parser('info', help='Show database information')
    
    # Global options
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        if args.command == 'init':
            success = init_database(args.years, args.force, args.debug)
            sys.exit(0 if success else 1)
            
        elif args.command == 'update':
            success = update_database(args.years, args.debug)
            sys.exit(0 if success else 1)
            
        elif args.command == 'info':
            show_database_info(args.debug)
            sys.exit(0)
            
    except KeyboardInterrupt:
        print("\n⚠️  Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main() 