import argparse
import pandas as pd
import sqlite3
from utils.data_sync_utils import read_excel, write_excel, read_sqlite, write_sqlite

def sync_excel_to_sqlite(excel_path, sheet, db_path, table_name):
    df = read_excel(excel_path, sheet)
    write_sqlite(df, db_path, table_name)
    print(f"Synced {len(df)} rows from Excel to SQLite ({table_name})")

def sync_sqlite_to_excel(db_path, table_name, excel_path, sheet):
    df = read_sqlite(db_path, table_name)
    write_excel(df, excel_path, sheet)
    print(f"Synced {len(df)} rows from SQLite ({table_name}) to Excel")

def main():
    parser = argparse.ArgumentParser(description="Sync/restore Excel and SQLite in either direction.")
    parser.add_argument("--excel", required=True, help="Excel file path")
    parser.add_argument("--sheet", default=0, help="Sheet name or index")
    parser.add_argument("--db", default="tickets.db", help="SQLite DB file path")
    parser.add_argument("--table", default="tickets", help="Table name in SQLite DB")
    parser.add_argument("--direction", choices=["excel_to_sqlite", "sqlite_to_excel"], required=True, help="Sync direction")
    args = parser.parse_args()

    if args.direction == "excel_to_sqlite":
        sync_excel_to_sqlite(args.excel, args.sheet, args.db, args.table)
    else:
        sync_sqlite_to_excel(args.db, args.table, args.excel, args.sheet)

if __name__ == "__main__":
    main() 