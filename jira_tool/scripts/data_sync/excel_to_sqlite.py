import argparse
import pandas as pd
import sqlite3
import sys
import os

# Add the parent directory to the path to import utils modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from utils.data_sync_utils import read_excel, write_sqlite


def excel_to_sqlite(excel_path, sheet, db_path, table_name):
    df = read_excel(excel_path, sheet)
    write_sqlite(df, db_path, table_name)
    print(f"Imported {len(df)} rows from {excel_path} to {db_path} (table: {table_name})")


def main():
    parser = argparse.ArgumentParser(description="Import Excel data into SQLite database.")
    parser.add_argument("--excel", required=True, help="Path to Excel file")
    parser.add_argument("--sheet", default=0, help="Sheet name or index")
    parser.add_argument("--db", default="tickets.db", help="SQLite DB file path")
    parser.add_argument("--table", default="tickets", help="Table name in SQLite DB")
    args = parser.parse_args()
    excel_to_sqlite(args.excel, args.sheet, args.db, args.table)

if __name__ == "__main__":
    main() 