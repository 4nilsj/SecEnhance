import argparse
from utils.data_sync_utils import read_excel, write_sqlite


def excel_to_sqlite(excel_path, sheet, db_path, table_name):
    df = pd.read_excel(excel_path, sheet_name=sheet)
    conn = sqlite3.connect(db_path)
    df.to_sql(table_name, conn, if_exists='replace', index=False)
    conn.close()
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