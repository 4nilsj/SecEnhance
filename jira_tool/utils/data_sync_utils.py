import pandas as pd
import sqlite3
import os
from debug_utils import debug_log, error_log, safe_run

def read_excel(excel_path, sheet=0):
    debug_log(f"Reading Excel: {excel_path}, sheet: {sheet}")
    try:
        return pd.read_excel(excel_path, sheet_name=sheet)
    except Exception as e:
        error_log(f"Failed to read Excel file: {excel_path}", e)
        return pd.DataFrame()

def write_excel(df, excel_path, sheet=0):
    debug_log(f"Writing Excel: {excel_path}, sheet: {sheet}")
    try:
        df.to_excel(excel_path, sheet_name=sheet, index=False)
    except Exception as e:
        error_log(f"Failed to write Excel file: {excel_path}", e)

def read_sqlite(db_path, table_name):
    debug_log(f"Reading SQLite: {db_path}, table: {table_name}")
    try:
        conn = sqlite3.connect(db_path)
        df = pd.read_sql_query(f'SELECT * FROM {table_name}', conn)
        conn.close()
        return df
    except Exception as e:
        error_log(f"Failed to read SQLite DB: {db_path}, table: {table_name}", e)
        return pd.DataFrame()

def write_sqlite(df, db_path, table_name):
    debug_log(f"Writing SQLite: {db_path}, table: {table_name}")
    try:
        conn = sqlite3.connect(db_path)
        df.to_sql(table_name, conn, if_exists='replace', index=False)
        conn.close()
    except Exception as e:
        error_log(f"Failed to write SQLite DB: {db_path}, table: {table_name}", e)

def update_row(df, key_col, key_val, updates):
    debug_log(f"Updating row where {key_col}={key_val} with {updates}")
    try:
        idx = df[df[key_col] == key_val].index
        if not idx.empty:
            for col, val in updates.items():
                df.at[idx[0], col] = val
        return df
    except Exception as e:
        error_log(f"Failed to update row in DataFrame", e)
        return df

def add_row(df, row_dict):
    debug_log(f"Adding row: {row_dict}")
    try:
        return pd.concat([df, pd.DataFrame([row_dict])], ignore_index=True)
    except Exception as e:
        error_log(f"Failed to add row to DataFrame", e)
        return df

def delete_row(df, key_col, key_val):
    debug_log(f"Deleting row where {key_col}={key_val}")
    try:
        return df[df[key_col] != key_val].reset_index(drop=True)
    except Exception as e:
        error_log(f"Failed to delete row from DataFrame", e)
        return df

def sync_resources(df, excel_path, db_path, table_name, sheet=0):
    debug_log(f"Syncing resources: Excel={excel_path}, DB={db_path}, Table={table_name}, Sheet={sheet}")
    write_excel(df, excel_path, sheet)
    write_sqlite(df, db_path, table_name) 