import sys
import traceback
import datetime
import os

DEBUG_MODE = False
LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs', 'error.log')


def set_debug(debug):
    global DEBUG_MODE
    DEBUG_MODE = debug


def info_log(msg):
    now = datetime.datetime.now().isoformat()
    log_entry = f"[INFO] {now} - {msg}\n"
    print(log_entry, end='')
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(log_entry)
    except Exception as log_exc:
        print(f"[ERROR] Failed to write to log file: {log_exc}")


def debug_log(msg):
    if DEBUG_MODE:
        now = datetime.datetime.now().isoformat()
        log_entry = f"[DEBUG] {now} - {msg}\n"
        print(log_entry, end='')
        try:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(log_entry)
        except Exception as log_exc:
            print(f"[ERROR] Failed to write to log file: {log_exc}")


def error_log(msg, exc=None):
    now = datetime.datetime.now().isoformat()
    log_entry = f"[ERROR] {now} - {msg}\n"
    print(log_entry, end='')
    if exc:
        log_entry += f"[ERROR] Exception: {exc}\n"
        print(f"[ERROR] Exception: {exc}")
        if DEBUG_MODE:
            stack = traceback.format_exc()
            print(stack)
            log_entry += stack + "\n"
    # Write to log file
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(log_entry)
    except Exception as log_exc:
        print(f"[ERROR] Failed to write to log file: {log_exc}")


def safe_run(func, *args, **kwargs):
    try:
        return func(*args, **kwargs)
    except Exception as e:
        error_log(f"Exception in {func.__name__}", e)
        return None 