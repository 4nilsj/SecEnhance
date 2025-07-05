import logging
import sys

def setup_debug_logging():
    """Set up debug logging for the API security testing tool."""
    logging.basicConfig(
        level=logging.DEBUG,
        format='[%(levelname)s] %(asctime)s %(module)s: %(message)s',
        stream=sys.stdout
    )
    logging.debug("Debug logging is enabled for API security testing tool.")

def debug_print(*args, **kwargs):
    """Print debug messages if logging is set to DEBUG."""
    if logging.getLogger().isEnabledFor(logging.DEBUG):
        print("[DEBUG]", *args, **kwargs) 