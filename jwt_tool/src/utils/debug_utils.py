import logging
import sys

def setup_debug_logging(debug: bool = False):
    """Set up debug logging for the tool."""
    if debug:
    logging.basicConfig(
        level=logging.DEBUG,
        format='[%(levelname)s] %(asctime)s %(module)s: %(message)s',
        stream=sys.stdout
    )
    logging.debug("Debug logging is enabled.")
    else:
        logging.basicConfig(
            level=logging.INFO,
            format='[%(levelname)s] %(asctime)s %(module)s: %(message)s',
            stream=sys.stdout
        )

def debug_print(*args, **kwargs):
    """Print debug messages if logging is set to DEBUG."""
    if logging.getLogger().isEnabledFor(logging.DEBUG):
        print("[DEBUG]", *args, **kwargs) 