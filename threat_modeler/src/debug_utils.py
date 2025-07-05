"""
Debug utilities for Threat Modeling Tool
Provides debug logging and print functionality for troubleshooting and development.
"""

import logging
import sys
from typing import Any, Optional
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

# Global debug flag
DEBUG_MODE = False

# Rich console for colored output
console = Console()

def setup_debug_logging(debug: bool = False) -> None:
    """Setup debug logging configuration."""
    global DEBUG_MODE
    DEBUG_MODE = debug
    
    if debug:
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler('threat_modeler_debug.log')
            ]
        )
        console.print("[bold green]Debug mode enabled[/bold green]")
    else:
        logging.basicConfig(level=logging.INFO)

def debug_print(message: str, data: Optional[Any] = None, level: str = "INFO") -> None:
    """Print debug information with optional data."""
    if not DEBUG_MODE:
        return
    
    # Color coding for different debug levels
    colors = {
        "INFO": "blue",
        "WARNING": "yellow", 
        "ERROR": "red",
        "SUCCESS": "green",
        "DEBUG": "cyan"
    }
    
    color = colors.get(level, "white")
    
    # Create debug panel
    debug_text = Text(f"[{level}] {message}", style=color)
    
    if data is not None:
        debug_text.append(f"\n\nData: {str(data)}", style="dim")
    
    panel = Panel(
        debug_text,
        title=f"Debug {level}",
        border_style=color,
        padding=(0, 1)
    )
    
    console.print(panel)

def debug_log(component: str, message: str, data: Optional[Any] = None) -> None:
    """Log debug information with component context."""
    if not DEBUG_MODE:
        return
    
    logger = logging.getLogger(f"threat_modeler.{component}")
    if data:
        logger.debug(f"{message} | Data: {data}")
    else:
        logger.debug(message)
    
    debug_print(f"[{component}] {message}", data)

def debug_architecture(architecture_data: dict) -> None:
    """Debug print architecture data."""
    if not DEBUG_MODE:
        return
    
    debug_print("Architecture Data", architecture_data, "DEBUG")

def debug_threats(threats: list) -> None:
    """Debug print threats data."""
    if not DEBUG_MODE:
        return
    
    debug_print("Threats Analysis", threats, "DEBUG")

def debug_mitigations(mitigations: dict) -> None:
    """Debug print mitigations data."""
    if not DEBUG_MODE:
        return
    
    debug_print("Mitigations Mapping", mitigations, "DEBUG")

def debug_report(report_data: dict) -> None:
    """Debug print report generation data."""
    if not DEBUG_MODE:
        return
    
    debug_print("Report Generation", report_data, "DEBUG") 