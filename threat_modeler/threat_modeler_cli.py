#!/usr/bin/env python3
"""
Threat Modeling Tool CLI
Comprehensive threat modeling for application security analysis.
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.threat_modeler import ThreatModeler
from src.debug_utils import setup_debug_logging

def main():
    """Main CLI entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Comprehensive Threat Modeling Tool for Application Security Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode
  python threat_modeler_cli.py
  
  # File input mode
  python threat_modeler_cli.py -i architecture.yaml -m STRIDE
  
  # Generate HTML report
  python threat_modeler_cli.py -i architecture.json -o html -f report.html
  
  # Debug mode
  python threat_modeler_cli.py --debug -i architecture.txt
        """
    )
    
    parser.add_argument(
        '-i', '--input-file',
        help='Input architecture file (JSON, YAML, or text)'
    )
    
    parser.add_argument(
        '-m', '--methodology',
        choices=['STRIDE', 'PASTA', 'DREAD'],
        default='STRIDE',
        help='Threat modeling methodology (default: STRIDE)'
    )
    
    parser.add_argument(
        '-o', '--output-format',
        choices=['markdown', 'html', 'json'],
        default='markdown',
        help='Output report format (default: markdown)'
    )
    
    parser.add_argument(
        '-f', '--output-file',
        help='Output file path'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Threat Modeling Tool v1.0.0'
    )
    
    args = parser.parse_args()
    
    try:
        # Setup debug logging
        setup_debug_logging(args.debug)
        
        # Initialize threat modeler
        modeler = ThreatModeler(debug=args.debug)
        
        # Run analysis
        if args.input_file:
            modeler.run_file_input(args.input_file, args.methodology)
        else:
            modeler.run_interactive()
            
    except KeyboardInterrupt:
        print("\nThreat modeling interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main() 