"""
CLI Autocomplete functionality for the API Security Scanner.
Provides intelligent command suggestions and tab completion.
"""

import os
import json
import glob
from typing import List, Dict, Any, Optional
from pathlib import Path


class AutocompleteManager:
    """Manages CLI autocomplete functionality."""
    
    def __init__(self):
        self.command_suggestions = self._load_command_suggestions()
        self.file_patterns = self._load_file_patterns()
        self.plugin_names = self._load_plugin_names()
        self.template_names = self._load_template_names()
    
    def _load_command_suggestions(self) -> Dict[str, List[str]]:
        """Load command suggestions for different contexts."""
        return {
            'main_commands': [
                'scan', 'config', 'list-scans', 'show-scan', 'cleanup', 'stats',
                'reset-db', 'clear-db', 'db-info', 'reports-info', 'clear-reports',
                'cleanup-reports', 'clear-reports-by-type', 'clear-reports-by-pattern',
                'templates', 'plugins', 'help', 'ls', 'show', 'clean', 'reset', 'clear',
                'reports', 'clear-reports'
            ],
            'scan_options': [
                '--file', '-f', '--curl', '-u', '--auth-type', '-a', '--auth-name', '-n',
                '--auth-value', '-v', '--zap-path', '--zap-port', '--zap-host',
                '--db-path', '--export', '--export-json', '--export-pdf', '--export-excel',
                '--export-xml', '--performance-stats', '--no-zap', '--no-plugins',
                '--plugins', '--spider-depth', '--spider-children', '--max-scan-time',
                '--no-progress', '--template'
            ],
            'config_options': [
                '--env-file', '--save-config', '--show-config', '--wizard'
            ],
            'auth_types': ['header', 'cookie', 'token'],
            'templates': ['quick', 'comprehensive', 'jwt-focused', 'api-only', 'zap-only'],
            'report_formats': ['html', 'json', 'pdf', 'excel', 'xml'],
            'file_extensions': ['.json', '.yaml', '.yml', '.har', '.curl']
        }
    
    def _load_file_patterns(self) -> Dict[str, List[str]]:
        """Load file patterns for different input types."""
        return {
            'postman': ['*collection*.json', '*postman*.json'],
            'openapi': ['*openapi*.json', '*openapi*.yaml', '*openapi*.yml', 
                       '*swagger*.json', '*swagger*.yaml', '*swagger*.yml'],
            'har': ['*.har'],
            'curl': ['*.curl', '*.txt']
        }
    
    def _load_plugin_names(self) -> List[str]:
        """Load available plugin names from the plugins directory."""
        try:
            plugins_dir = Path("api_security_scanner/plugins")
            if plugins_dir.exists():
                plugin_files = list(plugins_dir.glob("*.py"))
                plugin_names = []
                for plugin_file in plugin_files:
                    if plugin_file.name != "__init__.py":
                        # Extract class name from file
                        class_name = plugin_file.stem.replace("_", "").title() + "Checker"
                        plugin_names.append(class_name)
                return plugin_names
        except Exception:
            pass
        
        # Fallback to known plugins
        return [
            'SecurityHeadersChecker', 'CORSChecker', 'JWTSecurityChecker',
            'ParameterPollutionChecker', 'RateLimitingChecker', 'ComprehensiveSecurityChecker',
            'EnhancedSecurityChecker'
        ]
    
    def _load_template_names(self) -> List[str]:
        """Load available template names."""
        return ['quick', 'comprehensive', 'jwt-focused', 'api-only', 'zap-only']
    
    def get_suggestions(self, context: str, partial: str = "") -> List[str]:
        """Get suggestions based on context and partial input."""
        suggestions = []
        
        if context == "main_command":
            suggestions = self.command_suggestions['main_commands']
        elif context == "scan_option":
            suggestions = self.command_suggestions['scan_options']
        elif context == "config_option":
            suggestions = self.command_suggestions['config_options']
        elif context == "auth_type":
            suggestions = self.command_suggestions['auth_types']
        elif context == "template":
            suggestions = self.command_suggestions['templates']
        elif context == "plugin":
            suggestions = self.plugin_names
        elif context == "file":
            suggestions = self._get_file_suggestions(partial)
        elif context == "report_format":
            suggestions = self.command_suggestions['report_formats']
        
        # Filter suggestions based on partial input
        if partial:
            suggestions = [s for s in suggestions if s.lower().startswith(partial.lower())]
        
        return suggestions
    
    def _get_file_suggestions(self, partial: str = "") -> List[str]:
        """Get file suggestions based on partial path."""
        suggestions = []
        
        # Get current directory files
        try:
            current_dir = Path.cwd()
            
            # Look for common API files
            for pattern in ['*.json', '*.yaml', '*.yml', '*.har']:
                files = list(current_dir.glob(pattern))
                suggestions.extend([str(f.name) for f in files])
            
            # Look in common subdirectories
            for subdir in ['examples', 'collections', 'api', 'specs']:
                subdir_path = current_dir / subdir
                if subdir_path.exists():
                    for pattern in ['*.json', '*.yaml', '*.yml', '*.har']:
                        files = list(subdir_path.glob(pattern))
                        suggestions.extend([f"{subdir}/{f.name}" for f in files])
            
            # Filter based on partial input
            if partial:
                suggestions = [s for s in suggestions if s.lower().startswith(partial.lower())]
            
        except Exception:
            pass
        
        return suggestions[:20]  # Limit to 20 suggestions
    
    def get_context_help(self, command: str) -> str:
        """Get contextual help for a command."""
        help_texts = {
            'scan': """
🔍 SCAN COMMAND HELP
Usage: python main.py scan [OPTIONS]

Common Options:
  -f, --file PATH          Path to Postman Collection, OpenAPI spec, or HAR file
  -u, --curl TEXT          Curl command string to parse
  -a, --auth-type TYPE     Authentication type (header, cookie, token)
  -n, --auth-name TEXT     Authentication parameter name
  -v, --auth-value TEXT    Authentication parameter value
  --template TEMPLATE      Use predefined scan template
  --plugins TEXT           Comma-separated list of specific plugins
  --export-pdf PATH        Export report to PDF file
  --export-excel PATH      Export report to Excel file
  --no-zap                 Skip ZAP scanning (custom plugins only)
  --no-plugins             Skip custom plugins (ZAP only)

Examples:
  python main.py scan -f collection.json
  python main.py scan -f collection.json --template quick
  python main.py scan -f collection.json --plugins JWTSecurityChecker
            """,
            'config': """
⚙️ CONFIG COMMAND HELP
Usage: python main.py config [OPTIONS]

Options:
  --env-file PATH          Path to .env configuration file
  --save-config            Save current configuration to .env file
  --show-config            Show current configuration and exit
  --wizard                 Run interactive configuration wizard

Examples:
  python main.py config --show-config
  python main.py config --wizard
  python main.py config --save-config
            """,
            'templates': """
📋 TEMPLATES COMMAND HELP
Usage: python main.py templates

Available Templates:
  quick           - Fast scan using only custom plugins (1-2 min)
  comprehensive   - Full security scan with ZAP and all plugins (10-30 min)
  jwt-focused     - Specialized scan for JWT token security (2-5 min)
  api-only        - API-specific security checks without ZAP (3-8 min)
  zap-only        - Traditional OWASP ZAP scanning only (5-15 min)

Examples:
  python main.py scan -f collection.json --template quick
  python main.py scan -f collection.json --template comprehensive
            """,
            'plugins': """
🔌 PLUGINS COMMAND HELP
Usage: python main.py plugins

Shows all available custom security plugins with descriptions.

Plugin Selection Examples:
  python main.py scan -f collection.json --plugins SecurityHeadersChecker
  python main.py scan -f collection.json --plugins JWTSecurityChecker,CORSChecker
  python main.py scan -f collection.json --plugins JWTSecurityChecker,SecurityHeadersChecker
            """
        }
        
        return help_texts.get(command, f"No specific help available for '{command}'")
    
    def get_smart_suggestions(self, command_line: str) -> List[str]:
        """Get smart suggestions based on the entire command line context."""
        parts = command_line.strip().split()
        suggestions = []
        
        if len(parts) == 1:
            # Main command suggestions
            suggestions = self.get_suggestions("main_command", parts[0])
        elif len(parts) >= 2:
            main_command = parts[1]
            
            if main_command == "scan":
                # Scan-specific suggestions
                if "--template" in parts:
                    # Template suggestions
                    template_index = parts.index("--template")
                    if template_index + 1 < len(parts):
                        suggestions = self.get_suggestions("template", parts[template_index + 1])
                elif "--plugins" in parts:
                    # Plugin suggestions
                    plugins_index = parts.index("--plugins")
                    if plugins_index + 1 < len(parts):
                        suggestions = self.get_suggestions("plugin", parts[template_index + 1])
                elif "--auth-type" in parts:
                    # Auth type suggestions
                    auth_index = parts.index("--auth-type")
                    if auth_index + 1 < len(parts):
                        suggestions = self.get_suggestions("auth_type", parts[auth_index + 1])
                elif any(part.startswith("-f") or part.startswith("--file") for part in parts):
                    # File suggestions
                    file_index = -1
                    for i, part in enumerate(parts):
                        if part in ["-f", "--file"] and i + 1 < len(parts):
                            file_index = i + 1
                            break
                    if file_index >= 0 and file_index < len(parts):
                        suggestions = self.get_suggestions("file", parts[file_index])
                else:
                    # General scan options
                    last_part = parts[-1]
                    if last_part.startswith("-"):
                        suggestions = self.get_suggestions("scan_option", last_part)
            
            elif main_command == "config":
                # Config-specific suggestions
                last_part = parts[-1]
                if last_part.startswith("-"):
                    suggestions = self.get_suggestions("config_option", last_part)
        
        return suggestions[:10]  # Limit to 10 suggestions


def setup_autocomplete():
    """Setup autocomplete for different shells."""
    autocomplete_script = """
# API Security Scanner Autocomplete
_api_security_scanner_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    
    # Main commands
    if [[ ${COMP_CWORD} -eq 1 ]]; then
        opts="scan config list-scans show-scan cleanup stats reset-db clear-db db-info reports-info clear-reports cleanup-reports templates plugins help"
        COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
        return 0
    fi
    
    # Command-specific completions
    case ${COMP_WORDS[1]} in
        scan)
            if [[ ${prev} == "-f" || ${prev} == "--file" ]]; then
                COMPREPLY=( $(compgen -f -X '!*.{json,yaml,yml,har}' -- ${cur}) )
            elif [[ ${prev} == "--template" ]]; then
                COMPREPLY=( $(compgen -W "quick comprehensive jwt-focused api-only zap-only" -- ${cur}) )
            elif [[ ${prev} == "--auth-type" ]]; then
                COMPREPLY=( $(compgen -W "header cookie token" -- ${cur}) )
            elif [[ ${prev} == "--plugins" ]]; then
                COMPREPLY=( $(compgen -W "SecurityHeadersChecker CORSChecker JWTSecurityChecker ParameterPollutionChecker RateLimitingChecker" -- ${cur}) )
            else
                opts="-f --file -u --curl -a --auth-type -n --auth-name -v --auth-value --zap-path --zap-port --zap-host --db-path --export --export-json --export-pdf --export-excel --export-xml --performance-stats --no-zap --no-plugins --plugins --spider-depth --spider-children --max-scan-time --no-progress --template"
                COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
            fi
            ;;
        config)
            opts="--env-file --save-config --show-config --wizard"
            COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
            ;;
    esac
}

complete -F _api_security_scanner_completion python
complete -F _api_security_scanner_completion main.py
"""
    
    return autocomplete_script


def generate_autocomplete_files():
    """Generate autocomplete files for different shells."""
    autocomplete_dir = Path("autocomplete")
    autocomplete_dir.mkdir(exist_ok=True)
    
    # Bash completion
    bash_script = setup_autocomplete()
    with open(autocomplete_dir / "api-security-scanner.bash", "w") as f:
        f.write(bash_script)
    
    # Zsh completion
    zsh_script = bash_script.replace("compgen", "compgen -o plusdirs")
    with open(autocomplete_dir / "_api-security-scanner", "w") as f:
        f.write(zsh_script)
    
    # Fish completion
    fish_script = """
# API Security Scanner Fish Completion
complete -c python -n '__fish_seen_subcommand_from main.py' -a 'scan' -d 'Perform security scan'
complete -c python -n '__fish_seen_subcommand_from main.py' -a 'config' -d 'Configuration management'
complete -c python -n '__fish_seen_subcommand_from main.py' -a 'templates' -d 'List scan templates'
complete -c python -n '__fish_seen_subcommand_from main.py' -a 'plugins' -d 'List available plugins'

# Scan command completions
complete -c python -n '__fish_seen_subcommand_from main.py scan' -s f -l file -r -d 'Input file (Postman, OpenAPI, HAR)'
complete -c python -n '__fish_seen_subcommand_from main.py scan' -s u -l curl -r -d 'Curl command string'
complete -c python -n '__fish_seen_subcommand_from main.py scan' -l template -a 'quick comprehensive jwt-focused api-only zap-only' -d 'Scan template'
complete -c python -n '__fish_seen_subcommand_from main.py scan' -l plugins -r -d 'Specific plugins to run'
complete -c python -n '__fish_seen_subcommand_from main.py scan' -l auth-type -a 'header cookie token' -d 'Authentication type'
"""
    
    with open(autocomplete_dir / "api-security-scanner.fish", "w") as f:
        f.write(fish_script)
    
    print("✅ Autocomplete files generated in 'autocomplete/' directory")
    print("📁 Files created:")
    print("  - api-security-scanner.bash (for Bash)")
    print("  - _api-security-scanner (for Zsh)")
    print("  - api-security-scanner.fish (for Fish)")
    print("\n💡 To enable autocomplete:")
    print("  Bash: source autocomplete/api-security-scanner.bash")
    print("  Zsh:  cp autocomplete/_api-security-scanner ~/.zsh/completions/")
    print("  Fish: cp autocomplete/api-security-scanner.fish ~/.config/fish/completions/")


if __name__ == "__main__":
    generate_autocomplete_files()
