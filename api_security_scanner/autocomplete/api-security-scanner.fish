
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
