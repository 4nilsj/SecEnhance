#!/bin/bash
set -e

# API Security Scanner Container Entrypoint
# This script handles container initialization and command execution

# Default values
ZAP_PATH=${ZAP_PATH:-"/usr/local/bin/zap.sh"}
ZAP_PORT=${ZAP_PORT:-8080}
ZAP_HOST=${ZAP_HOST:-localhost}
SCAN_DB_PATH=${SCAN_DB_PATH:-"/app/data/scan_results.db"}
LOG_DIR=${LOG_DIR:-"/app/logs"}
REPORTS_DIR=${REPORTS_DIR:-"/app/reports"}
WORKSPACE_DIR=${WORKSPACE_DIR:-"/workspace"}

# Create directories if they don't exist
mkdir -p "$(dirname "$SCAN_DB_PATH")" "$LOG_DIR" "$REPORTS_DIR"

# Set permissions
chown -R scanner:scanner /app 2>/dev/null || true

# Function to show help
show_help() {
    echo "API Security Scanner - Container Usage:"
    echo "======================================"
    echo ""
    echo "Basic scan:"
    echo "  docker run --rm -v \$(pwd):/workspace api-security-scanner scan -f /workspace/collection.json"
    echo ""
    echo "Scan with authentication:"
    echo "  docker run --rm -v \$(pwd):/workspace api-security-scanner scan -f /workspace/collection.json -a header -n X-API-Key -v your-key"
    echo ""
    echo "Scan with custom ZAP instance:"
    echo "  docker run --rm -v \$(pwd):/workspace --network host api-security-scanner scan -f /workspace/collection.json --zap-host host.docker.internal"
    echo ""
    echo "Using docker-compose:"
    echo "  docker-compose run --rm scanner scan -f /workspace/collection.json"
    echo ""
    echo "List available commands:"
    echo "  docker run --rm api-security-scanner --help"
    echo ""
    echo "Environment Variables:"
    echo "  ZAP_HOST - ZAP proxy host (default: localhost)"
    echo "  ZAP_PORT - ZAP proxy port (default: 8080)"
    echo "  SCAN_DB_PATH - Database file path (default: /app/data/scan_results.db)"
    echo "  LOG_DIR - Log directory (default: /app/logs)"
    echo "  REPORTS_DIR - Reports directory (default: /app/reports)"
    echo "  WORKSPACE_DIR - Workspace directory (default: /workspace)"
    echo ""
}

# Function to check container environment
check_environment() {
    echo "Container Environment Check:"
    echo "============================"
    echo "ZAP_HOST: $ZAP_HOST"
    echo "ZAP_PORT: $ZAP_PORT"
    echo "SCAN_DB_PATH: $SCAN_DB_PATH"
    echo "LOG_DIR: $LOG_DIR"
    echo "REPORTS_DIR: $REPORTS_DIR"
    echo "WORKSPACE_DIR: $WORKSPACE_DIR"
    echo ""
    
    # Check if container config is available
    if [ -f "/app/container-config.py" ]; then
        echo "Container configuration: Available"
    else
        echo "Container configuration: Not available"
    fi
    
    # Check network connectivity to ZAP
    if [ "$ZAP_HOST" != "localhost" ]; then
        echo "Testing connectivity to ZAP at $ZAP_HOST:$ZAP_PORT..."
        if curl -s --connect-timeout 5 "http://$ZAP_HOST:$ZAP_PORT/JSON/core/view/version/" > /dev/null 2>&1; then
            echo "ZAP connectivity: OK"
        else
            echo "ZAP connectivity: FAILED"
            echo "Warning: Cannot connect to ZAP at $ZAP_HOST:$ZAP_PORT"
        fi
    fi
    echo ""
}

# Function to run scanner with container optimizations
run_scanner() {
    # Add container-specific arguments
    local args=("$@")
    
    # Set default paths if not specified
    local has_db_path=false
    local has_log_dir=false
    local has_reports_dir=false
    
    for arg in "${args[@]}"; do
        if [[ "$arg" == "--db-path" ]]; then
            has_db_path=true
        elif [[ "$arg" == "--log-dir" ]]; then
            has_log_dir=true
        elif [[ "$arg" == "--export" ]] || [[ "$arg" == "--export-json" ]]; then
            has_reports_dir=true
        fi
    done
    
    # Add default paths if not specified
    if [ "$has_db_path" = false ]; then
        args+=("--db-path" "$SCAN_DB_PATH")
    fi
    
    if [ "$has_log_dir" = false ]; then
        args+=("--log-dir" "$LOG_DIR")
    fi
    
    # Set ZAP host and port if not specified
    local has_zap_host=false
    local has_zap_port=false
    
    for arg in "${args[@]}"; do
        if [[ "$arg" == "--zap-host" ]]; then
            has_zap_host=true
        elif [[ "$arg" == "--zap-port" ]]; then
            has_zap_port=true
        fi
    done
    
    if [ "$has_zap_host" = false ]; then
        args+=("--zap-host" "$ZAP_HOST")
    fi
    
    if [ "$has_zap_port" = false ]; then
        args+=("--zap-port" "$ZAP_PORT")
    fi
    
    # Execute the scanner
    exec python -m api_security_scanner.cli.main "${args[@]}"
}

# Main execution logic
if [ $# -eq 0 ]; then
    show_help
    exit 0
fi

# Handle special commands
case "$1" in
    "help"|"--help"|"-h")
        show_help
        exit 0
        ;;
    "check"|"env"|"environment")
        check_environment
        exit 0
        ;;
    "version"|"--version"|"-v")
        python main.py --version
        exit 0
        ;;
esac

# Run the scanner with provided arguments
run_scanner "$@"
