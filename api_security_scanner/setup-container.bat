@echo off
REM Setup script for API Security Scanner container environment
REM This script creates necessary directories and sets up volume mounts

echo Setting up API Security Scanner container environment...

REM Create necessary directories
echo Creating directories...
if not exist data mkdir data
if not exist logs mkdir logs
if not exist reports mkdir reports
if not exist workspace mkdir workspace
if not exist examples mkdir examples
if not exist templates mkdir templates

REM Create workspace subdirectories
if not exist workspace\collections mkdir workspace\collections
if not exist workspace\specs mkdir workspace\specs
if not exist workspace\reports mkdir workspace\reports

REM Create a sample .env file for container configuration
echo Creating container configuration...
(
echo # API Security Scanner Container Configuration
echo ZAP_HOST=zap
echo ZAP_PORT=8080
echo SCAN_DB_PATH=/app/data/scan_results.db
echo LOG_DIR=/app/logs
echo REPORTS_DIR=/app/reports
echo WORKSPACE_DIR=/workspace
echo.
echo # Optional: Custom ZAP configuration
echo # ZAP_PATH=/usr/local/bin/zap.sh
echo.
echo # Optional: Network configuration
echo # DOCKER_NETWORK_MODE=docker-compose
) > .env

REM Create a sample docker-compose override file
echo Creating docker-compose override...
(
echo version: '3.8'
echo.
echo services:
echo   scanner:
echo     environment:
echo       - ZAP_HOST=zap
echo       - ZAP_PORT=8080
echo     volumes:
echo       # Mount your API collections and specs
echo       - ./workspace:/workspace:ro
echo       # Mount custom plugins ^(optional^)
echo       - ./plugins:/app/plugins:ro
echo       # Mount custom examples ^(optional^)
echo       - ./examples:/app/examples:ro
echo.
echo   scanner-standalone:
echo     environment:
echo       - ZAP_HOST=host.docker.internal
echo       - ZAP_PORT=8080
echo     volumes:
echo       # Mount your API collections and specs
echo       - ./workspace:/workspace:ro
echo       # Mount custom plugins ^(optional^)
echo       - ./plugins:/app/plugins:ro
echo       # Mount custom examples ^(optional^)
echo       - ./examples:/app/examples:ro
) > docker-compose.override.yml

echo Container environment setup complete!
echo.
echo Next steps:
echo 1. Place your API collections/specs in the workspace\ directory
echo 2. Run: docker-compose up -d zap ^(to start ZAP^)
echo 3. Run: docker-compose run --rm scanner scan -f /workspace/your-collection.json
echo.
echo Or for standalone mode:
echo 1. Start ZAP on your host machine
echo 2. Run: docker-compose run --rm scanner-standalone scan -f /workspace/your-collection.json

pause
