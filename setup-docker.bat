@echo off
REM Security Tools Docker Setup Script for Windows
REM This script sets up Docker containers for JWT and Mobile Security Testing Tools

echo 🔧 Security Tools Docker Setup
echo ==============================

REM Check if Docker is installed
echo [INFO] Checking Docker installation...
docker --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker is not installed. Please install Docker Desktop first.
    pause
    exit /b 1
)

docker-compose --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker Compose is not installed. Please install Docker Compose first.
    pause
    exit /b 1
)

echo [SUCCESS] Docker and Docker Compose are installed

REM Create necessary directories
echo [INFO] Creating output directories...
if not exist "jwt_output" mkdir jwt_output
if not exist "jwt_tokens" mkdir jwt_tokens
if not exist "mobile_output" mkdir mobile_output
if not exist "mobile_input" mkdir mobile_input
if not exist "mobile_reports" mkdir mobile_reports

echo [SUCCESS] Directories created successfully

REM Build Docker images
echo [INFO] Building Docker images...

echo [INFO] Building JWT Security Testing Tool...
cd jwt_tool
docker build -t jwt-security-tester .
cd ..

echo [INFO] Building Mobile Security Testing Tool...
cd mobile_tool
docker build -t mobile-security-tester .
cd ..

echo [SUCCESS] All Docker images built successfully

REM Test the installations
echo [INFO] Testing installations...

echo [INFO] Testing JWT tool...
docker run --rm jwt-security-tester --help >nul 2>&1
if errorlevel 1 (
    echo [ERROR] JWT tool test failed
    pause
    exit /b 1
)
echo [SUCCESS] JWT tool is working correctly

echo [INFO] Testing Mobile tool...
docker run --rm mobile-security-tester --help >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Mobile tool test failed
    pause
    exit /b 1
)
echo [SUCCESS] Mobile tool is working correctly

REM Create example files
echo [INFO] Creating example files...

REM Create example JWT token file
echo # Example JWT tokens for testing > jwt_tokens\example_tokens.txt
echo # Replace these with your actual tokens >> jwt_tokens\example_tokens.txt
echo. >> jwt_tokens\example_tokens.txt
echo # Example 1: Basic JWT token >> jwt_tokens\example_tokens.txt
echo eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c >> jwt_tokens\example_tokens.txt
echo. >> jwt_tokens\example_tokens.txt
echo # Example 2: Add your tokens here >> jwt_tokens\example_tokens.txt
echo # your.jwt.token.here >> jwt_tokens\example_tokens.txt

REM Create example APK placeholder
echo # Mobile Security Testing Input Directory > mobile_input\README.txt
echo. >> mobile_input\README.txt
echo Place your APK or IPA files in this directory for analysis. >> mobile_input\README.txt
echo. >> mobile_input\README.txt
echo Example: >> mobile_input\README.txt
echo - app.apk >> mobile_input\README.txt
echo - app.ipa >> mobile_input\README.txt
echo - test_app.apk >> mobile_input\README.txt
echo. >> mobile_input\README.txt
echo The tool will analyze all files in this directory when running batch processing. >> mobile_input\README.txt

echo [SUCCESS] Example files created

REM Show usage examples
echo.
echo 🚀 Setup Complete! Here are some usage examples:
echo ==============================================
echo.

echo 🔐 JWT Security Testing Tool:
echo   # Test a single token
echo   docker run --rm -v %cd%\jwt_output:/app/output jwt-security-tester --token "your.jwt.token" --output /app/output/report.json
echo.
echo   # Run comprehensive test
echo   docker run --rm -v %cd%\jwt_output:/app/output jwt-security-tester --token "your.jwt.token" --test all --output /app/output/comprehensive.json
echo.
echo   # Interactive mode
echo   docker run --rm -it jwt-security-tester
echo.

echo 📱 Mobile Security Testing Tool:
echo   # Analyze APK file
echo   docker run --rm -v %cd%\app.apk:/app/input/app.apk -v %cd%\mobile_output:/app/output mobile-security-tester /app/input/app.apk --output /app/output/analysis.json
echo.
echo   # Comprehensive analysis
echo   docker run --rm -v %cd%\app.apk:/app/input/app.apk -v %cd%\mobile_output:/app/output -v %cd%\mobile_reports:/app/reports mobile-security-tester /app/input/app.apk --analysis-type comprehensive --output /app/output/comprehensive.json --report /app/reports/report.html
echo.

echo 🐳 Docker Compose Usage:
echo   # Build all services
echo   docker-compose build
echo.
echo   # Run JWT tool
echo   docker-compose run --rm jwt-tool --token "your.jwt.token"
echo.
echo   # Run Mobile tool
echo   docker-compose run --rm mobile-tool /app/input/app.apk
echo.

echo 📚 For more information, see:
echo   - DOCKER_GUIDE.md
echo   - jwt_tool\README.md
echo   - mobile_tool\README.md
echo.

echo [SUCCESS] Setup completed successfully!
echo.
echo [INFO] You can now use the security testing tools with Docker.
pause 