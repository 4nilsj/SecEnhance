@echo off
REM Docker build script for API Security Scanner (Windows)
REM This script provides various build options and optimizations

setlocal enabledelayedexpansion

REM Default values
set IMAGE_NAME=api-security-scanner
set TAG=latest
set PLATFORM=linux/amd64
set BUILD_ARGS=
set PUSH=false
set NO_CACHE=false

REM Parse command line arguments
:parse_args
if "%~1"=="" goto :build
if "%~1"=="-n" (
    set IMAGE_NAME=%~2
    shift
    shift
    goto :parse_args
)
if "%~1"=="--name" (
    set IMAGE_NAME=%~2
    shift
    shift
    goto :parse_args
)
if "%~1"=="-t" (
    set TAG=%~2
    shift
    shift
    goto :parse_args
)
if "%~1"=="--tag" (
    set TAG=%~2
    shift
    shift
    goto :parse_args
)
if "%~1"=="-p" (
    set PLATFORM=%~2
    shift
    shift
    goto :parse_args
)
if "%~1"=="--platform" (
    set PLATFORM=%~2
    shift
    shift
    goto :parse_args
)
if "%~1"=="--push" (
    set PUSH=true
    shift
    goto :parse_args
)
if "%~1"=="--no-cache" (
    set NO_CACHE=true
    shift
    goto :parse_args
)
if "%~1"=="--multi-platform" (
    set PLATFORM=linux/amd64,linux/arm64
    shift
    goto :parse_args
)
if "%~1"=="-h" goto :show_help
if "%~1"=="--help" goto :show_help
echo Unknown option: %~1
goto :show_help

:show_help
echo Usage: %0 [OPTIONS]
echo.
echo Options:
echo   -n, --name NAME        Image name (default: api-security-scanner)
echo   -t, --tag TAG          Image tag (default: latest)
echo   -p, --platform PLAT    Platform (default: linux/amd64)
echo   --push                 Push image to registry after build
echo   --no-cache             Build without cache
echo   --multi-platform       Build for multiple platforms
echo   -h, --help             Show this help message
echo.
echo Examples:
echo   %0                                    # Basic build
echo   %0 -t v1.0.0                         # Build with specific tag
echo   %0 --multi-platform --push           # Multi-platform build and push
echo   %0 --no-cache                        # Clean build
goto :end

:build
REM Set build arguments
if "%NO_CACHE%"=="true" (
    set BUILD_ARGS=%BUILD_ARGS% --no-cache
)

REM Full image name
set FULL_IMAGE_NAME=%IMAGE_NAME%:%TAG%

echo Building API Security Scanner Docker image...
echo Image: %FULL_IMAGE_NAME%
echo Platform: %PLATFORM%
echo.

REM Check if Docker is available
docker --version >nul 2>&1
if errorlevel 1 (
    echo Error: Docker is not installed or not in PATH
    exit /b 1
)

REM Build the image
echo Starting Docker build...

if "%PLATFORM%"=="linux/amd64,linux/arm64" (
    REM Multi-platform build
    echo Building for multiple platforms: %PLATFORM%
    
    REM Check if buildx is available
    docker buildx version >nul 2>&1
    if errorlevel 1 (
        echo Warning: Docker buildx not available, falling back to single platform build
        set PLATFORM=linux/amd64
        goto :single_platform
    )
    
    REM Create and use buildx builder if it doesn't exist
    docker buildx inspect scanner-builder >nul 2>&1
    if errorlevel 1 (
        echo Creating buildx builder...
        docker buildx create --name scanner-builder --use
    ) else (
        docker buildx use scanner-builder
    )
    
    REM Build and optionally push
    if "%PUSH%"=="true" (
        echo Building and pushing multi-platform image...
        docker buildx build --platform %PLATFORM% --tag %FULL_IMAGE_NAME% %BUILD_ARGS% --push .
    ) else (
        echo Building multi-platform image (load to local)...
        docker buildx build --platform %PLATFORM% --tag %FULL_IMAGE_NAME% %BUILD_ARGS% --load .
    )
) else (
    :single_platform
    REM Single platform build
    echo Building for platform: %PLATFORM%
    docker build --platform %PLATFORM% --tag %FULL_IMAGE_NAME% %BUILD_ARGS% .
)

REM Check if build was successful
if errorlevel 1 (
    echo Docker build failed
    exit /b 1
)

echo Docker image built successfully!
echo Image: %FULL_IMAGE_NAME%

REM Show image info
echo.
echo Image information:
docker images %IMAGE_NAME% --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}"

REM Run health check
echo.
echo Running health check...
docker run --rm %FULL_IMAGE_NAME% python /app/healthcheck.py
if errorlevel 1 (
    echo Health check failed
    exit /b 1
)
echo Health check passed

REM Show usage instructions
echo.
echo Usage examples:
echo   # Run a basic scan
echo   docker run --rm -v %cd%:/workspace %FULL_IMAGE_NAME% scan -f /workspace/collection.json
echo.
echo   # Run with Docker Compose
echo   docker-compose up -d zap
echo   docker-compose run --rm scanner scan -f /workspace/collection.json
echo.
echo   # Get help
echo   docker run --rm %FULL_IMAGE_NAME% --help

:end
