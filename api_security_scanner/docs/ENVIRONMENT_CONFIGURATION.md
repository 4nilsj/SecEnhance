# Environment Configuration Guide

The API Security Scanner uses `.env` files for configuration management, making it easy to customize behavior across different environments without modifying code.

## Quick Start

1. **Copy the template:**
   ```bash
   cp env.template .env
   ```

2. **Edit the configuration:**
   ```bash
   nano .env  # or your preferred editor
   ```

3. **Use the configuration:**
   ```bash
   # Show current configuration
   python -m api_security_scanner.cli.main config --show-config
   
   # Validate configuration
   python -m api_security_scanner.cli.main config
   
   # Save current settings to .env
   python -m api_security_scanner.cli.main config --save-config
   ```

## Configuration Categories

### 🔧 Application Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `DEBUG` | `false` | Enable debug mode for detailed logging |
| `VERBOSE` | `false` | Enable verbose output |
| `APP_NAME` | `API Security Scanner` | Application name |

### 🗄️ Database Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_PATH` | `scan_results.db` | Path to SQLite database file |
| `DB_BACKUP_ENABLED` | `true` | Enable automatic database backups |
| `DB_BACKUP_INTERVAL` | `24` | Backup interval in hours |
| `DB_MAX_BACKUPS` | `7` | Maximum number of backup files |
| `DB_CONNECTION_TIMEOUT` | `30` | Database connection timeout (seconds) |

### 🔍 ZAP Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `ZAP_PATH` | *(auto-detect)* | Path to ZAP executable |
| `ZAP_HOST` | `localhost` | ZAP host (use `zap` for Docker) |
| `ZAP_PORT` | `8080` | ZAP port |
| `ZAP_API_KEY` | *(none)* | ZAP API key for authentication |
| `ZAP_TIMEOUT` | `300` | ZAP connection timeout (seconds) |
| `ZAP_MAX_SCAN_TIME` | `3600` | Maximum scan time (seconds) |
| `ZAP_SPIDER_DEPTH` | `5` | Spider crawl depth |
| `ZAP_MAX_CHILDREN` | `10` | Maximum children per node |
| `ZAP_THREAD_COUNT` | `2` | Number of scanning threads |
| `ZAP_EXTERNAL` | `false` | Use external ZAP instance |
| `ZAP_DAEMON` | `true` | Run ZAP in daemon mode |

### 📝 Logging Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `INFO` | Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL) |
| `LOG_DIR` | `logs` | Log directory |
| `LOG_FILE_ENABLED` | `true` | Enable file logging |
| `LOG_CONSOLE_ENABLED` | `true` | Enable console logging |
| `LOG_MAX_FILE_SIZE` | `10485760` | Maximum log file size (bytes) |
| `LOG_BACKUP_COUNT` | `5` | Number of backup log files |

### 📊 Report Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `REPORT_DIR` | `reports` | Report output directory |
| `REPORT_TEMPLATE_DIR` | `templates` | Template directory |
| `REPORT_INCLUDE_SCREENSHOTS` | `true` | Include screenshots in reports |
| `REPORT_INCLUDE_POC` | `true` | Include proof-of-concept in reports |
| `REPORT_MAX_SIZE` | `52428800` | Maximum report size (bytes) |
| `REPORT_AUTO_OPEN` | `false` | Automatically open reports |

### 🔒 Security Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_REQUESTS_PER_SECOND` | `10` | Maximum requests per second |
| `REQUEST_TIMEOUT` | `30` | Request timeout (seconds) |
| `VERIFY_SSL` | `true` | Verify SSL certificates |
| `FOLLOW_REDIRECTS` | `true` | Follow HTTP redirects |
| `MAX_REDIRECTS` | `5` | Maximum redirects to follow |
| `USER_AGENT` | `API-Security-Scanner/1.0.0` | User agent string |

### 🔌 Plugin Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `ENABLED_PLUGINS` | `CORSChecker,RateLimitingChecker,SecurityHeadersChecker,EnhancedSecurityChecker` | Comma-separated list of enabled plugins |
| `PLUGIN_TIMEOUT` | `60` | Plugin execution timeout (seconds) |
| `MAX_CONCURRENT_PLUGINS` | `3` | Maximum concurrent plugins |
| `CUSTOM_PLUGIN_DIR` | `custom_plugins` | Directory for custom plugins |

### 🐳 Container Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `CONTAINER_DATA_DIR` | `/app/data` | Data directory in container |
| `CONTAINER_LOGS_DIR` | `/app/logs` | Logs directory in container |
| `CONTAINER_REPORTS_DIR` | `/app/reports` | Reports directory in container |
| `CONTAINER_WORKSPACE_DIR` | `/workspace` | Workspace directory in container |
| `ZAP_CONTAINER_NAME` | `zap` | ZAP container name (Docker Compose) |
| `CONTAINER_NETWORK_MODE` | `bridge` | Container network mode |

## Environment-Specific Configurations

### Development Environment

```bash
# .env.development
DEBUG=true
VERBOSE=true
LOG_LEVEL=DEBUG
ZAP_EXTERNAL=false
REPORT_AUTO_OPEN=true
DEV_MODE=true
```

### Production Environment

```bash
# .env.production
DEBUG=false
VERBOSE=false
LOG_LEVEL=WARNING
ZAP_EXTERNAL=true
REPORT_AUTO_OPEN=false
DB_BACKUP_ENABLED=true
PERFORMANCE_MONITORING=true
```

### Docker Environment

```bash
# .env.docker
ZAP_HOST=zap
ZAP_EXTERNAL=true
CONTAINER_DATA_DIR=/app/data
CONTAINER_LOGS_DIR=/app/logs
CONTAINER_REPORTS_DIR=/app/reports
LOG_FILE_ENABLED=true
LOG_CONSOLE_ENABLED=false
```

### CI/CD Environment

```bash
# .env.ci
DEBUG=false
VERBOSE=true
LOG_LEVEL=INFO
ZAP_EXTERNAL=true
CI_CD_ENABLED=true
CI_CD_PIPELINE=security-scan
CI_CD_ENVIRONMENT=staging
```

## Usage Examples

### Basic Configuration

```bash
# Create a basic .env file
cat > .env << EOF
# Basic settings
DEBUG=false
LOG_LEVEL=INFO

# ZAP settings
ZAP_HOST=localhost
ZAP_PORT=8080
ZAP_EXTERNAL=false

# Database settings
DB_PATH=scan_results.db
DB_BACKUP_ENABLED=true

# Report settings
REPORT_DIR=reports
REPORT_AUTO_OPEN=false
EOF
```

### Docker Compose Configuration

```bash
# .env for Docker Compose
ZAP_HOST=zap
ZAP_PORT=8080
ZAP_EXTERNAL=true
CONTAINER_DATA_DIR=/app/data
CONTAINER_LOGS_DIR=/app/logs
CONTAINER_REPORTS_DIR=/app/reports
LOG_LEVEL=INFO
DEBUG=false
```

### Custom Plugin Configuration

```bash
# Enable only specific plugins
ENABLED_PLUGINS=CORSChecker,SecurityHeadersChecker

# Custom plugin directory
CUSTOM_PLUGIN_DIR=/path/to/custom/plugins

# Plugin timeout
PLUGIN_TIMEOUT=120
```

## Configuration Management Commands

### Show Current Configuration

```bash
python -m api_security_scanner.cli.main config --show-config
```

Output:
```
Current Configuration:
  Database Path: scan_results.db
  ZAP Host: localhost
  ZAP Port: 8080
  ZAP External: false
  Log Level: INFO
  Log Directory: logs
  Report Directory: reports
  Enabled Plugins: CORSChecker,RateLimitingChecker,SecurityHeadersChecker,EnhancedSecurityChecker
  Debug Mode: false
  Verbose Mode: false
```

### Validate Configuration

```bash
python -m api_security_scanner.cli.main config
```

Output:
```
Configuration is valid
```

Or if there are issues:
```
Configuration issues found:
  - Cannot create log directory /invalid/path: Permission denied
  - ZAP path must be specified when not using external ZAP
```

### Save Configuration

```bash
python -m api_security_scanner.cli.main config --save-config
```

This saves the current configuration to `.env` file.

### Use Custom .env File

```bash
python -m api_security_scanner.cli.main config --env-file .env.production --show-config
```

## Docker Integration

### Using .env with Docker Compose

1. **Create .env file:**
   ```bash
   cp env.template .env
   # Edit .env as needed
   ```

2. **Docker Compose automatically loads .env:**
   ```bash
   docker-compose up
   ```

3. **Override specific variables:**
   ```bash
   ZAP_HOST=external-zap-server docker-compose up
   ```

### Environment Variables in Docker

```bash
# Run with specific environment variables
docker run -e ZAP_HOST=external-zap -e ZAP_EXTERNAL=true \
  -v $(pwd)/.env:/app/.env:ro \
  api-security-scanner:latest
```

## Best Practices

### 1. **Environment Separation**
- Use different `.env` files for different environments
- Never commit sensitive data to version control
- Use `.env.example` for documentation

### 2. **Security**
- Keep API keys and passwords in environment variables
- Use `.env` files with restricted permissions
- Consider using secret management systems in production

### 3. **Configuration Validation**
- Always validate configuration before running scans
- Use the built-in validation commands
- Test configuration changes in development first

### 4. **Documentation**
- Document custom configurations
- Keep `.env.example` up to date
- Use comments in `.env` files for clarity

### 5. **Backup and Version Control**
- Backup important configuration files
- Use version control for configuration templates
- Keep sensitive data out of version control

## Troubleshooting

### Common Issues

1. **Configuration not loading:**
   ```bash
   # Check if .env file exists and is readable
   ls -la .env
   cat .env
   ```

2. **Invalid configuration values:**
   ```bash
   # Validate configuration
   python -m api_security_scanner.cli.main config
   ```

3. **Environment variables not working:**
   ```bash
   # Check environment variable loading
   python -c "from api_security_scanner.core.config import get_config; print(get_config().zap.host)"
   ```

4. **Docker configuration issues:**
   ```bash
   # Check Docker environment
   docker-compose config
   docker-compose exec scanner env | grep ZAP
   ```

### Debug Mode

Enable debug mode for detailed configuration information:

```bash
# Set debug mode
echo "DEBUG=true" >> .env

# Run with debug output
python -m api_security_scanner.cli.main config --show-config
```

## Advanced Configuration

### Custom Configuration Classes

You can extend the configuration system by creating custom configuration classes:

```python
from api_security_scanner.core.config import AppConfig, DatabaseConfig

class CustomDatabaseConfig(DatabaseConfig):
    def __init__(self):
        super().__init__()
        self.custom_setting = "custom_value"

class CustomAppConfig(AppConfig):
    def __init__(self):
        super().__init__()
        self.database = CustomDatabaseConfig()
```

### Programmatic Configuration

```python
from api_security_scanner.core.config import get_config_manager

# Get configuration manager
config_manager = get_config_manager()

# Update configuration
config_manager.update_config(
    debug=True,
    verbose=True
)

# Save to file
config_manager.save_to_env('.env.custom')
```

This comprehensive configuration system makes the API Security Scanner highly customizable and suitable for various deployment scenarios.
