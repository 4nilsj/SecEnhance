import pytest
import os
import tempfile
import json
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))
from config_manager import ConfigManager

@pytest.fixture
def temp_config_file():
    """Create a temporary config file for testing."""
    config_data = {
        "defaults": {
            "debug": True,
            "output_format": "json",
            "max_attempts": 500
        },
        "api": {
            "host": "127.0.0.1",
            "port": 8080
        }
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config_data, f)
        temp_file = f.name
    
    yield temp_file
    
    # Cleanup
    os.unlink(temp_file)

def test_config_manager_defaults():
    """Test ConfigManager with default configuration."""
    config = ConfigManager("nonexistent_file.json")
    
    assert config.get_default("debug") is False
    assert config.get_default("output_format") == "html"
    assert config.get_default("max_attempts") == 1000
    assert config.get_api("host") == "0.0.0.0"
    assert config.get_api("port") == 5000

def test_config_manager_file_loading(temp_config_file):
    """Test ConfigManager loading from file."""
    config = ConfigManager(temp_config_file)
    
    assert config.get_default("debug") is True
    assert config.get_default("output_format") == "json"
    assert config.get_default("max_attempts") == 500
    assert config.get_api("host") == "127.0.0.1"
    assert config.get_api("port") == 8080

def test_config_manager_environment_overrides():
    """Test ConfigManager environment variable overrides."""
    # Set environment variables
    os.environ["JWT_DEBUG"] = "true"
    os.environ["JWT_MAX_ATTEMPTS"] = "2000"
    os.environ["JWT_API_PORT"] = "9000"
    
    config = ConfigManager("nonexistent_file.json")
    
    assert config.get_default("debug") is True
    assert config.get_default("max_attempts") == 2000
    assert config.get_api("port") == 9000
    
    # Cleanup
    del os.environ["JWT_DEBUG"]
    del os.environ["JWT_MAX_ATTEMPTS"]
    del os.environ["JWT_API_PORT"]

def test_config_manager_get_methods():
    """Test ConfigManager get methods."""
    config = ConfigManager("nonexistent_file.json")
    
    # Test get with default
    assert config.get("defaults", "debug") is False  # Should get actual value
    assert config.get("nonexistent", "key", "default") == "default"  # Should use default
    
    # Test section getters
    assert config.get_default("debug") is False
    assert config.get_api("host") == "0.0.0.0"
    assert config.get_testing("enable_cve_tests") is True
    assert config.get_reporting("color_output") is True
    assert config.get_security("max_token_size") == 8192

def test_config_manager_set_method():
    """Test ConfigManager set method."""
    config = ConfigManager("nonexistent_file.json")
    
    config.set("defaults", "debug", True)
    config.set("custom", "value", "test")
    
    assert config.get_default("debug") is True
    assert config.get("custom", "value") == "test"

def test_config_manager_save_config(temp_config_file):
    """Test ConfigManager save configuration."""
    config = ConfigManager(temp_config_file)
    
    # Modify config
    config.set("defaults", "debug", False)
    
    # Save to new file
    new_config_file = temp_config_file + "_new.json"
    config.save_config(new_config_file)
    
    # Load and verify
    new_config = ConfigManager(new_config_file)
    assert new_config.get_default("debug") is False
    
    # Cleanup
    os.unlink(new_config_file) 