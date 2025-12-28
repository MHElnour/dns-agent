"""
Configuration Manager - Loads and manages YAML configuration
"""
import yaml
from pathlib import Path
from typing import Any, Dict
from core.platform_utils import get_config_dir, get_data_dir


class ConfigManager:
    """
    Manages configuration loading and access for DNS Agent
    """

    def __init__(self, config_file=None):
        """
        Initialize configuration manager

        Args:
            config_file: Path to YAML configuration file (None = use platform-specific config dir)
        """
        if config_file is None:
            self.config_file = get_config_dir() / 'dns_agent.yml'
        else:
            self.config_file = Path(config_file)

        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """
        Load configuration from YAML file

        Returns:
            Dictionary with configuration
        """
        # Default configuration
        default_config = {
            'server': {
                'host': '127.0.0.1',
                'port': 5354,
                'upstream_dns': '8.8.8.8',
                'max_workers': 50
            },
            'features': {
                'enable_cache': True,
                'enable_database': True,
                'enable_stats': True
            },
            'cache': {
                'max_size': 10000,
                'min_ttl': 60,
                'max_ttl': 86400
            },
            'database': {
                'db_path': 'data/dns_agent.db',
                'cleanup_days': 30,
                'auto_cleanup': False
            },
            'blocklist': {
                'blocklist_file': 'config/blocklists.txt',
                'whitelist_file': 'config/whitelist.txt',
                'auto_reload': False,
                'reload_interval': 3600
            },
            'logging': {
                'log_dir': 'data',
                'console_level': 'INFO',
                'file_level': 'DEBUG',
                'rotation': '10 MB',
                'retention': '7 days',
                'compression': 'zip'
            },
            'performance': {
                'socket_timeout': 1.0,
                'upstream_timeout': 5.0,
                'max_retries': 3
            }
        }

        try:
            if self.config_file.exists():
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    loaded_config = yaml.safe_load(f)
                    # Merge loaded config with defaults (loaded config takes precedence)
                    return self._merge_configs(default_config, loaded_config)
            else:
                print(f"WARNING: Config file not found: {self.config_file}")
                print("Using default configuration")
                return default_config

        except Exception as e:
            print(f"ERROR: Failed to load config file: {e}")
            print("Using default configuration")
            return default_config

    def _merge_configs(self, default: Dict, loaded: Dict) -> Dict:
        """
        Recursively merge loaded config with defaults

        Args:
            default: Default configuration
            loaded: Loaded configuration

        Returns:
            Merged configuration
        """
        merged = default.copy()

        for key, value in loaded.items():
            if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
                merged[key] = self._merge_configs(merged[key], value)
            else:
                merged[key] = value

        return merged

    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get configuration value by dot-separated path

        Args:
            key_path: Dot-separated path (e.g., 'server.host')
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        keys = key_path.split('.')
        value = self.config

        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default

        return value

    def get_section(self, section: str) -> Dict[str, Any]:
        """
        Get entire configuration section

        Args:
            section: Section name (e.g., 'server', 'cache')

        Returns:
            Section configuration dictionary
        """
        return self.config.get(section, {})

    def reload(self):
        """Reload configuration from file"""
        self.config = self._load_config()

    def save(self, config_file: str = None):
        """
        Save current configuration to file

        Args:
            config_file: Optional different file path to save to
        """
        output_file = Path(config_file) if config_file else self.config_file

        try:
            # Ensure directory exists
            output_file.parent.mkdir(parents=True, exist_ok=True)

            with open(output_file, 'w', encoding='utf-8') as f:
                yaml.dump(self.config, f, default_flow_style=False, sort_keys=False)

            print(f"Configuration saved to {output_file}")

        except Exception as e:
            print(f"ERROR: Failed to save config: {e}")

    # Convenience methods for common config values

    @property
    def server_host(self) -> str:
        """Get server host"""
        return self.get('server.host', '127.0.0.1')

    @property
    def server_port(self) -> int:
        """Get server port"""
        return self.get('server.port', 5354)

    @property
    def upstream_dns(self) -> str:
        """Get upstream DNS server"""
        return self.get('server.upstream_dns', '8.8.8.8')

    @property
    def max_workers(self) -> int:
        """Get max workers"""
        return self.get('server.max_workers', 50)

    @property
    def cache_enabled(self) -> bool:
        """Check if caching is enabled"""
        return self.get('features.enable_cache', True)

    @property
    def database_enabled(self) -> bool:
        """Check if database is enabled"""
        return self.get('features.enable_database', True)

    @property
    def cache_max_size(self) -> int:
        """Get cache max size"""
        return self.get('cache.max_size', 10000)

    @property
    def cache_min_ttl(self) -> int:
        """Get cache min TTL"""
        return self.get('cache.min_ttl', 60)

    @property
    def cache_max_ttl(self) -> int:
        """Get cache max TTL"""
        return self.get('cache.max_ttl', 86400)

    @property
    def database_path(self) -> str:
        """Get database path"""
        return self.get('database.db_path', 'data/dns_agent.db')

    @property
    def blocklist_file(self) -> str:
        """Get blocklist file path"""
        return self.get('blocklist.blocklist_file', 'config/blocklists.txt')

    @property
    def whitelist_file(self) -> str:
        """Get whitelist file path"""
        return self.get('blocklist.whitelist_file', 'config/whitelist.txt')

    @property
    def log_dir(self) -> str:
        """Get log directory"""
        return self.get('logging.log_dir', 'data')

    @property
    def console_log_level(self) -> str:
        """Get console log level"""
        return self.get('logging.console_level', 'INFO')

    @property
    def file_log_level(self) -> str:
        """Get file log level"""
        return self.get('logging.file_level', 'DEBUG')

    def __str__(self) -> str:
        """String representation of configuration"""
        return yaml.dump(self.config, default_flow_style=False, sort_keys=False)


# Global config instance
_config_instance = None


def get_config(config_file=None) -> ConfigManager:
    """
    Get global configuration instance (singleton)

    Args:
        config_file: Path to configuration file (None = use platform-specific config dir)

    Returns:
        ConfigManager instance
    """
    global _config_instance

    if _config_instance is None:
        _config_instance = ConfigManager(config_file)

    return _config_instance


def reload_config():
    """Reload global configuration"""
    global _config_instance

    if _config_instance is not None:
        _config_instance.reload()
