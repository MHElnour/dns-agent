"""
Platform-specific utilities
Handles differences between Windows, macOS, and Linux
"""
import platform
import os
from pathlib import Path

def get_platform():
    """Returns: 'windows', 'macos', or 'linux'"""
    system = platform.system().lower()
    if system == 'darwin':
        return 'macos'
    return system

def is_windows():
    return get_platform() == 'windows'

def is_macos():
    return get_platform() == 'macos'

def is_linux():
    return get_platform() == 'linux'

def is_admin():
    """Check if running with admin/root privileges"""
    if is_windows():
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:
        # macOS/Linux - check if effective user ID is 0 (root)
        return os.geteuid() == 0

def use_dev_mode():
    """Check if development mode is enabled (use local ./config and ./data)"""
    return os.getenv('DNS_AGENT_DEV_MODE', '').lower() in ('1', 'true', 'yes')

def get_config_dir():
    """
    Get platform-appropriate config directory

    Development mode (DNS_AGENT_DEV_MODE=1): ./config
    Production:
      - macOS: ~/Library/Application Support/DNSAgent
      - Windows: ~/AppData/Local/DNSAgent
      - Linux: ~/.config/dns-agent
    """
    if use_dev_mode():
        return Path('./config')

    if is_windows():
        return Path.home() / 'AppData' / 'Local' / 'DNSAgent'
    elif is_macos():
        return Path.home() / 'Library' / 'Application Support' / 'DNSAgent'
    else:
        return Path.home() / '.config' / 'dns-agent'

def get_data_dir():
    """
    Get platform-appropriate data directory

    Development mode (DNS_AGENT_DEV_MODE=1): ./data
    Production:
      - macOS: ~/Library/Application Support/DNSAgent/data
      - Windows: ~/AppData/Local/DNSAgent/data
      - Linux: ~/.local/share/dns-agent
    """
    if use_dev_mode():
        return Path('./data')

    if is_windows():
        return Path.home() / 'AppData' / 'Local' / 'DNSAgent' / 'data'
    elif is_macos():
        return Path.home() / 'Library' / 'Application Support' / 'DNSAgent' / 'data'
    else:
        return Path.home() / '.local' / 'share' / 'dns-agent'

def get_blocklist_dir():
    """Get blocklist storage directory"""
    return get_data_dir() / 'blocklists'

def ensure_directories():
    """Create all necessary directories if they don't exist"""
    dirs = {
        'config': get_config_dir(),
        'data': get_data_dir(),
        'blocklists': get_blocklist_dir()
    }

    for name, path in dirs.items():
        path.mkdir(parents=True, exist_ok=True)

    return dirs

def setup_initial_config():
    """
    Copy default config files from package to user config directory on first run.
    This is called when the app is run for the first time.

    Template files are in ./config/ (shipped with the package)
    They get copied to platform-specific directories on first run.
    """
    import shutil

    # Only copy if not in dev mode (dev mode uses ./config directly)
    if use_dev_mode():
        return

    config_dir = get_config_dir()

    # Files to copy from package to user config directory
    template_files = [
        ('config/dns_agent.yml', config_dir / 'dns_agent.yml'),
        ('config/blocklist_sources.yml', config_dir / 'blocklist_sources.yml'),
    ]

    # Copy each template file if it doesn't exist in user config
    for template_path, dest_path in template_files:
        template = Path(template_path)

        # Skip if destination already exists
        if dest_path.exists():
            continue

        # Copy template if it exists
        if template.exists():
            print(f"First run: Copying {template} to {dest_path}")
            shutil.copy2(template, dest_path)
        else:
            print(f"WARNING: Template file not found: {template}")

# Print platform info when run directly
if __name__ == "__main__":
    print(f"Platform: {get_platform()}")
    print(f"Is Admin/Root: {is_admin()}")
    print(f"Dev Mode: {use_dev_mode()}")
    print(f"Config Dir: {get_config_dir()}")
    print(f"Data Dir: {get_data_dir()}")
    print(f"Blocklist Dir: {get_blocklist_dir()}")