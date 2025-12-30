"""
Network DNS Utilities - Manage system DNS settings
Cross-platform support for macOS, Windows, and Linux
"""
import subprocess
from core.logger import get_logger
from core.platform_utils import is_macos, is_windows, is_linux


class NetworkDNSManager:
    """
    Manages system DNS settings.
    Saves original DNS on start, restores on stop.
    Cross-platform: macOS, Windows, Linux
    """

    def __init__(self):
        self.logger = get_logger()
        self.original_dns = {}
        self.network_interface = None
        self._dns_changed = False

    def get_active_interface(self):
        """Get the currently active network interface"""
        if is_macos():
            return self._get_active_interface_macos()
        elif is_windows():
            return self._get_active_interface_windows()
        elif is_linux():
            return self._get_active_interface_linux()
        else:
            self.logger.error(f"Unsupported platform")
            return None

    def _get_active_interface_macos(self):
        """Get active network service on macOS using default route"""
        try:
            # Get the interface used for default route (actual internet traffic)
            route_result = subprocess.run(
                ['route', '-n', 'get', 'default'],
                capture_output=True, text=True
            )
            device = None
            for line in route_result.stdout.split('\n'):
                if 'interface:' in line:
                    device = line.split(':')[1].strip()
                    break

            if not device:
                self.logger.error("Could not determine default route interface")
                return None

            # Map device (e.g., en0) to network service name (e.g., Wi-Fi)
            hw_result = subprocess.run(
                ['networksetup', '-listallhardwareports'],
                capture_output=True, text=True, check=True
            )

            service_name = None
            lines = hw_result.stdout.split('\n')
            for i, line in enumerate(lines):
                if f'Device: {device}' in line:
                    # Service name is on the line before this one
                    for j in range(i - 1, -1, -1):
                        if lines[j].startswith('Hardware Port:'):
                            service_name = lines[j].replace('Hardware Port:', '').strip()
                            break
                    break

            if service_name:
                self.logger.info(f"Active network service: {service_name} ({device})")
                return service_name

            self.logger.error(f"Could not find network service for device {device}")
            return None
        except Exception as e:
            self.logger.error(f"Error getting network services: {e}")
            return None

    def _get_active_interface_windows(self):
        """Get active network interface on Windows"""
        try:
            result = subprocess.run(
                ['powershell', '-Command',
                 "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1 -ExpandProperty Name"],
                capture_output=True, text=True, check=True
            )
            interface = result.stdout.strip()
            if interface:
                self.logger.info(f"Active network interface: {interface}")
                return interface
            return None
        except Exception as e:
            self.logger.error(f"Error getting network interface: {e}")
            return None

    def _get_active_interface_linux(self):
        """Get active network interface on Linux"""
        try:
            result = subprocess.run(
                ['ip', 'route', 'show', 'default'],
                capture_output=True, text=True, check=True
            )
            # Parse: "default via X.X.X.X dev eth0 ..."
            parts = result.stdout.split()
            if 'dev' in parts:
                idx = parts.index('dev')
                interface = parts[idx + 1]
                self.logger.info(f"Active network interface: {interface}")
                return interface
            return None
        except Exception as e:
            self.logger.error(f"Error getting network interface: {e}")
            return None

    def get_current_dns(self):
        """Get current DNS servers"""
        if is_macos():
            return self._get_dns_macos()
        elif is_windows():
            return self._get_dns_windows()
        elif is_linux():
            return self._get_dns_linux()
        return []

    def _get_dns_macos(self):
        """Get DNS servers on macOS"""
        if not self.network_interface:
            return []
        try:
            result = subprocess.run(
                ['networksetup', '-getdnsservers', self.network_interface],
                capture_output=True, text=True, check=True
            )
            output = result.stdout.strip()
            if "There aren't any DNS Servers set" in output:
                return []
            return [line.strip() for line in output.split('\n') if line.strip()]
        except Exception as e:
            self.logger.error(f"Error getting DNS: {e}")
            return []

    def _get_dns_windows(self):
        """Get DNS servers on Windows"""
        if not self.network_interface:
            return []
        try:
            result = subprocess.run(
                ['powershell', '-Command',
                 f"(Get-DnsClientServerAddress -InterfaceAlias '{self.network_interface}' -AddressFamily IPv4).ServerAddresses"],
                capture_output=True, text=True, check=True
            )
            return [line.strip() for line in result.stdout.split('\n') if line.strip()]
        except Exception as e:
            self.logger.error(f"Error getting DNS: {e}")
            return []

    def _get_dns_linux(self):
        """Get DNS servers on Linux"""
        try:
            with open('/etc/resolv.conf', 'r') as f:
                dns_servers = []
                for line in f:
                    if line.strip().startswith('nameserver'):
                        dns_servers.append(line.split()[1])
                return dns_servers
        except Exception as e:
            self.logger.error(f"Error getting DNS: {e}")
            return []

    def set_dns(self, dns_servers):
        """Set DNS servers"""
        if is_macos():
            return self._set_dns_macos(dns_servers)
        elif is_windows():
            return self._set_dns_windows(dns_servers)
        elif is_linux():
            return self._set_dns_linux(dns_servers)
        return False

    def _set_dns_macos(self, dns_servers):
        """Set DNS servers on macOS"""
        if not self.network_interface:
            return False
        try:
            if not dns_servers:
                cmd = ['networksetup', '-setdnsservers', self.network_interface, 'Empty']
            else:
                cmd = ['networksetup', '-setdnsservers', self.network_interface] + dns_servers

            self.logger.info(f"Setting DNS for {self.network_interface}: {dns_servers or 'DHCP'}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0
        except Exception as e:
            self.logger.error(f"Error setting DNS: {e}")
            return False

    def _set_dns_windows(self, dns_servers):
        """Set DNS servers on Windows"""
        if not self.network_interface:
            return False
        try:
            if not dns_servers:
                cmd = ['powershell', '-Command',
                       f"Set-DnsClientServerAddress -InterfaceAlias '{self.network_interface}' -ResetServerAddresses"]
            else:
                dns_str = ','.join(f"'{d}'" for d in dns_servers)
                cmd = ['powershell', '-Command',
                       f"Set-DnsClientServerAddress -InterfaceAlias '{self.network_interface}' -ServerAddresses @({dns_str})"]

            self.logger.info(f"Setting DNS for {self.network_interface}: {dns_servers or 'DHCP'}")
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0
        except Exception as e:
            self.logger.error(f"Error setting DNS: {e}")
            return False

    def _set_dns_linux(self, dns_servers):
        """Set DNS servers on Linux (modifies /etc/resolv.conf)"""
        try:
            self.logger.info(f"Setting DNS: {dns_servers or 'DHCP'}")
            if dns_servers:
                content = '\n'.join(f'nameserver {dns}' for dns in dns_servers) + '\n'
                with open('/etc/resolv.conf', 'w') as f:
                    f.write(content)
            return True
        except Exception as e:
            self.logger.error(f"Error setting DNS: {e}")
            return False

    def save_and_set_local_dns(self):
        """Save current DNS and set to 127.0.0.1"""
        self.network_interface = self.get_active_interface()
        if not self.network_interface:
            self.logger.error("Cannot determine network interface - DNS not changed")
            return False

        current_dns = self.get_current_dns()
        self.original_dns[self.network_interface] = current_dns
        self.logger.info(f"Saved original DNS: {current_dns or 'DHCP'}")

        if self.set_dns(['127.0.0.1']):
            self._dns_changed = True
            self.logger.info("DNS set to 127.0.0.1")
            return True
        return False

    def restore_original_dns(self):
        """Restore original DNS settings"""
        if not self._dns_changed:
            return True

        if not self.network_interface:
            return False

        original = self.original_dns.get(self.network_interface, [])
        self.logger.info(f"Restoring original DNS: {original or 'DHCP'}")

        if self.set_dns(original):
            self._dns_changed = False
            self.logger.info("Original DNS restored")
            return True
        return False

    @property
    def dns_changed(self):
        return self._dns_changed


_dns_manager = None

def get_dns_manager():
    global _dns_manager
    if _dns_manager is None:
        _dns_manager = NetworkDNSManager()
    return _dns_manager
