"""
Blocklist Manager - Loads and checks domains against blocklist
Supports exact matches, wildcards, and whitelists
"""
from pathlib import Path
from threading import RLock
from datetime import datetime
import re
from core.platform_utils import get_config_dir


class BlocklistManager:
    """
    Manages domain blocklists and whitelists with thread-safe operations
    """

    def __init__(self, blocklist_file=None, whitelist_file=None):
        # Use platform-specific config directory if not specified
        if blocklist_file is None:
            self.blocklist_file = str(get_config_dir() / 'blocklists.txt')
        else:
            self.blocklist_file = blocklist_file

        if whitelist_file is None:
            self.whitelist_file = str(get_config_dir() / 'whitelist.txt')
        else:
            self.whitelist_file = whitelist_file

        # Domain storage
        self.blocked_domains = set()
        self.wildcard_domains = set()
        self.whitelist_domains = set()
        self.whitelist_wildcards = set()

        # Statistics
        self.stats = {
            'total_blocks': 0,
            'total_checks': 0,
            'blocked_count': 0,
            'allowed_count': 0,
            'whitelisted_count': 0,
            'last_loaded': None,
            'load_count': 0
        }

        # Thread safety
        self._lock = RLock()

    def load(self, logger=None):
        """
        Load blocklist and whitelist from files

        Args:
            logger: Logger instance (optional, for compatibility)
        """
        with self._lock:
            # Clear existing data
            self.blocked_domains.clear()
            self.wildcard_domains.clear()
            self.whitelist_domains.clear()
            self.whitelist_wildcards.clear()

            # Load blocklist
            blocked_count = self._load_blocklist()

            # Load whitelist
            whitelist_count = self._load_whitelist()

            # Update stats
            self.stats['total_blocks'] = blocked_count
            self.stats['last_loaded'] = datetime.now()
            self.stats['load_count'] += 1

            if logger:
                logger.success(
                    f"Loaded {blocked_count} blocked domains "
                    f"({len(self.wildcard_domains)} wildcards), "
                    f"{whitelist_count} whitelisted"
                )

            return blocked_count, whitelist_count

    def _load_blocklist(self):
        """Load blocklist from file"""
        blocklist_path = Path(self.blocklist_file)

        if not blocklist_path.exists():
            return 0

        try:
            with open(blocklist_path, 'r', encoding='utf-8') as f:
                for line in f:
                    domain = self._parse_domain_line(line)
                    if domain:
                        if domain.startswith('*.'):
                            # Wildcard domain
                            self.wildcard_domains.add(domain[2:])
                        else:
                            # Exact domain
                            self.blocked_domains.add(domain)
        except Exception as e:
            print(f"Error loading blocklist: {e}")
            return 0

        return len(self.blocked_domains) + len(self.wildcard_domains)

    def _load_whitelist(self):
        """Load whitelist from file"""
        whitelist_path = Path(self.whitelist_file)

        if not whitelist_path.exists():
            return 0

        try:
            with open(whitelist_path, 'r', encoding='utf-8') as f:
                for line in f:
                    domain = self._parse_domain_line(line)
                    if domain:
                        if domain.startswith('*.'):
                            self.whitelist_wildcards.add(domain[2:])
                        else:
                            self.whitelist_domains.add(domain)
        except Exception as e:
            print(f"Error loading whitelist: {e}")
            return 0

        return len(self.whitelist_domains) + len(self.whitelist_wildcards)

    def _parse_domain_line(self, line):
        """
        Parse a domain from a line in blocklist/whitelist file
        Supports multiple formats:
        - Plain domain: example.com
        - With trailing dot: example.com.
        - Wildcard: *.example.com
        - Hosts file format: 0.0.0.0 example.com or 127.0.0.1 example.com
        - Comments: # comment or // comment

        Returns:
            Cleaned domain string or None if line should be skipped
        """
        # Remove whitespace
        line = line.strip()

        # Skip empty lines and comments
        if not line or line.startswith('#') or line.startswith('//'):
            return None

        # Handle hosts file format (0.0.0.0 domain or 127.0.0.1 domain)
        if line.startswith(('0.0.0.0', '127.0.0.1')):
            parts = line.split()
            if len(parts) >= 2:
                line = parts[1]

        # Clean the domain
        domain = line.lower().rstrip('.')

        # Validate domain format (basic validation)
        if self._is_valid_domain(domain):
            return domain

        return None

    def _is_valid_domain(self, domain):
        """
        Basic domain validation
        Accepts wildcards like *.example.com
        """
        if not domain:
            return False

        # Remove wildcard prefix for validation
        check_domain = domain[2:] if domain.startswith('*.') else domain

        # Basic regex for domain validation
        # Allows alphanumeric, hyphens, and dots
        pattern = r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'

        return bool(re.match(pattern, check_domain))

    def is_blocked(self, domain):
        """
        Check if a domain should be blocked

        Args:
            domain: Domain name to check

        Returns:
            bool: True if domain is blocked, False otherwise
        """
        with self._lock:
            self.stats['total_checks'] += 1

            # Normalize domain
            domain = domain.lower().rstrip('.')

            # 1. Check whitelist first (whitelist overrides blocklist)
            if self._is_whitelisted(domain):
                self.stats['whitelisted_count'] += 1
                self.stats['allowed_count'] += 1
                return False

            # 2. Check exact blocklist match
            if domain in self.blocked_domains:
                self.stats['blocked_count'] += 1
                return True

            # 3. Check wildcard blocklist match
            if self._check_wildcard_match(domain, self.wildcard_domains):
                self.stats['blocked_count'] += 1
                return True

            # Not blocked
            self.stats['allowed_count'] += 1
            return False

    def _is_whitelisted(self, domain):
        """Check if domain is whitelisted"""
        # Check exact whitelist match
        if domain in self.whitelist_domains:
            return True

        # Check wildcard whitelist match
        return self._check_wildcard_match(domain, self.whitelist_wildcards)

    def _check_wildcard_match(self, domain, wildcard_set):
        """
        Check if domain matches any wildcard pattern

        Example:
            - "www.facebook.com" matches "*.facebook.com" (facebook.com in wildcard_set)
            - "mail.google.com" matches "*.google.com"
        """
        for wildcard in wildcard_set:
            # Check if domain ends with the wildcard pattern
            if domain.endswith(wildcard):
                # Also check if it's a proper subdomain match
                # (not just partial string match)
                if domain == wildcard or domain.endswith('.' + wildcard):
                    return True

        return False

    def add_domain(self, domain, is_wildcard=False):
        """
        Add a domain to the blocklist at runtime

        Args:
            domain: Domain to block
            is_wildcard: If True, block all subdomains
        """
        with self._lock:
            domain = domain.lower().rstrip('.')

            if is_wildcard:
                self.wildcard_domains.add(domain)
            else:
                self.blocked_domains.add(domain)

            self.stats['total_blocks'] += 1

    def remove_domain(self, domain):
        """
        Remove a domain from the blocklist at runtime

        Args:
            domain: Domain to unblock
        """
        with self._lock:
            domain = domain.lower().rstrip('.')

            # Try to remove from both sets
            removed = False
            if domain in self.blocked_domains:
                self.blocked_domains.remove(domain)
                removed = True
            if domain in self.wildcard_domains:
                self.wildcard_domains.remove(domain)
                removed = True

            if removed:
                self.stats['total_blocks'] -= 1

            return removed

    def get_stats(self):
        """Get blocklist statistics"""
        with self._lock:
            return self.stats.copy()

    def reload(self, logger=None):
        """
        Reload blocklists from files

        Args:
            logger: Logger instance (optional)
        """
        if logger:
            logger.info("Reloading blocklists...")

        return self.load(logger)