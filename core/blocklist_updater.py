"""
Automatic Blocklist Updater - Downloads and updates blocklists from public sources
Supports multiple popular blocklist formats and sources
"""
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime
from threading import Lock
import hashlib
import re
import yaml
from core.logger import get_logger
from core.platform_utils import get_config_dir, get_blocklist_dir


class BlocklistUpdater:
    """
    Downloads and manages blocklists from public sources
    Loads configuration from YAML file for flexibility
    """

    def __init__(self, output_dir=None, cache_dir=None,
                 config_file=None):
        """
        Initialize blocklist updater

        Args:
            output_dir: Directory to save merged blocklist (None = use platform-specific config dir)
            cache_dir: Directory to cache downloaded blocklists (None = use platform-specific blocklist dir)
            config_file: Path to YAML configuration file (None = use platform-specific config dir)
        """
        # Use platform-specific directories if not specified
        self.output_dir = Path(output_dir) if output_dir else get_config_dir()
        self.cache_dir = Path(cache_dir) if cache_dir else get_blocklist_dir()
        self.config_file = Path(config_file) if config_file else (get_config_dir() / 'blocklist_sources.yml')
        self.logger = get_logger()
        self._lock = Lock()

        # Load configuration from YAML
        self.config = self._load_config()
        self.sources = self.config.get('sources', {})
        self.presets = self.config.get('presets', {})
        self.update_settings = self.config.get('update', {})

        # Statistics
        self.stats = {
            'last_update': None,
            'total_sources': 0,
            'successful_downloads': 0,
            'failed_downloads': 0,
            'total_domains': 0,
            'unique_domains': 0
        }

        # Ensure directories exist
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _load_config(self):
        """
        Load configuration from YAML file

        Returns:
            Dictionary with configuration
        """
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f)
                    self.logger.info(f"Loaded blocklist config from {self.config_file}")
                    return config
            else:
                self.logger.warning(f"Config file not found: {self.config_file}")
                return {'sources': {}, 'presets': {}, 'update': {}}
        except Exception as e:
            self.logger.error(f"Error loading config file: {e}")
            return {'sources': {}, 'presets': {}, 'update': {}}

    def download_blocklists(self, sources=None, preset=None, timeout=None):
        """
        Download blocklists from specified sources or preset

        Args:
            sources: List of source IDs to download (None = enabled sources)
            preset: Preset name to use (overrides sources parameter)
            timeout: Download timeout in seconds (None = use config default)

        Returns:
            Dictionary with download results
        """
        with self._lock:
            self.logger.info("Starting blocklist download...")

            # Use timeout from config if not specified
            if timeout is None:
                timeout = self.update_settings.get('timeout', 30)

            # Handle preset
            if preset:
                if preset in self.presets:
                    sources = self.presets[preset].get('sources', [])
                    self.logger.info(f"Using preset: {preset} ({self.presets[preset].get('description', '')})")
                else:
                    self.logger.error(f"Unknown preset: {preset}")
                    return {'success': False, 'error': f'Unknown preset: {preset}'}

            # Use enabled sources if none specified
            if sources is None:
                sources = [sid for sid, info in self.sources.items() if info.get('enabled', False)]
                if not sources:
                    self.logger.warning("No enabled sources found, using all sources")
                    sources = list(self.sources.keys())

            # Validate sources
            invalid_sources = [s for s in sources if s not in self.sources]
            if invalid_sources:
                self.logger.warning(f"Invalid sources: {', '.join(invalid_sources)}")
                sources = [s for s in sources if s in self.sources]

            if not sources:
                self.logger.error("No valid sources specified")
                return {'success': False, 'error': 'No valid sources'}

            self.stats['total_sources'] = len(sources)
            self.stats['successful_downloads'] = 0
            self.stats['failed_downloads'] = 0

            # Download each source
            downloaded_files = []
            for source_id in sources:
                result = self._download_source(source_id, timeout)
                if result['success']:
                    downloaded_files.append(result['file_path'])
                    self.stats['successful_downloads'] += 1
                else:
                    self.stats['failed_downloads'] += 1

            self.logger.info(
                f"Downloaded {self.stats['successful_downloads']}/{self.stats['total_sources']} sources"
            )

            return {
                'success': True,
                'downloaded': self.stats['successful_downloads'],
                'failed': self.stats['failed_downloads'],
                'files': downloaded_files,
                'sources': sources  # Return the actual list of sources downloaded
            }

    def _download_source(self, source_id, timeout):
        """
        Download a single blocklist source

        Args:
            source_id: Source identifier
            timeout: Download timeout

        Returns:
            Dictionary with download result
        """
        source = self.sources[source_id]
        self.logger.info(f"Downloading: {source['name']}")

        try:
            # Download with user agent to avoid blocking
            req = urllib.request.Request(
                source['url'],
                headers={'User-Agent': 'DNS-Agent/1.0 (Blocklist Updater)'}
            )

            with urllib.request.urlopen(req, timeout=timeout) as response:
                content = response.read().decode('utf-8', errors='ignore')

            # Save to cache directory
            cache_file = self.cache_dir / f"{source_id}.txt"
            with open(cache_file, 'w', encoding='utf-8') as f:
                f.write(content)

            # Calculate hash for change detection
            content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]

            self.logger.success(f"Downloaded {source['name']} ({len(content)} bytes)")

            return {
                'success': True,
                'source_id': source_id,
                'file_path': cache_file,
                'size': len(content),
                'hash': content_hash
            }

        except urllib.error.HTTPError as e:
            self.logger.error(f"HTTP error downloading {source['name']}: {e.code} {e.reason}")
            return {'success': False, 'error': f"HTTP {e.code}"}

        except urllib.error.URLError as e:
            self.logger.error(f"Network error downloading {source['name']}: {e.reason}")
            return {'success': False, 'error': str(e.reason)}

        except Exception as e:
            self.logger.error(f"Error downloading {source['name']}: {e}")
            return {'success': False, 'error': str(e)}

    def merge_blocklists(self, sources=None, output_file='blocklists.txt',
                        include_comments=True, deduplicate=True):
        """
        Merge downloaded blocklists into a single file

        Args:
            sources: List of source IDs to merge (None = all cached files)
            output_file: Output filename
            include_comments: Include source attribution comments
            deduplicate: Remove duplicate domains

        Returns:
            Dictionary with merge results
        """
        with self._lock:
            self.logger.info("Merging blocklists...")

            domains = set() if deduplicate else []
            total_entries = 0

            # Get list of files to merge
            if sources is None:
                files_to_merge = list(self.cache_dir.glob("*.txt"))
            else:
                files_to_merge = [self.cache_dir / f"{s}.txt" for s in sources if (self.cache_dir / f"{s}.txt").exists()]

            if not files_to_merge:
                self.logger.error("No blocklist files to merge")
                return {'success': False, 'error': 'No files to merge'}

            # Process each file
            for file_path in files_to_merge:
                source_id = file_path.stem
                source_info = self.sources.get(source_id, {})
                file_format = source_info.get('format', 'domains')

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    # Parse domains based on format
                    parsed_domains = self._parse_blocklist(content, file_format)

                    if deduplicate:
                        domains.update(parsed_domains)
                    else:
                        domains.extend(parsed_domains)

                    total_entries += len(parsed_domains)

                    self.logger.info(f"Parsed {len(parsed_domains)} domains from {source_id}")

                except Exception as e:
                    self.logger.error(f"Error processing {file_path}: {e}")

            # Write merged blocklist
            output_path = self.output_dir / output_file

            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    # Write header
                    if include_comments:
                        f.write("# DNS Agent Blocklist\n")
                        f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write(f"# Total domains: {len(domains)}\n")
                        f.write(f"# Sources: {len(files_to_merge)}\n")
                        f.write("#\n")

                        # List sources
                        for file_path in files_to_merge:
                            source_id = file_path.stem
                            source_info = self.sources.get(source_id, {})
                            if source_info:
                                f.write(f"# - {source_info.get('name', source_id)}\n")

                        f.write("#\n\n")

                    # Write domains (sorted for consistency)
                    sorted_domains = sorted(domains) if deduplicate else domains
                    for domain in sorted_domains:
                        f.write(f"{domain}\n")

                self.stats['total_domains'] = total_entries
                self.stats['unique_domains'] = len(domains)
                self.stats['last_update'] = datetime.now()

                self.logger.success(
                    f"Merged blocklist saved to {output_path} "
                    f"({len(domains)} unique domains from {total_entries} total entries)"
                )

                return {
                    'success': True,
                    'output_file': output_path,
                    'total_domains': total_entries,
                    'unique_domains': len(domains),
                    'sources': len(files_to_merge)
                }

            except Exception as e:
                self.logger.error(f"Error writing merged blocklist: {e}")
                return {'success': False, 'error': str(e)}

    def _parse_blocklist(self, content, file_format):
        """
        Parse blocklist content based on format

        Args:
            content: Raw blocklist content
            file_format: Format type (hosts, domains, adblock)

        Returns:
            Set of parsed domains
        """
        domains = set()

        if file_format == 'hosts':
            # Parse hosts file format (0.0.0.0 domain.com or 127.0.0.1 domain.com)
            for line in content.splitlines():
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue

                # Parse hosts format
                if line.startswith(('0.0.0.0', '127.0.0.1')):
                    parts = line.split()
                    if len(parts) >= 2:
                        domain = parts[1].lower().rstrip('.')
                        if self._is_valid_domain(domain):
                            domains.add(domain)

        elif file_format == 'domains':
            # Parse plain domain list
            for line in content.splitlines():
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue

                domain = line.lower().rstrip('.')
                if self._is_valid_domain(domain):
                    domains.add(domain)

        elif file_format == 'adblock':
            # Parse AdBlock/uBlock format (||domain.com^)
            for line in content.splitlines():
                line = line.strip()

                # Skip empty lines, comments, and element hiding rules
                if not line or line.startswith(('!', '[', '#')):
                    continue

                # Extract domain from ||domain.com^
                if line.startswith('||') and '^' in line:
                    domain = line[2:line.index('^')].lower().rstrip('.')

                    # Skip if it contains path or other modifiers
                    if '/' not in domain and '$' not in domain:
                        if self._is_valid_domain(domain):
                            domains.add(domain)

        return domains

    def _is_valid_domain(self, domain):
        """
        Validate domain format

        Args:
            domain: Domain to validate

        Returns:
            True if valid domain
        """
        if not domain or len(domain) > 253:
            return False

        # Skip localhost and local domains
        if domain in ('localhost', 'localhost.localdomain', 'local', 'broadcasthost'):
            return False

        # Skip IP addresses
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
            return False

        # Basic domain validation (alphanumeric, hyphens, dots, wildcards)
        # Allow wildcards like *.domain.com
        check_domain = domain[2:] if domain.startswith('*.') else domain

        pattern = r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'
        return bool(re.match(pattern, check_domain))

    def update_blocklists(self, sources=None, preset=None, timeout=None, output_file='blocklists.txt'):
        """
        Download and merge blocklists in one operation

        Args:
            sources: List of source IDs (None = enabled sources)
            preset: Preset name to use (overrides sources parameter)
            timeout: Download timeout (None = use config default)
            output_file: Output filename

        Returns:
            Dictionary with update results
        """
        self.logger.info("=" * 50)
        self.logger.info("Blocklist Update Started")
        self.logger.info("=" * 50)

        # Get settings from config
        if timeout is None:
            timeout = self.update_settings.get('timeout', 30)

        include_comments = self.update_settings.get('include_comments', True)
        deduplicate = self.update_settings.get('deduplicate', True)

        # Download blocklists
        download_result = self.download_blocklists(sources, preset, timeout)

        if not download_result['success'] or download_result['downloaded'] == 0:
            self.logger.error("No blocklists downloaded, aborting merge")
            return download_result

        # Merge blocklists - use the actual sources that were downloaded
        actual_sources = download_result.get('sources')
        merge_result = self.merge_blocklists(actual_sources, output_file, include_comments, deduplicate)

        self.logger.info("=" * 50)
        self.logger.info("Blocklist Update Complete")
        self.logger.info("=" * 50)

        return {
            'success': merge_result['success'],
            'download': download_result,
            'merge': merge_result,
            'stats': self.get_stats()
        }

    def get_stats(self):
        """Get updater statistics"""
        with self._lock:
            return self.stats.copy()

    def list_sources(self):
        """
        List all available blocklist sources

        Returns:
            Dictionary of available sources
        """
        return self.sources.copy()

    def get_source_info(self, source_id):
        """
        Get information about a specific source

        Args:
            source_id: Source identifier

        Returns:
            Source information dictionary or None
        """
        return self.sources.get(source_id)

    def list_presets(self):
        """
        List all available presets

        Returns:
            Dictionary of available presets
        """
        return self.presets.copy()

    def get_preset_info(self, preset_name):
        """
        Get information about a specific preset

        Args:
            preset_name: Preset name

        Returns:
            Preset information dictionary or None
        """
        return self.presets.get(preset_name)

    def get_enabled_sources(self):
        """
        Get list of enabled sources

        Returns:
            List of enabled source IDs
        """
        return [sid for sid, info in self.sources.items() if info.get('enabled', False)]
