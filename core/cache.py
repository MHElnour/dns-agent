"""
DNS Response Cache with TTL (Time-To-Live) support
Caches DNS responses to reduce upstream queries and improve performance
"""
from threading import RLock
from datetime import datetime, timedelta
from collections import OrderedDict
import dns.message


class DNSCache:
    """
    Thread-safe DNS response cache with TTL and LRU eviction
    """

    def __init__(self, max_size=10000, min_ttl=60, max_ttl=86400):
        """
        Initialize DNS cache

        Args:
            max_size: Maximum number of cached entries (LRU eviction)
            min_ttl: Minimum TTL in seconds (default: 60s = 1 minute)
            max_ttl: Maximum TTL in seconds (default: 86400s = 24 hours)
        """
        self.max_size = max_size
        self.min_ttl = min_ttl
        self.max_ttl = max_ttl

        # Cache storage: {(domain, qtype): CacheEntry}
        self._cache = OrderedDict()

        # Statistics
        self.stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'expirations': 0,
            'stores': 0
        }

        # Thread safety
        self._lock = RLock()

    def get(self, domain, qtype='A'):
        """
        Retrieve a cached DNS response

        Args:
            domain: Domain name
            qtype: Query type (A, AAAA, MX, etc.)

        Returns:
            DNS response message if found and not expired, None otherwise
        """
        with self._lock:
            # Normalize domain
            domain = domain.lower().rstrip('.')
            key = (domain, qtype)

            # Check if entry exists
            if key not in self._cache:
                self.stats['misses'] += 1
                return None

            entry = self._cache[key]

            # Check if entry has expired
            if entry.is_expired():
                # Remove expired entry
                del self._cache[key]
                self.stats['expirations'] += 1
                self.stats['misses'] += 1
                return None

            # Cache hit - move to end (most recently used)
            self._cache.move_to_end(key)
            self.stats['hits'] += 1

            return entry.response

    def store(self, domain, qtype, response, ttl=None):
        """
        Store a DNS response in cache

        Args:
            domain: Domain name
            qtype: Query type (A, AAAA, MX, etc.)
            response: DNS response message to cache
            ttl: Time-to-live in seconds (optional, extracted from response if not provided)
        """
        with self._lock:
            # Normalize domain
            domain = domain.lower().rstrip('.')
            key = (domain, qtype)

            # Extract TTL from response if not provided
            if ttl is None:
                ttl = self._extract_ttl(response)

            # Enforce min/max TTL limits
            ttl = max(self.min_ttl, min(ttl, self.max_ttl))

            # Create cache entry
            entry = CacheEntry(response, ttl)

            # Remove old entry if exists
            if key in self._cache:
                del self._cache[key]

            # Add to cache
            self._cache[key] = entry

            # Move to end (most recently used)
            self._cache.move_to_end(key)

            # Evict oldest entry if cache is full
            if len(self._cache) > self.max_size:
                self._cache.popitem(last=False)  # Remove oldest (first) item
                self.stats['evictions'] += 1

            self.stats['stores'] += 1

    def _extract_ttl(self, response):
        """
        Extract TTL from DNS response

        Args:
            response: DNS response message

        Returns:
            TTL in seconds (default: min_ttl if not found)
        """
        try:
            # Get minimum TTL from all answer records
            min_ttl = None

            for rrset in response.answer:
                if min_ttl is None or rrset.ttl < min_ttl:
                    min_ttl = rrset.ttl

            # If no TTL found, use default
            if min_ttl is None:
                return self.min_ttl

            return int(min_ttl)

        except Exception:
            return self.min_ttl

    def clear(self):
        """Clear all cached entries"""
        with self._lock:
            self._cache.clear()

    def remove(self, domain, qtype='A'):
        """
        Remove a specific entry from cache

        Args:
            domain: Domain name
            qtype: Query type

        Returns:
            True if entry was removed, False if not found
        """
        with self._lock:
            domain = domain.lower().rstrip('.')
            key = (domain, qtype)

            if key in self._cache:
                del self._cache[key]
                return True

            return False

    def cleanup_expired(self):
        """
        Remove all expired entries from cache

        Returns:
            Number of entries removed
        """
        with self._lock:
            expired_keys = []

            # Find all expired entries
            for key, entry in self._cache.items():
                if entry.is_expired():
                    expired_keys.append(key)

            # Remove expired entries
            for key in expired_keys:
                del self._cache[key]
                self.stats['expirations'] += 1

            return len(expired_keys)

    def get_stats(self):
        """
        Get cache statistics

        Returns:
            Dictionary with cache statistics
        """
        with self._lock:
            total_requests = self.stats['hits'] + self.stats['misses']
            hit_rate = (self.stats['hits'] / total_requests * 100) if total_requests > 0 else 0

            return {
                **self.stats,
                'size': len(self._cache),
                'max_size': self.max_size,
                'hit_rate': round(hit_rate, 2),
                'total_requests': total_requests
            }

    def get_size(self):
        """Get current cache size"""
        with self._lock:
            return len(self._cache)

    def get_entries(self, limit=100):
        """
        Get cache entries for debugging/display

        Args:
            limit: Maximum number of entries to return

        Returns:
            List of cache entry information
        """
        with self._lock:
            entries = []

            for (domain, qtype), entry in list(self._cache.items())[:limit]:
                entries.append({
                    'domain': domain,
                    'qtype': qtype,
                    'expires_at': entry.expires_at.isoformat(),
                    'ttl_remaining': entry.get_ttl_remaining(),
                    'is_expired': entry.is_expired()
                })

            return entries


class CacheEntry:
    """
    A single cache entry with expiration time
    """

    def __init__(self, response, ttl):
        """
        Initialize cache entry

        Args:
            response: DNS response message
            ttl: Time-to-live in seconds
        """
        self.response = response
        self.ttl = ttl
        self.created_at = datetime.now()
        self.expires_at = self.created_at + timedelta(seconds=ttl)

    def is_expired(self):
        """Check if cache entry has expired"""
        return datetime.now() >= self.expires_at

    def get_ttl_remaining(self):
        """
        Get remaining TTL in seconds

        Returns:
            Remaining TTL in seconds (0 if expired)
        """
        if self.is_expired():
            return 0

        remaining = (self.expires_at - datetime.now()).total_seconds()
        return max(0, int(remaining))
