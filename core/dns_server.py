"""
DNS Server with blocking, caching, and statistics
"""
import socket
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
from datetime import datetime
from threading import Event, Lock
from concurrent.futures import ThreadPoolExecutor
import time
from core.blocklist import BlocklistManager
from core.cache import DNSCache
from core.database import DNSDatabase
from core.logger import get_logger
from core.auto_updater import AutoUpdater
from core.dashboard import Dashboard


class DNSServer:
    """
    Production-ready DNS server with blocking, caching, and statistics
    """

    def __init__(self, host='127.0.0.1', port=5354, upstream_dns='8.8.8.8',
                 enable_cache=True, enable_database=True, max_workers=50, config=None,
                 dns_manager=None):
        """
        Initialize DNS server

        Args:
            host: IP address to bind to
            port: Port to listen on
            upstream_dns: Upstream DNS server to forward queries to
            enable_cache: Enable DNS response caching (default: True)
            enable_database: Enable database logging (default: True)
            max_workers: Maximum concurrent query handlers (default: 50)
            config: Optional ConfigManager instance for advanced settings
        """
        # Network configuration
        self.host = host
        self.port = port
        self.upstream_dns = upstream_dns
        self.sock = None
        self.config = config
        self.dns_manager = dns_manager  # For managing system DNS settings

        # Components - use config if available
        blocklist_file = config.blocklist_file if config else 'config/blocklists.txt'
        whitelist_file = config.whitelist_file if config else 'config/whitelist.txt'
        self.blocklist = BlocklistManager(blocklist_file, whitelist_file)

        # Cache with config settings
        if enable_cache:
            if config:
                self.cache = DNSCache(
                    max_size=config.cache_max_size,
                    min_ttl=config.cache_min_ttl,
                    max_ttl=config.cache_max_ttl
                )
            else:
                self.cache = DNSCache()
        else:
            self.cache = None

        # Database with config settings
        if enable_database:
            db_path = config.database_path if config else 'data/dns_agent.db'
            self.db = DNSDatabase(db_path)
        else:
            self.db = None

        # Thread pool for concurrent query handling
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="DNSWorker")

        # Statistics (thread-safe with lock)
        self.stats = {
            'total_queries': 0,
            'blocked_queries': 0,
            'allowed_queries': 0,
            'cached_queries': 0,
            'failed_queries': 0,
            'upstream_queries': 0,
            'total_response_time_ms': 0,
            'start_time': None,
            'last_query_time': None
        }
        self.stats_lock = Lock()

        # Control
        self.running = False
        self.shutdown_event = Event()

        # Auto-updater (initialized but not started yet)
        self.auto_updater = None
        if config:
            auto_update_enabled = config.get('blocklist.auto_update', False)
            if auto_update_enabled:
                update_interval = config.get('blocklist.update_interval', 86400)
                update_preset = config.get('blocklist.update_preset')
                self.auto_updater = AutoUpdater(
                    update_interval=update_interval,
                    preset=update_preset,
                    on_update_callback=self._reload_blocklists
                )

        # Web dashboard (initialized but not started yet)
        self.dashboard = None
        if config:
            dashboard_enabled = config.get('dashboard.enabled', False)
            if dashboard_enabled:
                dashboard_host = config.get('dashboard.host', '127.0.0.1')
                dashboard_port = config.get('dashboard.port', 8080)
                self.dashboard = Dashboard(
                    dns_server=self,
                    host=dashboard_host,
                    port=dashboard_port
                )

        # Setup logger (if not already set up by main.py)
        self.logger = get_logger()

    def start(self):
        """Start the DNS server"""
        try:
            self.logger.info("Starting DNS server...")
            self.stats['start_time'] = datetime.now()

            # Load blocklist
            self.blocklist.load(self.logger)

            # Start auto-updater if enabled
            if self.auto_updater:
                update_on_startup = self.config.get('blocklist.update_on_startup', True) if self.config else False
                self.auto_updater.start(update_on_startup=update_on_startup)

            # Start web dashboard if enabled
            if self.dashboard:
                self.dashboard.start()

            # Set system DNS to 127.0.0.1 AFTER blocklist update (uses original DNS)
            if self.dns_manager:
                if self.dns_manager.save_and_set_local_dns():
                    self.logger.info("System DNS now points to this DNS server (127.0.0.1)")
                else:
                    self.logger.warning("Could not set system DNS - you may need to configure it manually")

            # Create and bind socket
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.settimeout(1.0)  # 1 second timeout for clean shutdown
            self.sock.bind((self.host, self.port))

            self.running = True
            self.logger.success(f"DNS server listening on {self.host}:{self.port}")
            self.logger.info(f"Upstream DNS: {self.upstream_dns}")
            self.logger.info("Waiting for queries... (Press Ctrl+C to stop)")

            # Main server loop
            self._serve()

        except PermissionError:
            self.logger.error(f"Permission denied: Cannot bind to {self.host}:{self.port}")
            self.logger.info("Try using a port > 1024 or run with sudo/admin privileges")
        except OSError as e:
            self.logger.error(f"Socket error: {e}")
        except Exception as e:
            self.logger.error(f"Failed to start server: {e}")
        finally:
            self.stop()

    def _serve(self):
        """Main server loop - receives queries and dispatches to thread pool"""
        while self.running:
            try:
                # Receive DNS query with timeout
                try:
                    data, addr = self.sock.recvfrom(512)
                except socket.timeout:
                    # Check shutdown event
                    if self.shutdown_event.is_set():
                        break
                    continue

                # Submit query to thread pool for concurrent handling
                self.executor.submit(self._handle_query, data, addr)

            except KeyboardInterrupt:
                self.logger.warning("\nShutdown signal received...")
                break
            except Exception as e:
                self.logger.error(f"Error in server loop: {e}")

    def _handle_query(self, data, addr):
        """
        Handle a single DNS query (runs in thread pool)

        Args:
            data: Raw DNS query data
            addr: Client address tuple (ip, port)
        """
        start_time = time.time()

        try:
            # Update statistics (thread-safe)
            with self.stats_lock:
                self.stats['total_queries'] += 1
                self.stats['last_query_time'] = datetime.now()

            # Parse DNS query
            query = dns.message.from_wire(data)

            # Extract domain from query
            if not query.question:
                self.logger.warning(f"Query with no questions from {addr[0]}")
                return

            question = query.question[0]
            domain = question.name.to_text()
            qtype = dns.rdatatype.to_text(question.rdtype)

            self.logger.info(f"Query: {domain} ({qtype}) from {addr[0]}")

            # Check if domain is blocked
            if self.blocklist.is_blocked(domain):
                response_time_ms = int((time.time() - start_time) * 1000)
                self._handle_blocked(query, domain, addr, response_time_ms)
                return

            # Check cache if enabled
            if self.cache:
                cached_response = self.cache.get(domain, qtype)
                if cached_response:
                    response_time_ms = int((time.time() - start_time) * 1000)
                    self._handle_cached(cached_response, domain, qtype, addr, query, response_time_ms)
                    return

            # Forward to upstream DNS
            self._handle_upstream(query, domain, qtype, addr, start_time)

        except dns.message.ShortHeader:
            self.logger.warning(f"Malformed DNS query from {addr[0]}")
            with self.stats_lock:
                self.stats['failed_queries'] += 1
        except Exception as e:
            self.logger.error(f"Error handling query from {addr[0]}: {e}")
            with self.stats_lock:
                self.stats['failed_queries'] += 1

    def _handle_blocked(self, query, domain, addr, response_time_ms):
        """
        Handle a blocked domain query

        Args:
            query: DNS query message
            domain: Domain name
            addr: Client address
            response_time_ms: Response time in milliseconds
        """
        with self.stats_lock:
            self.stats['blocked_queries'] += 1
            self.stats['total_response_time_ms'] += response_time_ms
        self.logger.warning(f"BLOCKED: {domain}")

        # Create NXDOMAIN response (domain doesn't exist)
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.NXDOMAIN)

        # Send response
        try:
            self.sock.sendto(response.to_wire(), addr)
        except Exception as e:
            self.logger.error(f"Failed to send blocked response: {e}")

        # Log to database
        if self.db:
            try:
                question = query.question[0]
                qtype = dns.rdatatype.to_text(question.rdtype)
                self.db.log_query(
                    domain=domain,
                    query_type=qtype,
                    client_ip=addr[0],
                    result='BLOCKED',
                    answer=None,
                    response_time_ms=response_time_ms,
                    cached=False
                )
            except Exception as e:
                self.logger.error(f"Database logging error: {e}")

    def _handle_cached(self, cached_response, domain, qtype, addr, original_query, response_time_ms):
        """
        Handle a cached DNS response

        Args:
            cached_response: Cached DNS response message
            domain: Domain name
            qtype: Query type
            addr: Client address
            original_query: Original DNS query (needed for ID)
            response_time_ms: Response time in milliseconds
        """
        with self.stats_lock:
            self.stats['cached_queries'] += 1
            self.stats['allowed_queries'] += 1
            self.stats['total_response_time_ms'] += response_time_ms

        # Extract answer for logging
        answer_text = self._format_answer(cached_response.answer) if cached_response.answer else "cached"
        self.logger.info(f"CACHED: {domain} → {answer_text}")

        # Create new response with correct transaction ID
        # We need to copy the cached response but use the original query's ID
        response = dns.message.make_response(original_query)
        response.answer = cached_response.answer
        response.authority = cached_response.authority
        response.additional = cached_response.additional
        response.flags = cached_response.flags

        # Send response with correct ID
        try:
            self.sock.sendto(response.to_wire(), addr)
        except Exception as e:
            self.logger.error(f"Failed to send cached response: {e}")

        # Log to database
        if self.db:
            try:
                self.db.log_query(
                    domain=domain,
                    query_type=qtype,
                    client_ip=addr[0],
                    result='ALLOWED',
                    answer=answer_text,
                    response_time_ms=response_time_ms,
                    cached=True
                )
            except Exception as e:
                self.logger.error(f"Database logging error: {e}")

    def _handle_upstream(self, query, domain, qtype, addr, start_time):
        """
        Forward query to upstream DNS server

        Args:
            query: DNS query message
            domain: Domain name
            qtype: Query type (A, AAAA, etc.)
            addr: Client address
            start_time: Query start time (for response time calculation)
        """
        try:
            with self.stats_lock:
                self.stats['upstream_queries'] += 1

            # Query upstream DNS with timeout
            response = dns.query.udp(
                query,
                self.upstream_dns,
                timeout=5.0,
                raise_on_truncation=False
            )

            # Calculate response time
            response_time_ms = int((time.time() - start_time) * 1000)

            # Parse response
            answer_text = None
            if response.answer:
                # Extract answer for logging
                answer_text = self._format_answer(response.answer)
                self.logger.success(f"Resolved: {domain} → {answer_text}")
                with self.stats_lock:
                    self.stats['allowed_queries'] += 1
                    self.stats['total_response_time_ms'] += response_time_ms
            else:
                # No answer (NXDOMAIN, SERVFAIL, etc.)
                rcode = dns.rcode.to_text(response.rcode())
                self.logger.info(f"No answer for {domain} ({rcode})")
                with self.stats_lock:
                    self.stats['allowed_queries'] += 1
                    self.stats['total_response_time_ms'] += response_time_ms

            # Send response to client
            self.sock.sendto(response.to_wire(), addr)

            # Cache response if caching is enabled
            if self.cache and response.answer:
                self.cache.store(domain, qtype, response)

            # Log to database
            if self.db:
                try:
                    self.db.log_query(
                        domain=domain,
                        query_type=qtype,
                        client_ip=addr[0],
                        result='ALLOWED',
                        answer=answer_text,
                        response_time_ms=response_time_ms,
                        cached=False
                    )
                except Exception as e:
                    self.logger.error(f"Database logging error: {e}")

        except (socket.timeout, OSError) as e:
            self.logger.error(f"Timeout querying upstream for {domain}")
            with self.stats_lock:
                self.stats['failed_queries'] += 1
            self._send_servfail(query, addr)

        except Exception as e:
            self.logger.error(f"Error querying upstream for {domain}: {e}")
            with self.stats_lock:
                self.stats['failed_queries'] += 1
            self._send_servfail(query, addr)

    def _format_answer(self, answer_section):
        """
        Format DNS answer section for logging

        Args:
            answer_section: DNS answer section

        Returns:
            Formatted string with answer data
        """
        try:
            answers = []
            for rrset in answer_section:
                for rdata in rrset:
                    answers.append(str(rdata))
            return ", ".join(answers) if answers else "empty"
        except Exception:
            return "unknown"

    def _send_servfail(self, query, addr):
        """
        Send a SERVFAIL response to client

        Args:
            query: Original DNS query
            addr: Client address
        """
        try:
            response = dns.message.make_response(query)
            response.set_rcode(dns.rcode.SERVFAIL)
            self.sock.sendto(response.to_wire(), addr)
        except Exception as e:
            self.logger.error(f"Failed to send SERVFAIL response: {e}")

    def _reload_blocklists(self):
        """Reload blocklists from disk (called by auto-updater after update)"""
        try:
            self.logger.info("Reloading blocklists...")
            self.blocklist.reload(self.logger)
            self.logger.success("Blocklists reloaded successfully")
        except Exception as e:
            self.logger.error(f"Error reloading blocklists: {e}")

    def stop(self):
        """Stop the DNS server gracefully"""
        self.logger.info("Stopping DNS server...")
        self.running = False
        self.shutdown_event.set()

        # Restore original DNS settings
        if self.dns_manager and self.dns_manager.dns_changed:
            self.logger.info("Restoring original DNS settings...")
            self.dns_manager.restore_original_dns()

        # Stop auto-updater if running
        if self.auto_updater and self.auto_updater.is_running():
            self.auto_updater.stop()

        # Stop dashboard if running
        if self.dashboard and self.dashboard.is_running():
            self.dashboard.stop()

        # Shutdown thread pool - wait for in-flight queries to complete
        self.logger.info("Waiting for in-flight queries to complete...")
        self.executor.shutdown(wait=True, cancel_futures=False)

        # Close socket
        if self.sock:
            try:
                self.sock.close()
            except Exception as e:
                self.logger.error(f"Error closing socket: {e}")

        # Print final statistics
        self._print_stats()
        self.logger.success("DNS server stopped")

    def _print_stats(self):
        """Print server statistics"""
        # Get snapshot of stats (thread-safe)
        with self.stats_lock:
            stats_snapshot = self.stats.copy()

        self.logger.info("=" * 50)
        self.logger.info("DNS Server Statistics")
        self.logger.info("=" * 50)
        self.logger.info(f"Total queries:    {stats_snapshot['total_queries']}")
        self.logger.info(f"Blocked queries:  {stats_snapshot['blocked_queries']}")
        self.logger.info(f"Allowed queries:  {stats_snapshot['allowed_queries']}")
        self.logger.info(f"Cached queries:   {stats_snapshot['cached_queries']}")
        self.logger.info(f"Failed queries:   {stats_snapshot['failed_queries']}")

        # Calculate percentages
        if stats_snapshot['total_queries'] > 0:
            block_rate = (stats_snapshot['blocked_queries'] / stats_snapshot['total_queries']) * 100
            cache_rate = (stats_snapshot['cached_queries'] / stats_snapshot['total_queries']) * 100
            self.logger.info(f"Block rate:       {block_rate:.1f}%")
            self.logger.info(f"Cache hit rate:   {cache_rate:.1f}%")

        # Cache statistics
        if self.cache:
            cache_stats = self.cache.get_stats()
            self.logger.info(f"Cache size:       {cache_stats['size']}/{cache_stats['max_size']}")

        # Uptime
        if stats_snapshot['start_time']:
            uptime = datetime.now() - stats_snapshot['start_time']
            self.logger.info(f"Uptime:           {uptime}")

        self.logger.info("=" * 50)

    def get_stats(self):
        """Get current server statistics (thread-safe)"""
        with self.stats_lock:
            stats = self.stats.copy()

        # Rename for consistency with dashboard
        stats['queries_blocked'] = stats.get('blocked_queries', 0)
        stats['queries_allowed'] = stats.get('allowed_queries', 0)
        stats['queries_cached'] = stats.get('cached_queries', 0)
        stats['queries_failed'] = stats.get('failed_queries', 0)

        # Total response time is already in stats from the copy

        # Add blocklist stats
        stats['blocklist_stats'] = self.blocklist.get_stats()

        # Add cache stats if available
        if self.cache:
            stats['cache_stats'] = self.cache.get_stats()

        return stats

    def reload_blocklist(self):
        """Reload blocklist from files"""
        self.logger.info("Reloading blocklist...")
        self.blocklist.reload(self.logger)