"""
SQLite Database for DNS query logging and statistics
"""
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta
from threading import Lock
from contextlib import contextmanager
from core.platform_utils import get_data_dir


class DNSDatabase:
    """
    Thread-safe SQLite database for DNS query logging and statistics
    """

    def __init__(self, db_path=None):
        """
        Initialize database connection

        Args:
            db_path: Path to SQLite database file (None = use platform-specific data dir)
        """
        # Use platform-specific path if not specified
        if db_path is None:
            self.db_path = str(get_data_dir() / 'dns_agent.db')
        else:
            self.db_path = db_path

        self._lock = Lock()

        # Ensure database directory exists
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)

        # Initialize database schema
        try:
            self._init_schema()
        except Exception as e:
            print(f"ERROR: Failed to initialize database: {e}")
            raise

    @contextmanager
    def _get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Enable column access by name
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()

    def _init_schema(self):
        """Initialize database schema"""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                # Table: dns_queries - All DNS queries
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS dns_queries (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME NOT NULL,
                        domain TEXT NOT NULL,
                        query_type TEXT NOT NULL,
                        client_ip TEXT NOT NULL,
                        result TEXT NOT NULL,
                        answer TEXT,
                        response_time_ms INTEGER,
                        cached BOOLEAN DEFAULT 0
                    )
                ''')

                # Index for faster queries
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_timestamp
                    ON dns_queries(timestamp)
                ''')

                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_domain
                    ON dns_queries(domain)
                ''')

                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_result
                    ON dns_queries(result)
                ''')

                # Table: daily_stats - Aggregated daily statistics
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS daily_stats (
                        date DATE PRIMARY KEY,
                        total_queries INTEGER DEFAULT 0,
                        blocked_queries INTEGER DEFAULT 0,
                        allowed_queries INTEGER DEFAULT 0,
                        cached_queries INTEGER DEFAULT 0,
                        failed_queries INTEGER DEFAULT 0,
                        unique_domains INTEGER DEFAULT 0,
                        unique_clients INTEGER DEFAULT 0
                    )
                ''')

                # Table: top_blocked - Top blocked domains
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS top_blocked (
                        domain TEXT PRIMARY KEY,
                        block_count INTEGER DEFAULT 0,
                        last_blocked DATETIME
                    )
                ''')

                # Table: top_queried - Top queried domains
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS top_queried (
                        domain TEXT PRIMARY KEY,
                        query_count INTEGER DEFAULT 0,
                        last_queried DATETIME
                    )
                ''')

                conn.commit()

    def log_query(self, domain, query_type, client_ip, result, answer=None,
                  response_time_ms=None, cached=False):
        """
        Log a DNS query to the database

        Args:
            domain: Domain name queried
            query_type: DNS query type (A, AAAA, etc.)
            client_ip: Client IP address
            result: Query result (ALLOWED, BLOCKED, FAILED)
            answer: DNS answer/response (optional)
            response_time_ms: Response time in milliseconds (optional)
            cached: Whether response was served from cache
        """
        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()

                    # Insert query log
                    cursor.execute('''
                        INSERT INTO dns_queries
                        (timestamp, domain, query_type, client_ip, result, answer, response_time_ms, cached)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        datetime.now(),
                        domain.lower().rstrip('.'),
                        query_type,
                        client_ip,
                        result,
                        answer,
                        response_time_ms,
                        cached
                    ))

                    # Update aggregated stats
                    self._update_daily_stats(cursor, result)

                    # Update top domains
                    if result == 'BLOCKED':
                        self._update_top_blocked(cursor, domain)
                    else:
                        self._update_top_queried(cursor, domain)

            except Exception as e:
                print(f"Database error logging query: {e}")

    def _update_daily_stats(self, cursor, result):
        """Update daily statistics"""
        today = datetime.now().date()

        # Check if today's stats exist
        cursor.execute('SELECT date FROM daily_stats WHERE date = ?', (today,))
        row = cursor.fetchone()

        if row is None:
            # Create today's stats
            cursor.execute('''
                INSERT INTO daily_stats (date, total_queries)
                VALUES (?, 1)
            ''', (today,))
        else:
            # Update today's stats
            cursor.execute('''
                UPDATE daily_stats
                SET total_queries = total_queries + 1
                WHERE date = ?
            ''', (today,))

        # Update result-specific counter
        if result == 'BLOCKED':
            cursor.execute('''
                UPDATE daily_stats
                SET blocked_queries = blocked_queries + 1
                WHERE date = ?
            ''', (today,))
        elif result == 'ALLOWED':
            cursor.execute('''
                UPDATE daily_stats
                SET allowed_queries = allowed_queries + 1
                WHERE date = ?
            ''', (today,))
        elif result == 'FAILED':
            cursor.execute('''
                UPDATE daily_stats
                SET failed_queries = failed_queries + 1
                WHERE date = ?
            ''', (today,))

    def _update_top_blocked(self, cursor, domain):
        """Update top blocked domains"""
        domain = domain.lower().rstrip('.')

        cursor.execute('''
            INSERT INTO top_blocked (domain, block_count, last_blocked)
            VALUES (?, 1, ?)
            ON CONFLICT(domain) DO UPDATE SET
                block_count = block_count + 1,
                last_blocked = ?
        ''', (domain, datetime.now(), datetime.now()))

    def _update_top_queried(self, cursor, domain):
        """Update top queried domains"""
        domain = domain.lower().rstrip('.')

        cursor.execute('''
            INSERT INTO top_queried (domain, query_count, last_queried)
            VALUES (?, 1, ?)
            ON CONFLICT(domain) DO UPDATE SET
                query_count = query_count + 1,
                last_queried = ?
        ''', (domain, datetime.now(), datetime.now()))

    def get_recent_queries(self, limit=100, result_filter=None):
        """
        Get recent DNS queries

        Args:
            limit: Maximum number of queries to return
            result_filter: Filter by result type (ALLOWED, BLOCKED, FAILED)

        Returns:
            List of query dictionaries
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                if result_filter:
                    cursor.execute('''
                        SELECT * FROM dns_queries
                        WHERE result = ?
                        ORDER BY timestamp DESC
                        LIMIT ?
                    ''', (result_filter, limit))
                else:
                    cursor.execute('''
                        SELECT * FROM dns_queries
                        ORDER BY timestamp DESC
                        LIMIT ?
                    ''', (limit,))

                rows = cursor.fetchall()
                return [dict(row) for row in rows]

    def get_top_blocked(self, limit=20):
        """
        Get top blocked domains

        Args:
            limit: Number of domains to return

        Returns:
            List of domain dictionaries with block counts
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                cursor.execute('''
                    SELECT domain, block_count, last_blocked
                    FROM top_blocked
                    ORDER BY block_count DESC
                    LIMIT ?
                ''', (limit,))

                rows = cursor.fetchall()
                return [dict(row) for row in rows]

    def get_top_queried(self, limit=20):
        """
        Get top queried domains

        Args:
            limit: Number of domains to return

        Returns:
            List of domain dictionaries with query counts
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                cursor.execute('''
                    SELECT domain, query_count, last_queried
                    FROM top_queried
                    ORDER BY query_count DESC
                    LIMIT ?
                ''', (limit,))

                rows = cursor.fetchall()
                return [dict(row) for row in rows]

    def get_daily_stats(self, days=7):
        """
        Get daily statistics for the past N days

        Args:
            days: Number of days to retrieve

        Returns:
            List of daily statistics dictionaries
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                start_date = (datetime.now() - timedelta(days=days)).date()

                cursor.execute('''
                    SELECT * FROM daily_stats
                    WHERE date >= ?
                    ORDER BY date DESC
                ''', (start_date,))

                rows = cursor.fetchall()
                return [dict(row) for row in rows]

    def get_total_stats(self):
        """
        Get total statistics across all time

        Returns:
            Dictionary with total statistics
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                # Total queries by result
                cursor.execute('''
                    SELECT
                        COUNT(*) as total,
                        SUM(CASE WHEN result = 'BLOCKED' THEN 1 ELSE 0 END) as blocked,
                        SUM(CASE WHEN result = 'ALLOWED' THEN 1 ELSE 0 END) as allowed,
                        SUM(CASE WHEN result = 'FAILED' THEN 1 ELSE 0 END) as failed,
                        SUM(CASE WHEN cached = 1 THEN 1 ELSE 0 END) as cached
                    FROM dns_queries
                ''')

                row = cursor.fetchone()

                # Unique domains and clients
                cursor.execute('SELECT COUNT(DISTINCT domain) FROM dns_queries')
                unique_domains = cursor.fetchone()[0]

                cursor.execute('SELECT COUNT(DISTINCT client_ip) FROM dns_queries')
                unique_clients = cursor.fetchone()[0]

                return {
                    'total_queries': row['total'] or 0,
                    'blocked_queries': row['blocked'] or 0,
                    'allowed_queries': row['allowed'] or 0,
                    'failed_queries': row['failed'] or 0,
                    'cached_queries': row['cached'] or 0,
                    'unique_domains': unique_domains or 0,
                    'unique_clients': unique_clients or 0
                }

    def get_query_timeline(self, hours=24, interval_minutes=60):
        """
        Get query timeline for charts

        Args:
            hours: Number of hours to look back
            interval_minutes: Interval size in minutes

        Returns:
            List of time intervals with query counts
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                start_time = datetime.now() - timedelta(hours=hours)

                cursor.execute('''
                    SELECT
                        strftime('%Y-%m-%d %H:%M', timestamp) as time_bucket,
                        COUNT(*) as total,
                        SUM(CASE WHEN result = 'BLOCKED' THEN 1 ELSE 0 END) as blocked,
                        SUM(CASE WHEN result = 'ALLOWED' THEN 1 ELSE 0 END) as allowed
                    FROM dns_queries
                    WHERE timestamp >= ?
                    GROUP BY time_bucket
                    ORDER BY time_bucket
                ''', (start_time,))

                rows = cursor.fetchall()
                return [dict(row) for row in rows]

    def get_top_domains(self, result=None, days=7, limit=20):
        """
        Get top domains by query count for a specific result type

        Args:
            result: Filter by result type (ALLOWED, BLOCKED, FAILED) or None for all
            days: Number of days to look back
            limit: Maximum number of domains to return

        Returns:
            List of dictionaries with domain and count
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                start_time = datetime.now() - timedelta(days=days)

                if result:
                    cursor.execute('''
                        SELECT domain, COUNT(*) as count
                        FROM dns_queries
                        WHERE result = ? AND timestamp >= ?
                        GROUP BY domain
                        ORDER BY count DESC
                        LIMIT ?
                    ''', (result, start_time, limit))
                else:
                    cursor.execute('''
                        SELECT domain, COUNT(*) as count
                        FROM dns_queries
                        WHERE timestamp >= ?
                        GROUP BY domain
                        ORDER BY count DESC
                        LIMIT ?
                    ''', (start_time, limit))

                rows = cursor.fetchall()
                return [dict(row) for row in rows]

    def cleanup_old_data(self, days=30):
        """
        Clean up old query logs

        Args:
            days: Keep logs newer than this many days

        Returns:
            Number of deleted rows
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                cutoff_date = datetime.now() - timedelta(days=days)

                cursor.execute('''
                    DELETE FROM dns_queries
                    WHERE timestamp < ?
                ''', (cutoff_date,))

                deleted = cursor.rowcount
                return deleted
