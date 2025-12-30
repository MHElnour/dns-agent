"""
Main entry point - starts the DNS sinkhole server
"""
import argparse
import signal
import sys
from core.dns_server import DNSServer
from core.config import get_config
from core.logger import setup_logger, get_logger
from core.platform_utils import ensure_directories, setup_initial_config, get_config_dir


# Global reference for signal handler
_dns_server = None


def signal_handler(signum, frame):
    """Handle shutdown signals - stop server (which restores DNS)"""
    logger = get_logger()
    logger.info(f"Received signal {signum}, shutting down...")

    # Stop DNS server (this also restores original DNS settings)
    if _dns_server:
        _dns_server.stop()

    sys.exit(0)


def main():
    """Start the DNS sinkhole server"""
    global _dns_server

    # Ensure all necessary directories exist
    ensure_directories()

    # Copy default config files on first run
    setup_initial_config()

    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description='DNS Agent - DNS sinkhole with blocking and caching'
    )
    parser.add_argument('--config', default=None,
                        help=f'Path to config file (default: {get_config_dir()}/dns_agent.yml)')
    parser.add_argument('--host', help='Override host from config')
    parser.add_argument('--port', type=int, help='Override port from config')
    parser.add_argument('--upstream', help='Override upstream DNS from config')
    parser.add_argument('--manage-dns', action='store_true', default=True,
                        help='Automatically manage system DNS settings (default: enabled)')
    parser.add_argument('--no-manage-dns', action='store_true',
                        help='Do NOT automatically manage system DNS settings')
    args = parser.parse_args()

    # Determine if we should manage DNS
    manage_dns = args.manage_dns and not args.no_manage_dns

    # Load configuration
    config = get_config(args.config)

    # Setup logger with config settings
    setup_logger(
        log_dir=config.log_dir,
        console_level=config.console_log_level,
        file_level=config.file_log_level
    )

    logger = get_logger()

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Get DNS manager if DNS management is enabled
    # DNS will be set to 127.0.0.1 AFTER blocklist update inside dns_server.start()
    dns_manager = None
    if manage_dns:
        from core.network_utils import get_dns_manager
        dns_manager = get_dns_manager()

    # Create and start DNS server
    # Order inside start(): blocklist update -> set DNS to 127.0.0.1 -> serve
    _dns_server = DNSServer(
        host=args.host or config.server_host,
        port=args.port or config.server_port,
        upstream_dns=args.upstream or config.upstream_dns,
        enable_cache=config.cache_enabled,
        enable_database=config.database_enabled,
        max_workers=config.max_workers,
        config=config,
        dns_manager=dns_manager
    )

    try:
        _dns_server.start()
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)
    except Exception as e:
        logger.error(f"DNS server error: {e}")
        raise


if __name__ == "__main__":
    main()
