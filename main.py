"""
Main entry point - starts the DNS sinkhole server
"""
import argparse
from core.dns_server import DNSServer
from core.config import get_config
from core.logger import setup_logger
from core.platform_utils import ensure_directories, setup_initial_config, get_config_dir


def main():
    """Start the DNS sinkhole server"""
    # Ensure all necessary directories exist
    ensure_directories()

    # Copy default config files on first run
    setup_initial_config()

    # Parse command line arguments
    parser = argparse.ArgumentParser(description='DNS Agent - DNS sinkhole with blocking and caching')
    parser.add_argument('--config', default=None,
                        help=f'Path to configuration file (default: {get_config_dir()}/dns_agent.yml)')
    parser.add_argument('--host', help='Override host from config')
    parser.add_argument('--port', type=int, help='Override port from config')
    parser.add_argument('--upstream', help='Override upstream DNS from config')
    args = parser.parse_args()

    # Load configuration
    config = get_config(args.config)

    # Setup logger with config settings
    setup_logger(
        log_dir=config.log_dir,
        console_level=config.console_log_level,
        file_level=config.file_log_level
    )

    # Create DNS server with configuration
    dns_server = DNSServer(
        host=args.host or config.server_host,
        port=args.port or config.server_port,
        upstream_dns=args.upstream or config.upstream_dns,
        enable_cache=config.cache_enabled,
        enable_database=config.database_enabled,
        max_workers=config.max_workers,
        config=config
    )
    dns_server.start()


if __name__ == "__main__":
    main()