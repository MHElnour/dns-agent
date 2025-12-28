"""
Web Dashboard - Flask-based web interface for DNS Agent
Provides real-time statistics, query history, and management interface
"""
from flask import Flask, render_template, jsonify, request
from datetime import datetime, timedelta
from threading import Thread
import time
from core.logger import get_logger


class Dashboard:
    """
    Web dashboard for DNS Agent
    Provides real-time statistics and management interface
    """

    def __init__(self, dns_server, host='127.0.0.1', port=8080):
        """
        Initialize dashboard

        Args:
            dns_server: DNSServer instance
            host: Host to bind to
            port: Port to bind to
        """
        self.dns_server = dns_server
        self.host = host
        self.port = port
        self.logger = get_logger()

        # Create Flask app
        self.app = Flask(
            __name__,
            template_folder='../ui/templates',
            static_folder='../ui/static'
        )

        # Register routes
        self._register_routes()

        # Server thread
        self.thread = None
        self.running = False

    def _register_routes(self):
        """Register Flask routes"""

        @self.app.route('/')
        def index():
            """Main dashboard page"""
            return render_template('dashboard.html')

        @self.app.route('/api/stats')
        def get_stats():
            """Get current statistics"""
            try:
                stats = self.dns_server.get_stats()

                # Add cache stats if cache is enabled
                if self.dns_server.cache:
                    cache_stats = self.dns_server.cache.get_stats()
                    stats['cache'] = cache_stats

                # Add auto-updater stats if enabled
                if self.dns_server.auto_updater:
                    updater_stats = self.dns_server.auto_updater.get_stats()
                    stats['auto_updater'] = updater_stats

                # Add blocklist stats
                stats['blocklist'] = {
                    'blocked_domains': len(self.dns_server.blocklist.blocked_domains),
                    'wildcard_domains': len(self.dns_server.blocklist.wildcard_domains),
                    'whitelist_domains': len(self.dns_server.blocklist.whitelist_domains),
                    'whitelist_wildcards': len(self.dns_server.blocklist.whitelist_wildcards)
                }

                return jsonify(stats)

            except Exception as e:
                self.logger.error(f"Error getting stats: {e}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/queries/recent')
        def get_recent_queries():
            """Get recent queries"""
            try:
                limit = request.args.get('limit', 100, type=int)

                if self.dns_server.db:
                    queries = self.dns_server.db.get_recent_queries(limit)
                    return jsonify(queries)
                else:
                    return jsonify([])

            except Exception as e:
                self.logger.error(f"Error getting recent queries: {e}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/queries/timeline')
        def get_query_timeline():
            """Get query timeline (last 24 hours)"""
            try:
                hours = request.args.get('hours', 24, type=int)

                if self.dns_server.db:
                    timeline = self.dns_server.db.get_query_timeline(hours)
                    return jsonify(timeline)
                else:
                    return jsonify([])

            except Exception as e:
                self.logger.error(f"Error getting query timeline: {e}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/queries/top-blocked')
        def get_top_blocked():
            """Get top blocked domains"""
            try:
                limit = request.args.get('limit', 20, type=int)
                days = request.args.get('days', 7, type=int)

                if self.dns_server.db:
                    top_blocked = self.dns_server.db.get_top_domains(
                        result='BLOCKED',
                        days=days,
                        limit=limit
                    )
                    return jsonify(top_blocked)
                else:
                    return jsonify([])

            except Exception as e:
                self.logger.error(f"Error getting top blocked domains: {e}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/queries/top-allowed')
        def get_top_allowed():
            """Get top allowed domains"""
            try:
                limit = request.args.get('limit', 20, type=int)
                days = request.args.get('days', 7, type=int)

                if self.dns_server.db:
                    top_allowed = self.dns_server.db.get_top_domains(
                        result='ALLOWED',
                        days=days,
                        limit=limit
                    )
                    return jsonify(top_allowed)
                else:
                    return jsonify([])

            except Exception as e:
                self.logger.error(f"Error getting top allowed domains: {e}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/blocklist/sources')
        def get_blocklist_sources():
            """Get available blocklist sources"""
            try:
                if self.dns_server.auto_updater:
                    updater = self.dns_server.auto_updater.updater
                    sources = updater.list_sources()
                    presets = updater.list_presets()

                    return jsonify({
                        'sources': sources,
                        'presets': presets,
                        'enabled_sources': updater.get_enabled_sources()
                    })
                else:
                    return jsonify({'sources': {}, 'presets': {}, 'enabled_sources': []})

            except Exception as e:
                self.logger.error(f"Error getting blocklist sources: {e}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/blocklist/update', methods=['POST'])
        def trigger_blocklist_update():
            """Trigger immediate blocklist update"""
            try:
                if self.dns_server.auto_updater:
                    # Trigger update in background
                    Thread(
                        target=self.dns_server.auto_updater.trigger_update_now,
                        daemon=True,
                        name="ManualUpdate"
                    ).start()
                    return jsonify({'success': True, 'message': 'Update triggered'})
                else:
                    return jsonify({'success': False, 'message': 'Auto-updater not enabled'}), 400

            except Exception as e:
                self.logger.error(f"Error triggering blocklist update: {e}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/cache/clear', methods=['POST'])
        def clear_cache():
            """Clear DNS cache"""
            try:
                if self.dns_server.cache:
                    self.dns_server.cache.clear()
                    return jsonify({'success': True, 'message': 'Cache cleared'})
                else:
                    return jsonify({'success': False, 'message': 'Cache not enabled'}), 400

            except Exception as e:
                self.logger.error(f"Error clearing cache: {e}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/server/info')
        def get_server_info():
            """Get server information"""
            try:
                info = {
                    'host': self.dns_server.host,
                    'port': self.dns_server.port,
                    'upstream_dns': self.dns_server.upstream_dns,
                    'cache_enabled': self.dns_server.cache is not None,
                    'database_enabled': self.dns_server.db is not None,
                    'auto_updater_enabled': self.dns_server.auto_updater is not None,
                    'max_workers': self.dns_server.executor._max_workers,
                    'running': self.dns_server.running
                }

                return jsonify(info)

            except Exception as e:
                self.logger.error(f"Error getting server info: {e}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/settings/load')
        def load_settings():
            """Load settings from YAML config file"""
            try:
                import yaml
                from pathlib import Path
                from core.platform_utils import get_config_dir

                config_path = get_config_dir() / 'dns_agent.yml'
                if config_path.exists():
                    with open(config_path, 'r') as f:
                        config = yaml.safe_load(f) or {}
                else:
                    config = {}

                # Return full config
                return jsonify({
                    'success': True,
                    'config': config
                })

            except Exception as e:
                self.logger.error(f"Error loading settings: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500

        @self.app.route('/api/settings/save', methods=['POST'])
        def save_settings():
            """Save settings to YAML config file"""
            try:
                import yaml
                from pathlib import Path
                from core.platform_utils import get_config_dir

                settings = request.json

                # Load current config
                config_path = get_config_dir() / 'dns_agent.yml'
                if config_path.exists():
                    with open(config_path, 'r') as f:
                        config = yaml.safe_load(f) or {}
                else:
                    config = {}

                # Update config with new settings
                if 'server' in settings:
                    config.setdefault('server', {}).update(settings['server'])

                if 'blocklist' in settings:
                    config.setdefault('blocklist', {}).update(settings['blocklist'])

                if 'cache' in settings:
                    config.setdefault('cache', {}).update(settings['cache'])

                if 'logging' in settings:
                    config.setdefault('logging', {}).update(settings['logging'])

                # Ensure config directory exists
                config_path.parent.mkdir(parents=True, exist_ok=True)

                # Save config
                with open(config_path, 'w') as f:
                    yaml.dump(config, f, default_flow_style=False, sort_keys=False)

                self.logger.info(f"Settings saved to {config_path}")
                return jsonify({
                    'success': True,
                    'message': 'Settings saved successfully. Restart the server for changes to take effect.'
                })

            except Exception as e:
                self.logger.error(f"Error saving settings: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500

        @self.app.route('/api/blocklist-sources/load')
        def load_blocklist_sources():
            """Load blocklist sources configuration"""
            try:
                import yaml
                from pathlib import Path
                from core.platform_utils import get_config_dir

                sources_path = get_config_dir() / 'blocklist_sources.yml'
                if sources_path.exists():
                    with open(sources_path, 'r') as f:
                        sources_config = yaml.safe_load(f) or {}
                else:
                    sources_config = {}

                return jsonify({
                    'success': True,
                    'config': sources_config
                })

            except Exception as e:
                self.logger.error(f"Error loading blocklist sources: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500

        @self.app.route('/api/blocklist-sources/save', methods=['POST'])
        def save_blocklist_sources():
            """Save blocklist sources configuration"""
            try:
                import yaml
                from pathlib import Path
                from core.platform_utils import get_config_dir

                sources_config = request.json

                sources_path = get_config_dir() / 'blocklist_sources.yml'

                # Ensure config directory exists
                sources_path.parent.mkdir(parents=True, exist_ok=True)

                # Save config
                with open(sources_path, 'w') as f:
                    yaml.dump(sources_config, f, default_flow_style=False, sort_keys=False)

                self.logger.info(f"Blocklist sources saved to {sources_path}")
                return jsonify({
                    'success': True,
                    'message': 'Blocklist sources saved successfully.'
                })

            except Exception as e:
                self.logger.error(f"Error saving blocklist sources: {e}")
                return jsonify({'success': False, 'error': str(e)}), 500

    def start(self):
        """Start dashboard server in background thread"""
        if self.running:
            self.logger.warning("Dashboard already running")
            return

        self.logger.info(f"Starting web dashboard on http://{self.host}:{self.port}")

        self.running = True
        self.thread = Thread(
            target=self._run_server,
            daemon=True,
            name="Dashboard"
        )
        self.thread.start()

        self.logger.success(f"Dashboard started at http://{self.host}:{self.port}")

    def _run_server(self):
        """Run Flask server"""
        try:
            self.app.run(
                host=self.host,
                port=self.port,
                debug=False,
                use_reloader=False,
                threaded=True
            )
        except Exception as e:
            self.logger.error(f"Error running dashboard server: {e}")

    def stop(self):
        """Stop dashboard server"""
        if not self.running:
            return

        self.logger.info("Stopping dashboard...")
        self.running = False

        # Note: Flask doesn't have a clean shutdown mechanism
        # The server will stop when the main process exits (daemon thread)

        self.logger.success("Dashboard stopped")

    def is_running(self):
        """Check if dashboard is running"""
        return self.running
