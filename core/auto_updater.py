"""
Automatic Blocklist Updater - Background service for periodic blocklist updates
"""
from threading import Thread, Event
import time
from core.blocklist_updater import BlocklistUpdater
from core.logger import get_logger


class AutoUpdater:
    """
    Background service that automatically updates blocklists on a schedule
    """

    def __init__(self, update_interval=86400, preset=None, on_update_callback=None):
        """
        Initialize auto-updater

        Args:
            update_interval: Update interval in seconds (default: 86400 = 24 hours)
            preset: Preset name to use for updates (None = use enabled sources)
            on_update_callback: Callback function to call after successful update
        """
        self.update_interval = update_interval
        self.preset = preset
        self.on_update_callback = on_update_callback

        self.logger = get_logger()
        self.updater = BlocklistUpdater()

        # Thread control
        self.running = False
        self.thread = None
        self.stop_event = Event()

        # Statistics
        self.stats = {
            'last_update': None,
            'next_update': None,
            'total_updates': 0,
            'successful_updates': 0,
            'failed_updates': 0
        }

    def start(self, update_on_startup=True):
        """
        Start the auto-updater background thread

        Args:
            update_on_startup: If True, update immediately before starting timer
        """
        if self.running:
            self.logger.warning("Auto-updater already running")
            return

        self.logger.info("Starting automatic blocklist updater...")
        self.logger.info(f"Update interval: {self.update_interval} seconds ({self.update_interval / 3600:.1f} hours)")

        if self.preset:
            self.logger.info(f"Using preset: {self.preset}")
        else:
            enabled_sources = self.updater.get_enabled_sources()
            self.logger.info(f"Using enabled sources: {', '.join(enabled_sources)}")

        # Update immediately if requested
        if update_on_startup:
            self.logger.info("Performing initial blocklist update...")
            self._perform_update()

        # Start background thread
        self.running = True
        self.stop_event.clear()
        self.thread = Thread(target=self._update_loop, daemon=True, name="AutoUpdater")
        self.thread.start()

        self.logger.success("Auto-updater started successfully")

    def stop(self):
        """Stop the auto-updater background thread"""
        if not self.running:
            return

        self.logger.info("Stopping auto-updater...")
        self.running = False
        self.stop_event.set()

        # Wait for thread to finish (with timeout)
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)

        self.logger.success("Auto-updater stopped")

    def _update_loop(self):
        """Background thread loop for periodic updates"""
        while self.running:
            try:
                # Calculate next update time
                next_update_in = self.update_interval
                self.stats['next_update'] = time.time() + next_update_in

                self.logger.info(f"Next blocklist update in {next_update_in / 3600:.1f} hours")

                # Wait for the interval (or until stop event is set)
                if self.stop_event.wait(timeout=next_update_in):
                    # Stop event was set, exit loop
                    break

                # Perform the update
                if self.running:
                    self._perform_update()

            except Exception as e:
                self.logger.error(f"Error in auto-updater loop: {e}")
                # Sleep briefly before retrying
                time.sleep(60)

    def _perform_update(self):
        """Perform a blocklist update"""
        try:
            self.logger.info("Starting scheduled blocklist update...")
            self.stats['total_updates'] += 1

            # Perform the update
            result = self.updater.update_blocklists(
                preset=self.preset,
                sources=None  # Use preset or enabled sources
            )

            if result['success']:
                self.stats['successful_updates'] += 1
                self.stats['last_update'] = time.time()

                # Log success
                if 'merge' in result and result['merge']['success']:
                    merge = result['merge']
                    self.logger.success(
                        f"Blocklist update completed: "
                        f"{merge['unique_domains']:,} unique domains from {merge['sources']} sources"
                    )

                # Call the callback to reload blocklists
                if self.on_update_callback:
                    try:
                        self.on_update_callback()
                        self.logger.info("Blocklists reloaded in DNS server")
                    except Exception as e:
                        self.logger.error(f"Error reloading blocklists: {e}")
            else:
                self.stats['failed_updates'] += 1
                self.logger.error("Blocklist update failed")

        except Exception as e:
            self.stats['failed_updates'] += 1
            self.logger.error(f"Error performing blocklist update: {e}")

    def trigger_update_now(self):
        """Trigger an immediate update (doesn't reset the timer)"""
        self.logger.info("Manual update triggered")
        self._perform_update()

    def get_stats(self):
        """Get auto-updater statistics"""
        stats = self.stats.copy()

        # Add human-readable times
        if stats['last_update']:
            stats['last_update_ago'] = time.time() - stats['last_update']

        if stats['next_update']:
            stats['next_update_in'] = max(0, stats['next_update'] - time.time())

        return stats

    def is_running(self):
        """Check if auto-updater is running"""
        return self.running
