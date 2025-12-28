# DNS Agent

DNS sinkhole server with ad/malware blocking, caching, database logging, and web dashboard.

## Quick Start

### 1. Activate the virtual environment
```bash
source .venv/bin/activate
```

### 2. Run DNS Agent
```bash
# Run on default port 5354 (no sudo required)
dnsagent

# Run on port 53 (requires sudo)
sudo dnsagent --port 53
```

### 3. Update blocklists
```bash
dnsagent-update-blocklists
```

## Usage

### Start the DNS server
```bash
# Development mode (uses ./config and ./data)
DNS_AGENT_DEV_MODE=1 dnsagent

# Production mode (uses ~/Library/Application Support/DNSAgent/)
dnsagent

# Custom port
sudo dnsagent --port 53

# Custom upstream DNS
dnsagent --upstream 8.8.8.8
```

### Access the Dashboard
Once started, the web dashboard is available at:
- **http://127.0.0.1:9880**

Features:
- Real-time DNS query monitoring
- Block/Allow domain statistics
- Blocklist source management
- Settings configuration

### Update Blocklists
```bash
# Update using current preset
dnsagent-update-blocklists

# Update using specific preset
dnsagent-update-blocklists --preset aggressive

# Update specific sources only
dnsagent-update-blocklists --sources stevenblack adguard-dns

# List available sources
dnsagent-update-blocklists --list-sources

# List available presets
dnsagent-update-blocklists --list-presets
```

## Configuration

### Main Configuration
Edit `~/Library/Application Support/DNSAgent/dns_agent.yml`:
- Server settings (host, port, upstream DNS)
- Cache settings
- Database settings
- Blocklist settings
- Dashboard settings
- Logging settings

### Blocklist Sources
Edit `~/Library/Application Support/DNSAgent/blocklist_sources.yml`:
- Enable/disable specific blocklist sources
- Configure presets (minimal, balanced, aggressive, family, productivity, security)
- Add custom blocklist sources

### Development Mode
Set `DNS_AGENT_DEV_MODE=1` to use local directories:
- Config: `./config/`
- Data: `./data/`

## Data Locations

### Production Mode
- **Config**: `~/Library/Application Support/DNSAgent/`
  - `dns_agent.yml` - Main configuration
  - `blocklist_sources.yml` - Blocklist sources
  - `blocklists.txt` - Merged blocklist
  - `whitelist.txt` - Whitelist

- **Data**: `~/Library/Application Support/DNSAgent/data/`
  - `dns_agent.db` - SQLite database with query logs
  - `dns_queries.log` - Rotating log file

### Development Mode
- **Config**: `./config/`
- **Data**: `./data/`

## Available Presets

- **minimal**: Basic ad and malware blocking
- **balanced**: Balanced protection (recommended)
- **aggressive**: Maximum protection
- **family**: Family-friendly (blocks adult content)
- **productivity**: Blocks social media and distractions
- **security**: Security-focused (malware and phishing)

## Commands Reference

### dnsagent
Start the DNS server
```bash
dnsagent [--host HOST] [--port PORT] [--upstream UPSTREAM] [--config CONFIG]
```

### dnsagent-update-blocklists
Update blocklists from configured sources
```bash
dnsagent-update-blocklists [--preset PRESET] [--sources SOURCE1 SOURCE2 ...]
                          [--output FILE] [--list-sources] [--list-presets]
```

## Port 53 Note

To run on port 53 (standard DNS port), you need root privileges:
```bash
sudo dnsagent --port 53
```

## Stopping the Server

Press `Ctrl+C` to stop the server gracefully.
