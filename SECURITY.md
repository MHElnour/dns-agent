# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in DNS Agent, please report it by creating a private security advisory on GitHub or by emailing the maintainer directly.

**Please do not open public issues for security vulnerabilities.**

### What to include in your report:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if available)

### Response timeline:

- Initial response: Within 48 hours
- Status update: Within 7 days
- Fix timeline: Depends on severity and complexity

## Security Best Practices

When using DNS Agent:

1. **Run with minimum privileges** - Only use sudo/admin when necessary (port 53)
2. **Review blocklists** - Understand what domains are being blocked
3. **Monitor logs** - Check `data/dns_agent.db` for unusual queries
4. **Keep updated** - Regularly update dependencies and blocklists
5. **Secure dashboard** - The web dashboard (port 9880) is not authenticated - use firewall rules to restrict access

## Known Security Considerations

- Dashboard has no authentication - restrict access via firewall
- System DNS modification requires elevated privileges on some platforms
- Blocklist sources are fetched from third-party URLs - review sources before enabling

## Automated Security Scanning

This repository uses:
- **CodeQL** - Weekly automated code scanning for security vulnerabilities
- **Dependabot** - Automated dependency vulnerability alerts and updates
