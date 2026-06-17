# Security Policy

## Supported versions

Only the latest release receives security fixes. Always run the most recent version of VortexPanel.

| Version | Supported |
|---|---|
| Latest (v3.1.x) | ✅ |
| Older releases | ❌ |

## Reporting a vulnerability

**Please do not report security vulnerabilities as public GitHub issues.**

VortexPanel is a server control panel — vulnerabilities could expose servers running it. Responsible disclosure gives maintainers time to fix the issue before it's made public.

To report a vulnerability:

1. Email the maintainer directly (check the GitHub profile for contact info)  
   **OR**
2. Use [GitHub's private security advisory](https://github.com/BrowserlessAPI/VortexPanel/security/advisories/new) feature

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Your suggested fix (if any)

You'll get a response within **72 hours**. Once a fix is released, you'll be credited in the release notes unless you prefer to stay anonymous.

## Known security considerations

- VortexPanel is designed to run as root (required for system management). Run it on a dedicated VPS, not shared hosting.
- The panel listens on port 8888 by default — restrict access with your firewall (e.g. `ufw allow from YOUR-IP to any port 8888`)
- HTTPS can be enabled by placing a reverse proxy (nginx) in front of Gunicorn
- Admin credentials are stored as SHA-256 hashes in `credentials.json`
