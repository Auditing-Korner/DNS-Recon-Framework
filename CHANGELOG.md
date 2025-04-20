# Changelog

## Version 2.1.0 (2024)

### Major Changes
- Upgraded framework to fully integrate all tools with proper inheritance from BaseTool
- Added new SSL/TLS security scanner tool for comprehensive certificate and protocol analysis
- Added new DNS takeover scanner tool for subdomain takeover vulnerability detection
- Improved mobile gateway enumeration with support for targeting specific gateway types

### New Tools
- **ssl_scanner**: Comprehensive SSL/TLS configuration and vulnerability scanner
  - Detects support for weak protocols (SSLv2, SSLv3, TLSv1.0)
  - Identifies weak ciphers and insecure configurations
  - Checks certificate validity, expiration, and name mismatches
  - Detects known vulnerabilities (BEAST, POODLE, FREAK, etc.)

- **dns_takeover**: DNS subdomain takeover vulnerability scanner
  - Detects dangling DNS records vulnerable to subdomain takeover
  - Supports numerous cloud services and hosting platforms
  - Includes fingerprints for AWS, Azure, GitHub, Heroku, etc.
  - Automatically enumerates subdomains or accepts a custom list

### Improvements
- **mobile_gateway_enum.py**: 
  - Rewritten to properly integrate with the BaseTool class
  - Added support for targeting specific gateway types (GGSN, P-GW, S-GW, etc.)
  - Added configuration from the framework's config.yaml file
  - Improved error handling and reporting

### Configuration
- Updated config.yaml with comprehensive settings for all tools
- Added specific configurations for new tools
- Ensured compatibility with existing framework elements

### Documentation
- Added README.md with comprehensive documentation
- Added requirements.txt for easier dependency management
- Added detailed usage examples for all tools

### Framework Updates
- Updated tools/__init__.py to register and integrate new tools
- Ensured all tools follow the standard BaseTool interface
- Standardized error handling and results reporting across all tools
- Improved logging and result collection

### Bug Fixes
- Fixed thread management in concurrent operations
- Improved error handling for network connectivity issues
- Added proper dependency checking in tool initialization

## Version 1.0.0 (Original Release)

- Initial release of the RFS DNS Framework
- Core functionality for DNS enumeration and analysis
- Basic tools for cloud provider detection
- Mobile gateway enumeration capabilities
- Reports generation in JSON and HTML formats 