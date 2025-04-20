# RFS DNS Framework Tools

This section provides detailed documentation for each tool in the RFS DNS Framework.

## Core Security Tools

### [DNS Zone Walker](zone_walker.md)
DNSSEC zone enumeration using NSEC/NSEC3 records. Features zone transfer attempts, NSEC/NSEC3 chain walking, and NSEC3 hash cracking.

### [DNS Tunnel Detector](tunnel_detector.md)
Advanced DNS tunneling and data exfiltration detection using multiple analysis methods including statistical, entropy, pattern matching, and signature-based detection.

### [DNS Cache Poisoning](dns-cache-poison.md)
DNS cache poisoning detection and testing tool with support for various attack vectors and detection methods.

## Enumeration Tools

### [DNS Enumerator](dns_enum.md)
Comprehensive DNS record enumeration and analysis tool with support for various record types and discovery methods.

### [DNS Server Finder](find_dnsserver.md)
Tool for discovering and testing DNS servers, including support for various server types and testing methods.

### [TLD Bruteforcer](tld_brute.md)
Multi-threaded TLD discovery tool with support for custom wordlists and pattern-based discovery.

## Infrastructure Analysis

### [Cloud Provider Enumerator](cloud_enum.md)
Detect and analyze cloud service providers with support for AWS, Azure, GCP, and other major providers.

### [Mobile Gateway Enumerator](mobile_gw.md)
Specialized tool for enumerating 3GPP mobile network gateways and infrastructure.

### [SSL/TLS Scanner](ssl_scanner.md)
Comprehensive SSL/TLS security scanner with support for various vulnerability checks and best practices.

## Takeover Detection

### [DNS Takeover Scanner](dns_takeover.md)
DNS subdomain takeover vulnerability scanner with support for various cloud providers and services.

### [Subdomain Takeover Tester](subdomain_takeover.md)
Advanced tool for testing and verifying subdomain takeover vulnerabilities.

### [Cloud Takeover Detector](cloud_takeover.md)
Specialized tool for detecting cloud resource takeover vulnerabilities.

## Privacy & Compliance

### [Privacy Scanner](privacy_scanner.md)
DNS privacy testing tool with support for DoH, DoT, DNSCrypt, and other privacy-enhancing technologies.

### [Configuration Auditor](config_auditor.md)
DNS configuration and security best practices analysis tool.

## Tool Categories

### Security Testing
- DNS Zone Walker
- DNS Tunnel Detector
- DNS Cache Poisoning
- SSL/TLS Scanner

### Enumeration & Discovery
- DNS Enumerator
- DNS Server Finder
- TLD Bruteforcer
- Cloud Provider Enumerator

### Infrastructure Analysis
- Mobile Gateway Enumerator
- Cloud Takeover Detector
- Configuration Auditor

### Vulnerability Assessment
- DNS Takeover Scanner
- Subdomain Takeover Tester
- Privacy Scanner

## Tool Dependencies

Some tools require additional dependencies or privileges:

### Root/Administrator Required
- DNS Tunnel Detector
- DNS Cache Poisoning
- Mobile Gateway Enumerator

### Optional Dependencies
- Scapy (for packet capture and analysis)
- Cryptography (for SSL/TLS testing)
- Requests (for HTTP-based tests)

## Integration

All tools are designed to work both:
1. Standalone via direct execution
2. As part of the framework's workflow system
3. Through the framework's API

## Common Features

All tools share these features:
- Configuration via `config.yaml`
- JSON/HTML report generation
- Framework integration mode
- Logging and error handling
- Progress reporting
- Rate limiting support

## Best Practices

When using the tools:
1. Always check tool documentation for specific requirements
2. Use appropriate privileges for tools that need them
3. Consider rate limiting for production environments
4. Review and customize configurations as needed
5. Monitor resource usage for intensive operations
6. Follow security and privacy guidelines

## Contributing

To contribute new tools or improve existing ones:
1. Follow the tool template structure
2. Implement required base class methods
3. Add comprehensive documentation
4. Include tests and examples
5. Update the configuration file
6. Submit a pull request

See [Contributing Guidelines](../contributing.md) for more details. 