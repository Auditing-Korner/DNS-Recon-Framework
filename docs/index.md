# RFS DNS Framework

A comprehensive DNS security testing and analysis framework designed for security researchers and penetration testers.

{: .warning }
> This framework is for educational and authorized testing purposes only. Unauthorized testing of DNS infrastructure may be illegal in your jurisdiction.

## Overview

The RFS DNS Framework provides a suite of specialized tools for DNS security testing, reconnaissance, and vulnerability analysis. Built with modern security challenges in mind, it offers:

- 🔍 Advanced vulnerability detection
- 🚀 High-performance parallel processing
- 📊 Comprehensive reporting
- 🛡️ Multiple security checks
- 📝 Detailed logging
- 🔄 Support for various DNS record types

## Core Tools

### DNS Cache Poisoning Tool
Advanced detection and simulation of DNS cache poisoning vulnerabilities. Features include:
- Transaction ID and source port prediction testing
- Protocol-level manipulation capabilities
- Multiple attack mode support
- Detailed vulnerability reporting

[Learn more →](tools/dns-cache-poison){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 }

### DNS Record Validator
Comprehensive DNS record validation and security analysis:
- Record syntax validation
- TTL analysis
- SPF/DMARC/DKIM validation
- Record conflicts detection
- Best practices compliance checks

[Learn more →](tools/dns-record-validator){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 }

### DNS Takeover Scanner
Identifies potential subdomain takeover vulnerabilities:
- Multi-provider support (AWS, Azure, GitHub, etc.)
- Automated vulnerability verification
- Detailed risk assessment
- Remediation guidance

[Learn more →](tools/dns-takeover-scanner){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 }

### SSL Scanner
Comprehensive SSL/TLS security analysis:
- Certificate validation
- Protocol support checking
- Cipher suite analysis
- Known vulnerability detection
- Security header verification

[Learn more →](tools/ssl-scanner){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 }

### Seizure Detector
Detects potential law enforcement domain seizures:
- WHOIS change detection
- DNS record analysis
- HTTP evidence collection
- Multi-agency signature support

[Learn more →](tools/seizure-detector){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 }

## Additional Tools

### Cloud Enumerator
- Detects cloud service usage
- Provider identification
- Resource enumeration
- Security configuration analysis

### TLD Bruteforcer
- Multi-threaded TLD discovery
- Custom wordlist support
- Pattern-based scanning
- Result validation

### Mobile Gateway Enum
- 3GPP gateway detection
- Protocol testing (GTP, Diameter)
- Vulnerability scanning
- Multi-threaded analysis

## Quick Start

```bash
# Install the framework
git clone https://github.com/rfs85/RFS-DNS-Framework.git
cd RFS-DNS-Framework
pip install -r requirements.txt

# Run a basic DNS security scan
python rfs_dns_framework.py --domain example.com --workflow
```

## Framework Integration

All tools support seamless integration with the main framework:
- Standardized argument parsing
- Consistent output formatting
- Unified reporting
- Workflow automation

```bash
# Run individual tools with framework integration
python rfs_dns_framework.py --tool dns-cache-poison --domain example.com
python rfs_dns_framework.py --tool ssl-scanner --domain example.com
```

## Documentation Sections

- [Installation Guide](installation.md) - Detailed setup instructions
- [Usage Guide](usage.md) - Tool usage examples and workflows
- [API Reference](api/) - Framework API documentation
- [Contributing](contributing.md) - Guidelines for contributors
- [Security Policy](security.md) - Security considerations and reporting

## Project Status

This project is actively maintained and regularly updated with new features and security improvements. Check our [GitHub repository](https://github.com/rfs85/RFS-DNS-Framework) for the latest updates.

## License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/rfs85/RFS-DNS-Framework/blob/main/LICENSE) file for details. 