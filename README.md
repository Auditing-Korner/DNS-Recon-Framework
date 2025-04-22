# RFS DNS Framework

Comprehensive DNS Security Testing Framework

## Overview -

RFS DNS Framework is a comprehensive security testing framework focused on DNS infrastructure. It provides a collection of tools for DNS enumeration, vulnerability assessment, and security testing, all integrated into a single cohesive framework.

## Key Features

### Core Functionality
- **Modular Architecture**: Multiple specialized tools integrated into one framework
- **Comprehensive DNS Enumeration**: Discover subdomains, DNS records, and infrastructure
- **Vulnerability Detection**: Identify common DNS security issues
- **Reporting**: Generate comprehensive HTML and JSON reports

### Security Testing Tools
- **DNS Zone Walking**: DNSSEC zone enumeration using NSEC/NSEC3 records
- **DNS Tunneling Detection**: Identify data exfiltration through DNS tunneling
- **Cache Poisoning Detection**: Test for DNS cache poisoning vulnerabilities
- **SSL/TLS Security**: Analyze SSL/TLS configurations and vulnerabilities

### Infrastructure Analysis
- **Cloud Provider Detection**: Identify usage of cloud services
- **Mobile Gateway Detection**: Scan for 3GPP mobile network gateways
- **Subdomain Takeover**: Identify vulnerable subdomains
- **Domain Seizure Detection**: Identify law enforcement domain seizures

## Installation

### Requirements

- Python 3.7+
- Required Python packages (see requirements.txt)
- Root/Administrator privileges (for certain tools)

### Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/rfs85/RFS-DNS-Framework.git
   cd RFS-DNS-Framework
   ```

2. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/macOS
   # or
   .\venv\Scripts\activate  # Windows
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Framework Commands

List available tools:
```bash
python rfs_dns_framework.py --list-tools
```

Run a specific tool:
```bash
python rfs_dns_framework.py --tool <tool_name> [options]
```

Run complete workflow:
```bash
python rfs_dns_framework.py --workflow --domain example.com --output-dir results
```

### Tool-Specific Examples

#### DNS Zone Walking
```bash
# Walk DNSSEC zones using NSEC/NSEC3 records
python rfs_dns_framework.py --tool zone_walker example.com

# Disable NSEC3 walking
python rfs_dns_framework.py --tool zone_walker example.com --no-nsec3
```

#### DNS Tunneling Detection
```bash
# Analyze PCAP file for tunneling
python rfs_dns_framework.py --tool tunnel_detector --pcap capture.pcap

# Analyze single query
python rfs_dns_framework.py --tool tunnel_detector --query suspicious.example.com
```

#### DNS Enumeration
```bash
# Basic enumeration
python rfs_dns_framework.py --tool dns_enum example.com

# With custom wordlist
python rfs_dns_framework.py --tool dns_enum example.com --wordlist custom_wordlist.txt
```

#### SSL/TLS Scanner
```bash
# Basic SSL scan
python rfs_dns_framework.py --tool ssl_scanner example.com

# Scan specific ports
python rfs_dns_framework.py --tool ssl_scanner example.com --ports 443,8443
```

## Available Tools

| Tool Name | Description | Root Required |
|-----------|-------------|---------------|
| zone_walker | DNSSEC Zone Walking and NSEC/NSEC3 Analysis | No |
| tunnel_detector | Detect DNS Tunneling and Data Exfiltration | Yes |
| dns_enum | Comprehensive DNS enumeration and analysis | No |
| find_server | Discover and test DNS servers | No |
| cloud_enum | Detect and analyze cloud service providers | No |
| tld_brute | Multi-threaded TLD discovery | No |
| takeover | Identify subdomain takeover vulnerabilities | No |
| seizure | Identify law enforcement domain seizures | No |
| mobile_gw | Enumerate 3GPP Mobile Gateways | No |
| cache_poison | DNS cache poisoning detection | Yes |
| ssl_scanner | SSL/TLS security scanner | No |
| dns_takeover | DNS subdomain takeover vulnerability scanner | No |
| privacy_scanner | DNS Privacy, DoH, DoT, and DNSCrypt Testing | No |
| config_auditor | DNS Configuration and Security Best Practices Analysis | No |

## Configuration

The framework's behavior can be customized through the `config.yaml` file:

- DNS settings (resolvers, timeouts, etc.)
- Tool-specific configurations
- Reporting preferences
- Logging settings

See [Configuration Guide](docs/configuration.md) for details.

## Documentation

- [Installation Guide](docs/installation.md)
- [Usage Guide](docs/usage.md)
- [Tool Documentation](docs/tools/index.md)
- [API Reference](docs/api/index.md)
- [Security Considerations](docs/security.md)

## Security Notice

⚠️ **Important**: This framework is for educational and authorized testing purposes only. Unauthorized testing of DNS infrastructure may be illegal in your jurisdiction.

## License

Copyright (c) 2024 rfs85. See [LICENSE](LICENSE) for details.

## Author

- rfs85
- GitHub: https://github.com/rfs85/RFS-DNS-Framework