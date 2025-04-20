# RFS DNS Framework

Comprehensive DNS Security Testing Framework

## Overview

RFS DNS Framework is a comprehensive security testing framework focused on DNS infrastructure. It provides a collection of tools for DNS enumeration, vulnerability assessment, and security testing, all integrated into a single cohesive framework.

## Features

- **Modular Architecture**: Multiple specialized tools integrated into one framework
- **Comprehensive DNS Enumeration**: Discover subdomains, DNS records, and infrastructure
- **Vulnerability Detection**: Identify common DNS security issues
- **Cloud Provider Detection**: Identify usage of cloud services
- **Mobile Gateway Detection**: Scan for 3GPP mobile network gateways
- **SSL/TLS Security Scanning**: Analyze SSL/TLS configurations for vulnerabilities
- **Subdomain Takeover Detection**: Identify vulnerable subdomains
- **Reporting**: Generate comprehensive HTML and JSON reports

## Installation

### Requirements

- Python 3.7+
- Required Python packages (see requirements.txt)

### Setup

1. Clone the repository:
   ```
   git clone https://github.com/rfs85/RFS-DNS-Framework.git
   cd RFS-DNS-Framework
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

### Basic Usage

Run the framework's help command to see all available options:

```
python rfs_dns_framework.py --help
```

### List Available Tools

```
python rfs_dns_framework.py --list-tools
```

### Running a Specific Tool

Example running the DNS enumeration tool:

```
python rfs_dns_framework.py --tool dns_enum example.com
```

### Running a Full Workflow

```
python rfs_dns_framework.py --workflow --domain example.com --output-dir results
```

### Tool-Specific Examples

#### DNS Enumeration

```
python rfs_dns_framework.py --tool dns_enum example.com
```

#### Mobile Gateway Enumeration

Scan a specific IP or range for mobile gateways:

```
python rfs_dns_framework.py --tool mobile_gw 10.0.0.1
```

Scan for a specific gateway type:

```
python rfs_dns_framework.py --tool mobile_gw 10.0.0.0/24 --gateway-type P-GW
```

#### SSL/TLS Scanner

Scan domain for SSL/TLS vulnerabilities:

```
python rfs_dns_framework.py --tool ssl_scanner example.com
```

Scan specific ports:

```
python rfs_dns_framework.py --tool ssl_scanner example.com --ports 443,8443
```

#### DNS Takeover Scanner

Scan for subdomain takeover vulnerabilities:

```
python rfs_dns_framework.py --tool dns_takeover example.com
```

Provide a list of subdomains to check:

```
python rfs_dns_framework.py --tool dns_takeover example.com --subdomains subdomains.txt
```

## Configuration

The framework behavior can be customized through the `config.yaml` file. This file controls various aspects of the tools, including:

- DNS settings (resolvers, query timeouts, etc.)
- Tool-specific configurations
- Reporting preferences
- Logging settings

## Available Tools

| Tool Name | Description |
|-----------|-------------|
| dns_enum | Comprehensive DNS enumeration and analysis |
| find_server | Discover and test DNS servers |
| cloud_enum | Detect and analyze cloud service providers |
| tld_brute | Multi-threaded TLD discovery |
| takeover | Identify subdomain takeover vulnerabilities |
| seizure | Identify law enforcement domain seizures |
| mobile_gw | Enumerate 3GPP Mobile Gateways |
| cache_poison | DNS cache poisoning detection |
| ssl_scanner | SSL/TLS security scanner |
| dns_takeover | DNS subdomain takeover vulnerability scanner |

## License

Copyright (c) 2023 rfs85

## Author

- rfs85
- GitHub: https://github.com/rfs85/RFS-DNS-Framework