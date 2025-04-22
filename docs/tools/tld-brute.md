# TLD Bruteforcer

{: .no_toc }

Advanced Top-Level Domain discovery and enumeration tool.

## Table of Contents
{: .no_toc .text-delta }

1. TOC
{:toc}

## Overview

The TLD Bruteforcer is a specialized tool for discovering registered domain names across different Top-Level Domains (TLDs). It helps identify domain variations, typosquatting attempts, and brand protection issues through comprehensive TLD enumeration.

{: .warning }
> This tool should be used responsibly. Aggressive scanning may trigger rate limits from domain registrars.

## Features

### Core Capabilities

- Multi-threaded TLD scanning
- Custom wordlist support
- Pattern-based scanning
- Result validation
- WHOIS integration
- DNS verification
- Detailed reporting

### Detection Methods

- TLD enumeration
- DNS resolution
- WHOIS validation
- Pattern matching
- Typo detection
- Homograph detection

## Installation

```bash
# Install from requirements
pip install -r requirements.txt

# Verify installation
python rfs_dns_framework.py --tool tld-brute --help
```

### Dependencies

- Python 3.7+
- dnspython
- whois
- requests
- tldextract

## Usage

### Basic Usage

```bash
# Basic TLD scan
python rfs_dns_framework.py --tool tld-brute \
  --domain example

# Custom TLD list
python rfs_dns_framework.py --tool tld-brute \
  --domain example \
  --tld-list custom_tlds.txt
```

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `domain` | Base domain to check | Required |
| `--tld-list` | Custom TLD list file | built-in |
| `--threads` | Number of threads | 10 |
| `--timeout` | Request timeout | 30 |
| `--verify-dns` | Verify with DNS | True |
| `--check-whois` | Check WHOIS | False |
| `--output` | Output file path | None |
| `--format` | Output format (json/csv/text) | json |

### Advanced Usage

#### Pattern-Based Scan
```bash
python rfs_dns_framework.py --tool tld-brute \
  --domain example \
  --patterns typo,homograph \
  --output results.json
```

#### Comprehensive Check
```bash
python rfs_dns_framework.py --tool tld-brute \
  --domain example \
  --check-all \
  --verify-dns \
  --check-whois
```

## Output Examples

### JSON Output
```json
{
  "status": "success",
  "tool_name": "tld-brute",
  "findings": [
    {
      "domain": "example.com",
      "status": "registered",
      "dns_records": true,
      "creation_date": "1995-08-14",
      "registrar": "Example Registrar"
    },
    {
      "domain": "example.net",
      "status": "registered",
      "dns_records": true,
      "creation_date": "1995-08-14",
      "registrar": "Another Registrar"
    }
  ]
}
```

### Discovery Report
```json
{
  "scan_summary": {
    "base_domain": "example",
    "tlds_checked": 100,
    "domains_found": 5,
    "scan_time": "2024-02-20T10:30:00Z"
  },
  "domains": {
    "registered": [
      {
        "domain": "example.com",
        "registrar": "Example Registrar",
        "nameservers": ["ns1.example.com", "ns2.example.com"]
      }
    ],
    "available": [
      "example.xyz",
      "example.info"
    ]
  }
}
```

## Detection Methods

### TLD Discovery
1. Common TLDs
   - gTLDs (.com, .net, .org)
   - ccTLDs (.us, .uk, .de)
   - New gTLDs (.app, .dev, .web)

2. Pattern Matching
   - Typosquatting
   - Homographs
   - Brand variations

3. Validation
   - DNS resolution
   - WHOIS lookup
   - HTTP response

## Integration

### Framework Integration
```bash
python rfs_dns_framework.py --workflow domain-audit \
  --domain example \
  --output report.json
```

### Custom Integration
```python
from tools.tld_brute import TLDBruteforcer

bruteforcer = TLDBruteforcer()
result = bruteforcer.run(args)
print(result.to_dict())
```

## TLD Lists

### Built-in Lists
- Common TLDs (50+)
- Country Code TLDs (240+)
- New gTLDs (1000+)
- Brand TLDs

### Custom Lists
```text
# custom_tlds.txt
com
net
org
io
app
dev
```

## Best Practices

### Scanning Strategy
1. **Rate Limiting**
   - Start with low threads
   - Use appropriate delays
   - Monitor responses

2. **Validation**
   - Verify findings
   - Check DNS records
   - Validate WHOIS data

3. **Documentation**
   - Record all findings
   - Track changes
   - Document patterns

## Security Considerations

1. **Rate Limits**
   - Respect registrar limits
   - Use distributed scanning
   - Implement backoff

2. **Data Handling**
   - Secure findings
   - Follow privacy rules
   - Handle PII appropriately

3. **Legal Compliance**
   - Check local laws
   - Respect WHOIS privacy
   - Follow terms of service

## Troubleshooting

### Common Issues

1. **Rate Limiting**
   ```bash
   # Adjust scan rate
   --delay 5
   ```

2. **WHOIS Failures**
   ```bash
   # Use alternative server
   --whois-server whois.example.com
   ```

### Error Messages

| Error | Solution |
|-------|----------|
| "WHOIS blocked" | Increase delay |
| "DNS timeout" | Check resolver |
| "Connection error" | Verify network |

## References

1. [ICANN TLD List](https://www.icann.org/resources/pages/tlds-2012-02-25-en)
2. [Domain Name System Structure](https://www.iana.org/domains/root/db)
3. [New gTLD Program](https://newgtlds.icann.org/en/program-status/statistics)

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](../contributing.md) for details on:
- Adding TLD lists
- Improving detection
- Adding validation methods
- Enhancing documentation 