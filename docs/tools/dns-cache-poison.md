# DNS Cache Poisoning Tool

{: .no_toc }

Advanced DNS cache poisoning detection and testing tool for security researchers.

## Table of Contents
{: .no_toc .text-delta }

1. TOC
{:toc}

## Overview

The DNS Cache Poisoning Tool is designed to detect and test vulnerabilities in DNS server implementations that could lead to cache poisoning attacks. It provides both detection and simulation capabilities for authorized security testing.

{: .warning }
> This tool should only be used for authorized security testing. Unauthorized DNS cache poisoning attempts are illegal and can disrupt network operations.

## Features

### Core Capabilities

- Transaction ID prediction testing
- Source port randomization analysis
- Protocol-level manipulation
- Multiple attack mode support
- Detailed vulnerability reporting
- Multi-threaded testing

### Detection Methods

- Source port entropy analysis
- Transaction ID randomization testing
- Response race condition testing
- DNSSEC validation checking
- Birthday attack simulation

## Installation

```bash
# Install from requirements
pip install -r requirements.txt

# Verify installation
python rfs_dns_framework.py --tool dns-cache-poison --help
```

### Dependencies

- Python 3.7+
- Scapy
- dnspython
- cryptography

## Usage

### Basic Usage

```bash
# Detection mode
python rfs_dns_framework.py --tool dns-cache-poison \
  --domain example.com \
  --nameserver 8.8.8.8 \
  --mode detect

# Full testing mode
python rfs_dns_framework.py --tool dns-cache-poison \
  --domain example.com \
  --nameserver 8.8.8.8 \
  --spoofed-ip 192.168.1.1 \
  --mode both
```

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `domain` | Target domain to test | Required |
| `nameserver` | DNS server to test | Required |
| `spoofed-ip` | IP address to inject | Required for poison mode |
| `--mode` | Operation mode (detect/poison/both) | detect |
| `--record-type` | DNS record type to test | A |
| `--duration` | Test duration in seconds | 30 |
| `--max-attempts` | Maximum number of attempts | 1000 |
| `--threads` | Number of parallel threads | 10 |

### Operation Modes

#### Detection Mode
Analyzes DNS server for potential vulnerabilities:
```bash
python rfs_dns_framework.py --tool dns-cache-poison \
  --domain example.com \
  --nameserver 8.8.8.8 \
  --mode detect
```

#### Poisoning Mode
Attempts cache poisoning (requires authorization):
```bash
python rfs_dns_framework.py --tool dns-cache-poison \
  --domain example.com \
  --nameserver 8.8.8.8 \
  --spoofed-ip 192.168.1.1 \
  --mode poison
```

#### Combined Mode
Performs both detection and poisoning tests:
```bash
python rfs_dns_framework.py --tool dns-cache-poison \
  --domain example.com \
  --nameserver 8.8.8.8 \
  --spoofed-ip 192.168.1.1 \
  --mode both
```

## Output Examples

### Detection Results
```json
{
  "status": "success",
  "tool_name": "dns-cache-poison",
  "findings": [
    {
      "title": "Weak Source Port Randomization",
      "description": "DNS server uses predictable source ports",
      "risk_level": "High",
      "evidence": "Only 100 unique ports observed in 1000 queries"
    }
  ]
}
```

### Vulnerability Report
```json
{
  "vulnerability_checks": [
    {
      "check": "source_port_randomization",
      "vulnerable": true,
      "details": "Unique ports observed: 100/1000",
      "risk_level": "High"
    },
    {
      "check": "txid_randomization",
      "vulnerable": false,
      "details": "Good entropy in transaction IDs",
      "risk_level": "Low"
    }
  ]
}
```

## Integration

### Framework Integration
The tool fully integrates with the RFS DNS Framework:
```bash
python rfs_dns_framework.py --workflow \
  --domain example.com \
  --output results.json
```

### Custom Integration
```python
from tools.dns_cache_poison import DNSCachePoisonScanner

scanner = DNSCachePoisonScanner()
result = scanner.run(args)
print(result.to_dict())
```

## Security Considerations

1. **Authorization**: Always obtain explicit permission before testing.
2. **Impact**: Cache poisoning attempts can affect production services.
3. **Monitoring**: Ensure proper logging and monitoring during tests.
4. **Cleanup**: Verify DNS cache is cleared after testing.

## Troubleshooting

### Common Issues

1. **Permission Errors**
   ```bash
   sudo python3 rfs_dns_framework.py --tool dns-cache-poison ...
   ```

2. **Scapy Import Error**
   ```bash
   pip install --upgrade scapy
   ```

3. **Connection Timeouts**
   ```bash
   # Increase timeout
   --timeout 10
   ```

### Error Messages

| Error | Solution |
|-------|----------|
| "Permission denied" | Run with sudo/root |
| "No route to host" | Check network connectivity |
| "DNS query failed" | Verify nameserver address |

## References

1. [DNS Cache Poisoning - MITRE ATT&CK](https://attack.mitre.org/techniques/T1584/)
2. [RFC 5452 - Measures for Making DNS More Resilient against Forged Answers](https://tools.ietf.org/html/rfc5452)
3. [DNSSEC Protection](https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en)

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](../contributing.md) for details. 