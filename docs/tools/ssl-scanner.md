# SSL Scanner

{: .no_toc }

Comprehensive SSL/TLS security analysis tool.

## Table of Contents
{: .no_toc .text-delta }

1. TOC
{:toc}

## Overview

The SSL Scanner is a specialized tool for analyzing SSL/TLS configurations, certificates, and security headers. It helps identify vulnerabilities, misconfigurations, and deviations from security best practices in HTTPS implementations.

{: .warning }
> This tool should be used responsibly as part of authorized security assessments. Some tests may trigger security alerts.

## Features

### Core Capabilities

- Certificate validation
- Protocol support detection
- Cipher suite analysis
- Security header verification
- Known vulnerability testing
- Configuration assessment
- Detailed reporting

### Security Checks

- Certificate chain validation
- Protocol version detection
- Cipher strength analysis
- Perfect Forward Secrecy
- HSTS implementation
- CAA record verification
- Known vulnerability tests

## Installation

```bash
# Install from requirements
pip install -r requirements.txt

# Verify installation
python rfs_dns_framework.py --tool ssl-scanner --help
```

### Dependencies

- Python 3.7+
- cryptography
- pyOpenSSL
- requests
- sslyze

## Usage

### Basic Usage

```bash
# Basic SSL scan
python rfs_dns_framework.py --tool ssl-scanner \
  --domain example.com

# Comprehensive security scan
python rfs_dns_framework.py --tool ssl-scanner \
  --domain example.com \
  --check-all
```

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `domain` | Target domain to scan | Required |
| `--port` | Target port | 443 |
| `--check-cert` | Validate certificate | True |
| `--check-proto` | Check protocols | True |
| `--check-ciphers` | Analyze ciphers | True |
| `--check-vulns` | Test vulnerabilities | False |
| `--check-all` | Run all checks | False |
| `--timeout` | Connection timeout | 30 |
| `--output` | Output file path | None |
| `--format` | Output format (json/csv/text) | json |

### Advanced Usage

#### Custom Port Scan
```bash
python rfs_dns_framework.py --tool ssl-scanner \
  --domain example.com \
  --port 8443 \
  --check-all
```

#### Vulnerability Focus
```bash
python rfs_dns_framework.py --tool ssl-scanner \
  --domain example.com \
  --check-vulns \
  --include-known-vulns
```

## Output Examples

### JSON Output
```json
{
  "status": "success",
  "tool_name": "ssl-scanner",
  "findings": [
    {
      "category": "protocol",
      "status": "warning",
      "description": "TLS 1.0 supported",
      "risk_level": "Medium",
      "recommendation": "Disable TLS 1.0 support"
    },
    {
      "category": "cipher",
      "status": "fail",
      "description": "Weak cipher (RC4) supported",
      "risk_level": "High",
      "recommendation": "Remove RC4 cipher support"
    }
  ]
}
```

### Security Report
```json
{
  "scan_summary": {
    "hostname": "example.com",
    "ip_address": "93.184.216.34",
    "port": 443,
    "scan_time": "2024-02-20T10:30:00Z",
    "grade": "B"
  },
  "certificate": {
    "subject": "CN=example.com",
    "issuer": "C=US, O=Let's Encrypt, CN=R3",
    "valid_from": "2024-01-01",
    "valid_until": "2024-03-31",
    "key_size": 2048,
    "signature_algorithm": "sha256WithRSAEncryption"
  },
  "protocols": {
    "ssl2": false,
    "ssl3": false,
    "tls1_0": true,
    "tls1_1": true,
    "tls1_2": true,
    "tls1_3": true
  }
}
```

## Security Tests

### Certificate Analysis
- Chain validation
- Hostname verification
- Expiration checking
- Key strength
- Algorithm security
- SAN validation

### Protocol Testing
- Version support
- Configuration security
- Downgrade protection
- Renegotiation support

### Cipher Analysis
- Strength assessment
- Forward secrecy
- Key exchange methods
- MAC algorithms

### Vulnerability Checks
- Heartbleed
- POODLE
- ROBOT
- BEAST
- CRIME
- BREACH
- Sweet32

## Integration

### Framework Integration
```bash
python rfs_dns_framework.py --workflow security-audit \
  --domain example.com \
  --output report.json
```

### Custom Integration
```python
from tools.ssl_scanner import SSLScanner

scanner = SSLScanner()
result = scanner.run(args)
print(result.to_dict())
```

## Best Practices

### Configuration Guidelines
1. **Protocol Support**
   - Enable TLS 1.2 and 1.3
   - Disable SSL 2.0 and 3.0
   - Consider TLS 1.0/1.1 requirements

2. **Cipher Selection**
   - Prefer strong ciphers
   - Enable Perfect Forward Secrecy
   - Remove weak algorithms

3. **Certificate Management**
   - Regular rotation
   - Strong key sizes
   - Proper chain configuration

## Security Considerations

1. **Testing Impact**
   - Monitor server load
   - Test during low traffic
   - Respect rate limits

2. **Findings Handling**
   - Secure sensitive data
   - Follow disclosure policies
   - Document all issues

## Troubleshooting

### Common Issues

1. **Connection Errors**
   ```bash
   # Increase timeout
   --timeout 60
   ```

2. **Certificate Chain**
   ```bash
   # Include intermediate certificates
   --include-chain
   ```

### Error Messages

| Error | Solution |
|-------|----------|
| "Connection refused" | Check firewall rules |
| "Certificate error" | Verify trust chain |
| "Timeout" | Increase timeout value |

## References

1. [SSL/TLS Best Practices](https://www.ssllabs.com/downloads/SSL_TLS_Deployment_Best_Practices.pdf)
2. [NIST SP 800-52](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf)
3. [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](../contributing.md) for details on:
- Adding new checks
- Improving analysis
- Adding vulnerability tests
- Enhancing documentation 