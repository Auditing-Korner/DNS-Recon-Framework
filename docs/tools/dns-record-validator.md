# DNS Record Validator

{: .no_toc }

Comprehensive DNS record validation and security analysis tool.

## Table of Contents
{: .no_toc .text-delta }

1. TOC
{:toc}

## Overview

The DNS Record Validator is a specialized tool for validating and analyzing DNS records for security best practices, misconfigurations, and potential vulnerabilities. It performs comprehensive checks on various DNS record types and provides detailed recommendations for improvements.

{: .warning }
> This tool should be used as part of your DNS security assessment process. Some checks may require modifications to production DNS records.

## Features

### Core Capabilities

- Record syntax validation
- TTL analysis and optimization
- SPF/DMARC/DKIM validation
- Record conflicts detection
- Best practices compliance
- Security policy verification
- Comprehensive reporting

### Supported Record Types

- A/AAAA Records
- MX Records
- NS Records
- TXT Records (including SPF)
- DMARC Records
- DKIM Records
- CAA Records
- SOA Records

## Installation

```bash
# Install from requirements
pip install -r requirements.txt

# Verify installation
python rfs_dns_framework.py --tool dns-record-validator --help
```

### Dependencies

- Python 3.7+
- dnspython
- validators
- cryptography

## Usage

### Basic Usage

```bash
# Validate all records
python rfs_dns_framework.py --tool dns-record-validator \
  --domain example.com \
  --check-all

# Specific record validation
python rfs_dns_framework.py --tool dns-record-validator \
  --domain example.com \
  --check-spf \
  --check-dmarc
```

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `domain` | Target domain to validate | Required |
| `--check-spf` | Validate SPF records | False |
| `--check-dmarc` | Validate DMARC records | False |
| `--check-dkim` | Validate DKIM records | False |
| `--check-mx` | Validate MX records | False |
| `--check-ns` | Validate NS records | False |
| `--check-all` | Run all checks | False |
| `--output` | Output file path | None |
| `--format` | Output format (json/csv/text) | json |

### Advanced Usage

#### Custom TTL Analysis
```bash
python rfs_dns_framework.py --tool dns-record-validator \
  --domain example.com \
  --min-ttl 300 \
  --max-ttl 86400
```

#### Email Security Check
```bash
python rfs_dns_framework.py --tool dns-record-validator \
  --domain example.com \
  --check-spf \
  --check-dmarc \
  --check-dkim \
  --selector default
```

## Output Examples

### JSON Output
```json
{
  "status": "success",
  "tool_name": "dns-record-validator",
  "findings": [
    {
      "record_type": "SPF",
      "status": "warning",
      "description": "SPF record uses too many DNS lookups (>10)",
      "current_value": "v=spf1 include:_spf.google.com include:spf.protection.outlook.com -all",
      "recommendation": "Reduce DNS lookups or use flattened SPF record"
    },
    {
      "record_type": "DMARC",
      "status": "fail",
      "description": "Missing DMARC record",
      "recommendation": "Add DMARC record with recommended policy"
    }
  ]
}
```

### Validation Report
```json
{
  "domain": "example.com",
  "timestamp": "2024-02-20T10:30:00Z",
  "summary": {
    "total_checks": 15,
    "passed": 12,
    "warnings": 2,
    "failures": 1
  },
  "records": {
    "spf": {
      "status": "warning",
      "details": "Multiple SPF records found"
    },
    "dmarc": {
      "status": "pass",
      "policy": "reject"
    }
  }
}
```

## Validation Rules

### SPF Validation
- Maximum DNS lookups (≤10)
- Valid mechanisms
- Appropriate qualifiers
- Policy strength

### DMARC Validation
- Syntax checking
- Policy strength
- Reporting configuration
- Subdomain policy

### DKIM Validation
- Key presence
- Algorithm strength
- Key length
- Rotation schedule

### TTL Analysis
- Minimum values
- Maximum values
- Consistency
- Optimization recommendations

## Integration

### Framework Integration
```bash
python rfs_dns_framework.py --workflow dns-audit \
  --domain example.com \
  --output report.json
```

### Custom Integration
```python
from tools.dns_record_validator import DNSRecordValidator

validator = DNSRecordValidator()
result = validator.run(args)
print(result.to_dict())
```

## Best Practices

### Record Management
1. **TTL Optimization**
   - Balance between performance and update speed
   - Consider geographic distribution
   - Plan for emergency changes

2. **Email Security**
   - Implement SPF, DMARC, and DKIM
   - Regular policy reviews
   - Monitor reports

3. **Nameserver Configuration**
   - Redundancy
   - Geographic distribution
   - Regular health checks

## Troubleshooting

### Common Issues

1. **Resolution Failures**
   ```bash
   # Specify custom nameserver
   --nameserver 8.8.8.8
   ```

2. **DKIM Verification**
   ```bash
   # Specify selector
   --selector default
   ```

### Error Messages

| Error | Solution |
|-------|----------|
| "No such domain" | Verify domain name |
| "Timeout" | Check network connection |
| "SERVFAIL" | Check nameserver health |

## References

1. [RFC 7208 - SPF](https://tools.ietf.org/html/rfc7208)
2. [RFC 7489 - DMARC](https://tools.ietf.org/html/rfc7489)
3. [RFC 6376 - DKIM](https://tools.ietf.org/html/rfc6376)

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](../contributing.md) for details on:
- Adding new validation rules
- Improving checks
- Adding record types
- Enhancing documentation 