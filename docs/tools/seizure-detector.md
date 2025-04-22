# Seizure Detector

{: .no_toc }

Advanced domain seizure detection and analysis tool.

## Table of Contents
{: .no_toc .text-delta }

1. TOC
{:toc}

## Overview

The Seizure Detector is a specialized tool for identifying potential law enforcement domain seizures and related indicators. It analyzes various data points including WHOIS changes, DNS records, and HTTP evidence to detect signs of domain seizures.

{: .warning }
> This tool is for informational and research purposes only. Always verify findings through official channels.

## Features

### Core Capabilities

- WHOIS change detection
- DNS record analysis
- HTTP evidence collection
- Multi-agency signature support
- Historical data comparison
- Risk assessment
- Detailed reporting

### Detection Methods

- WHOIS record analysis
- DNS record monitoring
- HTTP response analysis
- SSL certificate changes
- Agency signature matching
- Historical comparison

## Installation

```bash
# Install from requirements
pip install -r requirements.txt

# Verify installation
python rfs_dns_framework.py --tool seizure-detector --help
```

### Dependencies

- Python 3.7+
- whois
- requests
- dnspython
- beautifulsoup4

## Usage

### Basic Usage

```bash
# Check single domain
python rfs_dns_framework.py --tool seizure-detector \
  --domain example.com

# Check multiple domains
python rfs_dns_framework.py --tool seizure-detector \
  --input domains.txt
```

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `domain` | Target domain to check | Required |
| `--input` | Input file with domains | None |
| `--check-whois` | Check WHOIS changes | True |
| `--check-dns` | Check DNS changes | True |
| `--check-http` | Check HTTP evidence | True |
| `--threads` | Number of threads | 10 |
| `--timeout` | Request timeout | 30 |
| `--output` | Output file path | None |
| `--format` | Output format (json/csv/text) | json |

### Advanced Usage

#### Historical Analysis
```bash
python rfs_dns_framework.py --tool seizure-detector \
  --domain example.com \
  --historical \
  --days 30
```

#### Custom Agency Signatures
```bash
python rfs_dns_framework.py --tool seizure-detector \
  --domain example.com \
  --signatures custom_signatures.json
```

## Output Examples

### JSON Output
```json
{
  "status": "success",
  "tool_name": "seizure-detector",
  "findings": [
    {
      "domain": "example.com",
      "seized": true,
      "confidence": "high",
      "evidence": {
        "whois_changes": true,
        "dns_changes": true,
        "http_evidence": true
      },
      "agency": "FBI",
      "timestamp": "2024-02-20T10:30:00Z"
    }
  ]
}
```

### Analysis Report
```json
{
  "domain": "example.com",
  "scan_time": "2024-02-20T10:30:00Z",
  "status": {
    "seized": true,
    "confidence": 0.95,
    "risk_level": "High"
  },
  "evidence": {
    "whois": {
      "registrar_changed": true,
      "nameservers_changed": true,
      "last_update": "2024-02-19"
    },
    "dns": {
      "a_record_changed": true,
      "new_ip": "192.0.2.1"
    },
    "http": {
      "seizure_notice": true,
      "agency_logos": ["fbi", "doj"]
    }
  }
}
```

## Detection Methods

### WHOIS Analysis
- Registrar changes
- Nameserver changes
- Contact information
- Update timestamps
- Historical comparison

### DNS Monitoring
- A record changes
- NS record changes
- MX record changes
- TXT record analysis
- SOA serial tracking

### HTTP Evidence
- Response codes
- Page content
- Agency logos
- SSL certificates
- Server headers

## Integration

### Framework Integration
```bash
python rfs_dns_framework.py --workflow domain-audit \
  --domain example.com \
  --output report.json
```

### Custom Integration
```python
from tools.seizure_detector import SeizureDetector

detector = SeizureDetector()
result = detector.run(args)
print(result.to_dict())
```

## Agency Signatures

### Supported Agencies
- FBI (Federal Bureau of Investigation)
- DOJ (Department of Justice)
- ICE (Immigration and Customs Enforcement)
- EUROPOL (European Union Agency for Law Enforcement)
- INTERPOL (International Criminal Police Organization)

### Custom Signatures
```json
{
  "agency_name": {
    "whois_patterns": ["pattern1", "pattern2"],
    "dns_patterns": ["pattern1", "pattern2"],
    "http_patterns": ["pattern1", "pattern2"],
    "confidence_threshold": 0.8
  }
}
```

## Best Practices

### Analysis Strategy
1. **Data Collection**
   - Gather historical data
   - Monitor changes over time
   - Document evidence

2. **Verification**
   - Cross-reference findings
   - Check multiple sources
   - Validate signatures

3. **Reporting**
   - Include all evidence
   - Rate confidence levels
   - Document timeline

## Security Considerations

1. **Data Handling**
   - Secure sensitive information
   - Follow privacy policies
   - Document chain of custody

2. **False Positives**
   - Verify findings manually
   - Consider legitimate changes
   - Document uncertainty

## Troubleshooting

### Common Issues

1. **WHOIS Access**
   ```bash
   # Use alternative WHOIS server
   --whois-server whois.example.com
   ```

2. **Rate Limiting**
   ```bash
   # Adjust query delay
   --delay 5
   ```

### Error Messages

| Error | Solution |
|-------|----------|
| "WHOIS error" | Check server access |
| "DNS timeout" | Increase timeout |
| "HTTP 429" | Reduce request rate |

## References

1. [Domain Seizure Process](https://www.justice.gov/archives/jm/criminal-resource-manual-2851-domain-name-seizures)
2. [ICANN Domain Security](https://www.icann.org/resources/pages/security-2012-02-25-en)
3. [Domain Takedown Guidelines](https://www.europol.europa.eu/publications-events/publications/domain-takedown-guidelines)

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](../contributing.md) for details on:
- Adding agency signatures
- Improving detection methods
- Adding new evidence types
- Enhancing documentation 