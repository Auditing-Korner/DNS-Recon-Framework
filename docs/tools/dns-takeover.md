# DNS Takeover Scanner

{: .no_toc }

Advanced subdomain takeover vulnerability scanner for cloud services and web platforms.

## Table of Contents
{: .no_toc .text-delta }

1. TOC
{:toc}

## Overview

The DNS Takeover Scanner is a specialized tool designed to identify potential subdomain takeover vulnerabilities across various cloud services and web platforms. It analyzes DNS records and service configurations to detect misconfigurations that could lead to domain hijacking.

{: .warning }
> This tool should only be used for authorized security assessments. Unauthorized testing may violate terms of service and legal regulations.

## Features

### Core Capabilities

- Multi-provider subdomain takeover detection
- Automated fingerprint matching
- DNS record analysis
- HTTP endpoint verification
- Risk assessment scoring
- Detailed vulnerability reporting

### Supported Services

- Amazon S3
- GitHub Pages
- Microsoft Azure
- AWS CloudFront
- Heroku
- Shopify
- Zendesk
- Tumblr
- Google Cloud Storage
- And many more...

## Installation

```bash
# Install from requirements
pip install -r requirements.txt

# Verify installation
python rfs_dns_framework.py --tool dns-takeover --help
```

### Dependencies

- Python 3.7+
- dnspython
- requests
- aiohttp
- aiodns

## Usage

### Basic Usage

```bash
# Scan a single domain
python rfs_dns_framework.py --tool dns-takeover \
  --domain example.com

# Scan with custom threads and timeout
python rfs_dns_framework.py --tool dns-takeover \
  --domain example.com \
  --threads 20 \
  --timeout 30
```

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `domain` | Target domain to scan | Required |
| `--threads` | Number of concurrent threads | 10 |
| `--timeout` | Request timeout in seconds | 10 |
| `--check-http` | Enable HTTP verification | True |
| `--output` | Output file path | None |
| `--format` | Output format (json/csv/text) | json |

### Advanced Usage

#### Scan Multiple Domains
```bash
python rfs_dns_framework.py --tool dns-takeover \
  --input domains.txt \
  --output results.json \
  --threads 30
```

#### Custom Service Checks
```bash
python rfs_dns_framework.py --tool dns-takeover \
  --domain example.com \
  --services "s3,azure,github" \
  --output results.json
```

## Output Examples

### JSON Output
```json
{
  "status": "success",
  "tool_name": "dns-takeover",
  "findings": [
    {
      "subdomain": "storage.example.com",
      "cname": "example.s3.amazonaws.com",
      "service": "Amazon S3",
      "vulnerable": true,
      "evidence": "NoSuchBucket: The specified bucket does not exist",
      "risk_level": "High"
    }
  ]
}
```

### Vulnerability Report
```json
{
  "scan_summary": {
    "total_subdomains": 50,
    "vulnerable_count": 2,
    "services_detected": ["Amazon S3", "GitHub Pages"],
    "risk_levels": {
      "high": 1,
      "medium": 1,
      "low": 0
    }
  },
  "vulnerabilities": [
    {
      "subdomain": "storage.example.com",
      "service": "Amazon S3",
      "risk_level": "High",
      "details": "Bucket not found - potential takeover"
    }
  ]
}
```

## Integration

### Framework Integration
```bash
# Run as part of a workflow
python rfs_dns_framework.py --workflow dns-audit \
  --domain example.com \
  --output report.json
```

### Custom Integration
```python
from tools.dns_takeover_scanner import DNSTakeoverScanner

scanner = DNSTakeoverScanner()
result = scanner.run(args)
print(result.to_dict())
```

## Detection Methods

### Service Fingerprints

The tool uses a comprehensive database of service fingerprints to identify potential takeover opportunities:

```python
TAKEOVER_FINGERPRINTS = {
    "s3": {
        "cname": [".s3.amazonaws.com"],
        "fingerprint": ["NoSuchBucket"],
        "status_code": 404
    },
    "github": {
        "cname": [".github.io"],
        "fingerprint": ["There isn't a GitHub Pages site here"],
        "status_code": 404
    }
}
```

### Verification Process

1. DNS Resolution
   - CNAME record lookup
   - A record verification
   - Service identification

2. HTTP Verification
   - Status code checking
   - Response content analysis
   - SSL certificate validation

3. Risk Assessment
   - Service criticality
   - Exploitation potential
   - Business impact

## Security Considerations

1. **Rate Limiting**: Respect service provider rate limits
2. **Authorization**: Obtain permission before testing
3. **Documentation**: Document all findings and attempts
4. **Responsible Disclosure**: Follow security disclosure policies

## Troubleshooting

### Common Issues

1. **DNS Resolution Errors**
   ```bash
   # Increase DNS timeout
   --dns-timeout 5
   ```

2. **HTTP Timeouts**
   ```bash
   # Adjust request timeout
   --timeout 30
   ```

3. **Rate Limiting**
   ```bash
   # Reduce concurrent threads
   --threads 5
   ```

### Error Messages

| Error | Solution |
|-------|----------|
| "DNS resolution failed" | Check network/DNS settings |
| "Connection timeout" | Increase timeout value |
| "Too many requests" | Reduce thread count |

## Best Practices

1. **Scanning Strategy**
   - Start with low thread counts
   - Gradually increase based on results
   - Monitor for rate limiting

2. **Result Verification**
   - Manually verify high-risk findings
   - Document false positives
   - Update fingerprint database

3. **Reporting**
   - Include evidence for findings
   - Provide remediation steps
   - Prioritize by risk level

## References

1. [OWASP Subdomain Takeover](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover)
2. [HackerOne Subdomain Takeover Report](https://www.hackerone.com/application-security/guide-subdomain-takeovers)
3. [Cloud Provider Security Best Practices](https://cloud.google.com/security/best-practices)

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](../contributing.md) for details on:
- Adding new service fingerprints
- Improving detection methods
- Fixing bugs
- Enhancing documentation 