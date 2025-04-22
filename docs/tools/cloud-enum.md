# Cloud Enumerator

{: .no_toc }

Multi-cloud service discovery and security assessment tool.

## Table of Contents
{: .no_toc .text-delta }

1. TOC
{:toc}

## Overview

The Cloud Enumerator is a specialized tool for discovering and assessing cloud service usage across major providers (AWS, Azure, GCP). It helps identify cloud resources, potential misconfigurations, and security risks in cloud deployments.

{: .warning }
> This tool should only be used with proper authorization. Unauthorized scanning of cloud resources may violate terms of service.

## Features

### Core Capabilities

- Multi-cloud provider support
- Service discovery
- Resource enumeration
- Security configuration analysis
- Access control assessment
- Misconfiguration detection
- Detailed reporting

### Supported Providers

- Amazon Web Services (AWS)
- Microsoft Azure
- Google Cloud Platform (GCP)
- Digital Ocean
- Alibaba Cloud
- Oracle Cloud

## Installation

```bash
# Install from requirements
pip install -r requirements.txt

# Verify installation
python rfs_dns_framework.py --tool cloud-enum --help
```

### Dependencies

- Python 3.7+
- boto3
- azure-sdk
- google-cloud-sdk
- requests
- dnspython

## Usage

### Basic Usage

```bash
# Enumerate single domain
python rfs_dns_framework.py --tool cloud-enum \
  --domain example.com

# Scan specific providers
python rfs_dns_framework.py --tool cloud-enum \
  --domain example.com \
  --providers aws,azure,gcp
```

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `domain` | Target domain to enumerate | Required |
| `--providers` | Cloud providers to check | all |
| `--services` | Specific services to check | all |
| `--threads` | Number of threads | 10 |
| `--timeout` | Request timeout | 30 |
| `--output` | Output file path | None |
| `--format` | Output format (json/csv/text) | json |

### Advanced Usage

#### Service-Specific Scan
```bash
python rfs_dns_framework.py --tool cloud-enum \
  --domain example.com \
  --providers aws \
  --services s3,ec2,rds
```

#### Wordlist-Based Discovery
```bash
python rfs_dns_framework.py --tool cloud-enum \
  --domain example.com \
  --wordlist custom_words.txt \
  --mutations common
```

## Output Examples

### JSON Output
```json
{
  "status": "success",
  "tool_name": "cloud-enum",
  "findings": [
    {
      "provider": "AWS",
      "service": "S3",
      "resource": "example-bucket",
      "status": "exposed",
      "risk_level": "High",
      "details": "Public read access enabled"
    },
    {
      "provider": "Azure",
      "service": "Storage",
      "resource": "example-storage",
      "status": "secure",
      "risk_level": "Low",
      "details": "Private access only"
    }
  ]
}
```

### Discovery Report
```json
{
  "scan_summary": {
    "domain": "example.com",
    "providers_checked": ["AWS", "Azure", "GCP"],
    "resources_found": 15,
    "risk_levels": {
      "high": 2,
      "medium": 3,
      "low": 10
    }
  },
  "resources": {
    "storage": {
      "s3_buckets": ["bucket1", "bucket2"],
      "azure_blobs": ["storage1"],
      "gcp_buckets": ["bucket3"]
    },
    "compute": {
      "ec2_instances": ["i-123456"],
      "azure_vms": ["vm1"],
      "gcp_instances": ["instance1"]
    }
  }
}
```

## Service Coverage

### AWS Services
- S3 Buckets
- EC2 Instances
- RDS Databases
- Lambda Functions
- CloudFront Distributions
- ELB Load Balancers

### Azure Services
- Storage Accounts
- Virtual Machines
- App Services
- SQL Databases
- CDN Endpoints
- Key Vaults

### GCP Services
- Cloud Storage
- Compute Engine
- Cloud SQL
- Cloud Functions
- Load Balancers
- Cloud CDN

## Detection Methods

### Resource Discovery
1. DNS Analysis
   - CNAME records
   - A records
   - TXT records

2. SSL Certificates
   - Subject names
   - Alternative names
   - Issuer information

3. Service Endpoints
   - API endpoints
   - Storage URLs
   - CDN domains

## Integration

### Framework Integration
```bash
python rfs_dns_framework.py --workflow cloud-audit \
  --domain example.com \
  --output report.json
```

### Custom Integration
```python
from tools.cloud_enum import CloudEnumerator

enumerator = CloudEnumerator()
result = enumerator.run(args)
print(result.to_dict())
```

## Best Practices

### Scanning Strategy
1. **Resource Discovery**
   - Start with DNS analysis
   - Use targeted wordlists
   - Validate findings

2. **Rate Limiting**
   - Respect provider limits
   - Use appropriate delays
   - Monitor API quotas

3. **Security Assessment**
   - Check access controls
   - Validate configurations
   - Document findings

## Security Considerations

1. **Authorization**
   - Obtain permission
   - Follow provider policies
   - Document scope

2. **API Access**
   - Use read-only credentials
   - Implement least privilege
   - Rotate access keys

3. **Data Handling**
   - Secure findings
   - Encrypt sensitive data
   - Follow compliance requirements

## Troubleshooting

### Common Issues

1. **API Rate Limits**
   ```bash
   # Adjust request rate
   --delay 5
   ```

2. **Authentication**
   ```bash
   # Use custom credentials file
   --credentials creds.json
   ```

### Error Messages

| Error | Solution |
|-------|----------|
| "Access Denied" | Check credentials |
| "Rate Exceeded" | Reduce scan rate |
| "Invalid Region" | Specify region |

## References

1. [AWS Security Best Practices](https://aws.amazon.com/security/security-learning/)
2. [Azure Security Documentation](https://docs.microsoft.com/azure/security/)
3. [Google Cloud Security](https://cloud.google.com/security/)

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](../contributing.md) for details on:
- Adding provider support
- Improving detection methods
- Adding service checks
- Enhancing documentation 