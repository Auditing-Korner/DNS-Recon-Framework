# Mobile Gateway Enumerator

{: .no_toc }

Advanced mobile network gateway discovery and security assessment tool.

## Table of Contents
{: .no_toc .text-delta }

1. TOC
{:toc}

## Overview

The Mobile Gateway Enumerator is a specialized tool for discovering and analyzing mobile network gateways, including 3GPP interfaces, roaming connections, and related infrastructure. It helps identify potential security issues in mobile network configurations.

{: .warning }
> This tool should only be used with explicit authorization from network operators. Unauthorized scanning of mobile network infrastructure is illegal.

## Features

### Core Capabilities

- 3GPP gateway detection
- Protocol testing (GTP, Diameter)
- Roaming interface discovery
- Security configuration analysis
- Vulnerability assessment
- Performance testing
- Detailed reporting

### Supported Protocols

- GTP (GPRS Tunneling Protocol)
- Diameter
- MAP (Mobile Application Part)
- SCCP (Signaling Connection Control Part)
- SIGTRAN
- S1AP/X2AP

## Installation

```bash
# Install from requirements
pip install -r requirements.txt

# Verify installation
python rfs_dns_framework.py --tool mobile-gw --help
```

### Dependencies

- Python 3.7+
- scapy
- pydiameter
- pysctp
- requests
- dnspython

## Usage

### Basic Usage

```bash
# Basic gateway scan
python rfs_dns_framework.py --tool mobile-gw \
  --target 192.0.2.0/24

# Protocol-specific scan
python rfs_dns_framework.py --tool mobile-gw \
  --target example.com \
  --protocol gtp,diameter
```

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `target` | Target IP/range/domain | Required |
| `--protocol` | Protocols to test | all |
| `--port-range` | Port range to scan | standard |
| `--threads` | Number of threads | 10 |
| `--timeout` | Request timeout | 30 |
| `--output` | Output file path | None |
| `--format` | Output format (json/csv/text) | json |

### Advanced Usage

#### Protocol Testing
```bash
python rfs_dns_framework.py --tool mobile-gw \
  --target example.com \
  --protocol gtp \
  --gtp-version v1,v2
```

#### Comprehensive Scan
```bash
python rfs_dns_framework.py --tool mobile-gw \
  --target 192.0.2.0/24 \
  --check-all \
  --verbose
```

## Output Examples

### JSON Output
```json
{
  "status": "success",
  "tool_name": "mobile-gw",
  "findings": [
    {
      "host": "gw.example.com",
      "ip": "192.0.2.1",
      "protocol": "GTP",
      "version": "v2",
      "ports": [2123, 2152],
      "services": ["S11", "S5/S8"],
      "risk_level": "Medium"
    },
    {
      "host": "diameter.example.com",
      "ip": "192.0.2.2",
      "protocol": "Diameter",
      "ports": [3868],
      "applications": ["S6a", "Gx"],
      "risk_level": "Low"
    }
  ]
}
```

### Discovery Report
```json
{
  "scan_summary": {
    "target": "192.0.2.0/24",
    "protocols_checked": ["GTP", "Diameter", "SCTP"],
    "gateways_found": 5,
    "risk_levels": {
      "high": 1,
      "medium": 2,
      "low": 2
    }
  },
  "gateways": {
    "gtp": [
      {
        "ip": "192.0.2.1",
        "version": "v2",
        "interfaces": ["S11", "S5/S8"]
      }
    ],
    "diameter": [
      {
        "ip": "192.0.2.2",
        "applications": ["S6a", "Gx"]
      }
    ]
  }
}
```

## Protocol Tests

### GTP Testing
- Version detection
- Interface identification
- Security configuration
- Echo request/response
- Path management

### Diameter Testing
- Application discovery
- Capability exchange
- Authentication vectors
- AVP support
- Routing configuration

### SCCP/SIGTRAN
- Point code discovery
- SSN identification
- Route verification
- Connection testing

## Integration

### Framework Integration
```bash
python rfs_dns_framework.py --workflow mobile-audit \
  --target example.com \
  --output report.json
```

### Custom Integration
```python
from tools.mobile_gw import MobileGatewayEnum

enumerator = MobileGatewayEnum()
result = enumerator.run(args)
print(result.to_dict())
```

## Best Practices

### Scanning Strategy
1. **Network Impact**
   - Start with minimal traffic
   - Monitor network load
   - Use appropriate intervals

2. **Protocol Testing**
   - Test standard ports first
   - Validate responses
   - Document findings

3. **Security Assessment**
   - Check configurations
   - Identify vulnerabilities
   - Test security controls

## Security Considerations

1. **Authorization**
   - Obtain explicit permission
   - Document scope
   - Follow regulations

2. **Network Impact**
   - Monitor traffic levels
   - Avoid service disruption
   - Use test environments

3. **Data Protection**
   - Handle findings securely
   - Protect subscriber data
   - Follow privacy laws

## Troubleshooting

### Common Issues

1. **Connection Failures**
   ```bash
   # Increase timeout
   --timeout 60
   ```

2. **Protocol Errors**
   ```bash
   # Specify version
   --gtp-version v1
   ```

### Error Messages

| Error | Solution |
|-------|----------|
| "No response" | Check connectivity |
| "Version mismatch" | Verify protocol version |
| "Access denied" | Check permissions |

## References

1. [3GPP Specifications](https://www.3gpp.org/specifications)
2. [GSMA Guidelines](https://www.gsma.com/security/)
3. [Mobile Network Security](https://www.gsma.com/security/mobile-network-security/)

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](../contributing.md) for details on:
- Adding protocol support
- Improving detection
- Adding security checks
- Enhancing documentation 