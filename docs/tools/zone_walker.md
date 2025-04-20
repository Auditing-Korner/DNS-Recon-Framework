# DNS Zone Walker

The DNS Zone Walker is a specialized tool for enumerating DNS zones using DNSSEC NSEC and NSEC3 records. It provides comprehensive zone analysis capabilities including zone transfers, NSEC/NSEC3 chain walking, and NSEC3 hash cracking.

## Features

- DNSSEC status verification
- Zone transfer attempts (AXFR/IXFR)
- NSEC record chain walking
- NSEC3 record chain walking and hash cracking
- Chain completeness verification
- Detailed reporting of findings

## Usage

### Basic Usage

```bash
# Basic zone walking with all features enabled
python rfs_dns_framework.py --tool zone_walker example.com

# Disable NSEC3 walking
python rfs_dns_framework.py --tool zone_walker example.com --no-nsec3

# Disable zone transfer attempts
python rfs_dns_framework.py --tool zone_walker example.com --no-zone-transfer

# Specify custom wordlist for NSEC3 cracking
python rfs_dns_framework.py --tool zone_walker example.com --wordlist custom_wordlist.txt
```

### Advanced Options

```bash
# Adjust thread count for parallel operations
python rfs_dns_framework.py --tool zone_walker example.com --threads 20

# Set custom timeout
python rfs_dns_framework.py --tool zone_walker example.com --timeout 10

# Output results to specific file
python rfs_dns_framework.py --tool zone_walker example.com --output results.json
```

## Configuration

The tool's behavior can be customized in `config.yaml`:

```yaml
zone_walker:
  # Enable NSEC/NSEC3 walking
  enable_nsec_walk: true
  enable_nsec3_walk: true
  
  # NSEC3 cracking settings
  nsec3_cracking:
    enabled: true
    wordlist: "data/nsec3_wordlist.txt"
    max_iterations: 1000
    
  # Zone transfer settings
  zone_transfer:
    attempt_axfr: true
    attempt_ixfr: true
    
  # Chain analysis settings
  chain_analysis:
    verify_chain: true
    report_gaps: true
    
  # Performance settings
  threads: 10
  timeout: 5
```

## Understanding Results

### NSEC Records

NSEC records form a chain that links domain names in canonical order:

```json
{
  "nsec_records": [
    {
      "owner": "example.com",
      "next": "mail.example.com",
      "types": ["A", "MX", "NS", "SOA"]
    },
    {
      "owner": "mail.example.com",
      "next": "www.example.com",
      "types": ["A", "MX"]
    }
  ]
}
```

### NSEC3 Records

NSEC3 records provide similar functionality but use hashed names:

```json
{
  "nsec3_records": [
    {
      "name": "www.example.com",
      "hash": "2t7b4g4vsa5smi47k61mv5bv1a22bojr",
      "salt": "aabbccdd",
      "iterations": 10,
      "types": ["A", "AAAA"]
    }
  ]
}
```

### Zone Transfers

Results from zone transfer attempts:

```json
{
  "zone_transfer": {
    "success": true,
    "records": [
      "example.com. 3600 IN SOA ns1.example.com. admin.example.com. ...",
      "example.com. 3600 IN NS ns1.example.com.",
      "www.example.com. 3600 IN A 93.184.216.34"
    ]
  }
}
```

## Error Handling

The tool handles various error conditions:

- DNSSEC not enabled
- Zone transfers blocked
- NSEC/NSEC3 records not found
- Network connectivity issues
- Timeout errors

## Security Considerations

1. **Authorization**: Ensure you have permission to perform zone walking
2. **Resource Usage**: NSEC3 cracking can be resource-intensive
3. **Network Impact**: Consider rate limiting for production environments
4. **Data Sensitivity**: Handle enumerated data responsibly

## Integration

The tool integrates with the framework's workflow system:

```bash
# Run as part of complete workflow
python rfs_dns_framework.py --workflow --domain example.com

# Generate HTML report
python rfs_dns_framework.py --tool zone_walker example.com --format html
```

## Troubleshooting

### Common Issues

1. **No DNSSEC Records**
   ```bash
   # Verify DNSSEC is enabled
   dig +dnssec example.com
   ```

2. **Zone Transfer Failures**
   ```bash
   # Test zone transfer manually
   dig @ns1.example.com example.com AXFR
   ```

3. **Performance Issues**
   ```bash
   # Reduce thread count
   python rfs_dns_framework.py --tool zone_walker example.com --threads 5
   ```

## References

- [RFC 4034 - DNSSEC Resource Records](https://tools.ietf.org/html/rfc4034)
- [RFC 5155 - NSEC3 Records](https://tools.ietf.org/html/rfc5155)
- [IANA - DNS Parameters](https://www.iana.org/assignments/dns-parameters) 