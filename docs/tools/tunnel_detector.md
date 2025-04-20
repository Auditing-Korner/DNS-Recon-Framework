# DNS Tunnel Detector

The DNS Tunnel Detector is an advanced tool for identifying DNS tunneling and data exfiltration attempts. It uses multiple detection methods including statistical analysis, entropy calculation, pattern matching, and signature-based detection.

## Features

- Multiple detection methods:
  - Statistical analysis
  - Shannon entropy calculation
  - Pattern matching
  - Signature-based detection
- PCAP file analysis
- Real-time query analysis
- Configurable detection thresholds
- Detailed reporting and logging

## Usage

### Basic Usage

```bash
# Analyze a PCAP file
python rfs_dns_framework.py --tool tunnel_detector --pcap capture.pcap

# Analyze a single query
python rfs_dns_framework.py --tool tunnel_detector --query suspicious.example.com

# Specify query type
python rfs_dns_framework.py --tool tunnel_detector --query data.example.com --qtype TXT
```

### Detection Methods

```bash
# Disable specific detection methods
python rfs_dns_framework.py --tool tunnel_detector --pcap capture.pcap \
  --no-statistical \
  --no-entropy \
  --no-pattern \
  --no-signature
```

## Configuration

The tool's behavior can be customized in `config.yaml`:

```yaml
tunnel_detector:
  # Detection methods
  methods:
    statistical: true
    entropy: true
    pattern_matching: true
    signature_based: true
    
  # Analysis settings
  analysis:
    min_sample_size: 1000
    time_window: 300
    entropy_threshold: 0.7
    
  # Known signatures file
  signatures_file: "data/tunnel_signatures.json"
  
  # Logging settings
  log_queries: true
  log_matches: true
  
  # Performance
  threads: 15
  packet_buffer: 10000
```

## Understanding Results

### Single Query Analysis

Example output for a single query analysis:

```json
{
  "query": "data.example.com",
  "qtype": "TXT",
  "statistical_indicators": {
    "length": 45,
    "subdomain_count": 3,
    "unique_chars": 32,
    "digit_ratio": 0.4,
    "consonant_ratio": 0.6
  },
  "entropy_score": 0.85,
  "pattern_matches": ["base64_encoded", "long_numeric"],
  "signature_matches": ["dnscat2_tunnel"],
  "is_tunnel": true,
  "confidence": 0.92
}
```

### PCAP Analysis

Summary of PCAP file analysis:

```json
{
  "analyzed_queries": 1000,
  "tunnel_detected": true,
  "detections": [
    {
      "query": "encoded-data.example.com",
      "confidence": 0.95,
      "pattern_matches": ["base64_encoded"],
      "signature_matches": ["iodine_tunnel"]
    }
  ],
  "summary": {
    "total_detections": 5,
    "unique_patterns": ["base64_encoded", "hex_encoded"],
    "unique_signatures": ["iodine_tunnel", "dnscat2_tunnel"],
    "confidence_stats": {
      "min": 0.75,
      "max": 0.95,
      "avg": 0.85
    }
  }
}
```

## Detection Methods

### 1. Statistical Analysis

Analyzes various statistical properties:
- Query length
- Subdomain count
- Character diversity
- Digit ratio
- Query frequency
- Average query length

### 2. Entropy Analysis

Calculates Shannon entropy to detect encoded data:
- Higher entropy indicates potential encoding
- Configurable threshold
- Adaptive to query patterns

### 3. Pattern Matching

Detects common tunneling patterns:
- Base64 encoding
- Hex encoding
- Long numeric sequences
- Repeating patterns

### 4. Signature-Based Detection

Matches against known tunneling tools:
- Iodine
- Dnscat2
- DNS2TCP
- Custom signatures

## Signature Format

Custom signatures can be added to `data/tunnel_signatures.json`:

```json
{
  "name": "custom_tunnel",
  "description": "Custom tunneling pattern",
  "pattern": "^[a-zA-Z0-9+/]{20,}\\.[a-zA-Z0-9-]+\\.[a-zA-Z]{2,}$",
  "qtype": "TXT"
}
```

## Security Considerations

1. **False Positives**: Some legitimate services may trigger detection
2. **Resource Usage**: PCAP analysis can be memory-intensive
3. **Privacy**: DNS queries may contain sensitive information
4. **Authorization**: Ensure you have permission to monitor DNS traffic

## Integration

The tool integrates with the framework's workflow system:

```bash
# Run as part of complete workflow
python rfs_dns_framework.py --workflow --domain example.com

# Generate HTML report
python rfs_dns_framework.py --tool tunnel_detector --pcap capture.pcap --format html
```

## Troubleshooting

### Common Issues

1. **Memory Usage**
   ```bash
   # Reduce packet buffer size
   python rfs_dns_framework.py --tool tunnel_detector --pcap capture.pcap --buffer-size 5000
   ```

2. **Missing Dependencies**
   ```bash
   # Install Scapy for PCAP analysis
   pip install scapy
   ```

3. **Performance Issues**
   ```bash
   # Disable some detection methods
   python rfs_dns_framework.py --tool tunnel_detector --pcap capture.pcap --no-entropy
   ```

## References

- [DNS Tunneling Techniques](https://www.sans.org/reading-room/whitepapers/dns/detecting-dns-tunneling-34152)
- [IANA - DNS Parameters](https://www.iana.org/assignments/dns-parameters)
- [DNS Data Exfiltration](https://attack.mitre.org/techniques/T1048/001/) 