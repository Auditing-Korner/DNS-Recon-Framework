# DNS Cache Poisoning Tool

The DNS Cache Poisoning Tool is an advanced security testing utility designed to identify vulnerabilities in DNS server implementations and demonstrate cache poisoning attack vectors.

## Features

### 1. Vulnerability Detection

The tool performs multiple sophisticated checks to identify potential vulnerabilities:

- **Source Port Randomization**: Tests if the DNS server uses predictable source ports
- **Transaction ID Analysis**: Checks for patterns in DNS transaction IDs
- **DNSSEC Implementation**: Verifies if DNSSEC is properly implemented
- **Response Pattern Analysis**: Analyzes DNS response patterns for predictability

### 2. Cache Poisoning Simulation

Demonstrates various cache poisoning techniques:

- Parallel processing for efficient testing
- Multiple DNS record type support (A, AAAA, MX)
- Automated success verification
- Detailed success rate tracking

### 3. Performance Optimization

- Multi-threaded execution
- Optimized packet generation
- Efficient network utilization
- Configurable performance parameters

## Usage

### Basic Usage

```bash
sudo python3 dns_cache_poison.py \
  --target example.com \
  --nameserver 8.8.8.8 \
  --spoofed-ip 192.168.1.1 \
  --mode detect
```

### Advanced Options

```bash
sudo python3 dns_cache_poison.py \
  --target example.com \
  --nameserver 8.8.8.8 \
  --spoofed-ip 192.168.1.1 \
  --record-type A \
  --mode both \
  --duration 30 \
  --max-attempts 1000 \
  --threads 10 \
  --output results.json
```

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--target` | Target domain to test | Required |
| `--nameserver` | DNS server to test | Required |
| `--spoofed-ip` | IP address to inject | Required |
| `--record-type` | DNS record type (A/AAAA/MX) | A |
| `--mode` | Operation mode (detect/poison/both) | detect |
| `--duration` | Duration of poisoning attempt (seconds) | 30 |
| `--max-attempts` | Maximum number of attempts | 1000 |
| `--threads` | Number of parallel threads | 10 |
| `--output` | Results output file | dns_poison_results.json |

## Output Format

The tool generates a detailed JSON report containing:

```json
{
  "timestamp": "2024-03-14T12:00:00",
  "target_domain": "example.com",
  "nameserver": "8.8.8.8",
  "record_type": "A",
  "vulnerability_checks": [
    {
      "check": "source_port_randomization",
      "vulnerable": false,
      "details": "Unique ports observed: 10/10"
    },
    {
      "check": "txid_randomization",
      "vulnerable": false,
      "details": "Unique TXIDs observed: 10/10"
    },
    {
      "check": "dnssec",
      "vulnerable": false,
      "details": "DNSSEC implemented"
    }
  ],
  "poisoning_attempts": [
    {
      "total_attempts": 100,
      "successful_attempts": 0,
      "success_rate": 0.0,
      "duration": 30.5
    }
  ]
}
```

## Implementation Details

### Vulnerability Detection

The tool uses multiple methods to detect vulnerabilities:

1. **Source Port Analysis**
   ```python
   def check_source_port_randomization(self, num_queries=10):
       ports = set()
       for _ in range(num_queries):
           reply = sr1(query, timeout=2, verbose=0)
           if reply and UDP in reply:
               ports.add(reply[UDP].sport)
       return len(ports) > num_queries * 0.8
   ```

2. **Transaction ID Testing**
   ```python
   def check_txid_randomization(self, num_queries=10):
       txids = set()
       for _ in range(num_queries):
           reply = sr1(query, timeout=2, verbose=0)
           if reply and DNS in reply:
               txids.add(reply[DNS].id)
       return len(txids) > num_queries * 0.8
   ```

### Cache Poisoning Simulation

The poisoning attempt uses parallel processing:

```python
with ThreadPoolExecutor(max_workers=max_workers) as executor:
    futures = []
    while time.time() - start_time < duration:
        futures.append(
            executor.submit(self.poison_worker, total_attempts)
        )
```

## Security Considerations

1. **Legal Requirements**
   - Obtain proper authorization before testing
   - Follow responsible disclosure practices
   - Document all testing activities

2. **System Requirements**
   - Root/Administrator privileges required
   - Proper network access
   - Sufficient system resources

3. **Risk Mitigation**
   - Use in controlled environments
   - Monitor system resources
   - Implement proper rate limiting

## Troubleshooting

### Common Issues

1. **Permission Denied**
   ```bash
   sudo python3 dns_cache_poison.py ...
   ```

2. **Network Access**
   - Ensure proper network connectivity
   - Check firewall settings
   - Verify DNS server accessibility

3. **Resource Constraints**
   - Adjust thread count
   - Modify attempt duration
   - Monitor system load

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](contributing.md) for details on:

- Code style
- Testing requirements
- Pull request process
- Feature requests

## License

This tool is part of the RFS DNS Framework and is licensed under the MIT License. 