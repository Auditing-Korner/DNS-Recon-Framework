# Usage Guide

This guide provides detailed instructions on how to use the RFS DNS Framework tools effectively.

## DNS Cache Poisoning Tool

### Basic Usage

1. **Vulnerability Detection**
   ```bash
   sudo python3 dns_cache_poison.py \
     --target example.com \
     --nameserver 8.8.8.8 \
     --spoofed-ip 192.168.1.1 \
     --mode detect
   ```

2. **Cache Poisoning Simulation**
   ```bash
   sudo python3 dns_cache_poison.py \
     --target example.com \
     --nameserver 8.8.8.8 \
     --spoofed-ip 192.168.1.1 \
     --mode poison
   ```

3. **Complete Analysis**
   ```bash
   sudo python3 dns_cache_poison.py \
     --target example.com \
     --nameserver 8.8.8.8 \
     --spoofed-ip 192.168.1.1 \
     --mode both \
     --record-type A \
     --duration 60 \
     --threads 15
   ```

### Advanced Features

1. **Different Record Types**
   ```bash
   # Test AAAA records
   sudo python3 dns_cache_poison.py \
     --target example.com \
     --nameserver 8.8.8.8 \
     --spoofed-ip 2001:db8::1 \
     --record-type AAAA

   # Test MX records
   sudo python3 dns_cache_poison.py \
     --target example.com \
     --nameserver 8.8.8.8 \
     --spoofed-ip mail.example.com \
     --record-type MX
   ```

2. **Performance Tuning**
   ```bash
   # Increase thread count for faster testing
   sudo python3 dns_cache_poison.py \
     --target example.com \
     --nameserver 8.8.8.8 \
     --spoofed-ip 192.168.1.1 \
     --threads 20 \
     --duration 120
   ```

3. **Custom Output**
   ```bash
   # Save results to custom file
   sudo python3 dns_cache_poison.py \
     --target example.com \
     --nameserver 8.8.8.8 \
     --spoofed-ip 192.168.1.1 \
     --output custom_results.json
   ```

## Understanding Results

### Vulnerability Detection Results

The tool provides detailed information about potential vulnerabilities:

```json
{
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
      "vulnerable": true,
      "details": "DNSSEC not implemented"
    }
  ]
}
```

### Cache Poisoning Results

Results from poisoning attempts include:

```json
{
  "poisoning_attempts": [
    {
      "total_attempts": 1000,
      "successful_attempts": 0,
      "success_rate": 0.0,
      "duration": 30.5
    }
  ]
}
```

## Best Practices

1. **Testing Environment**
   - Use controlled test environments
   - Obtain proper authorization
   - Document all testing activities

2. **Performance Optimization**
   - Start with default settings
   - Gradually increase thread count
   - Monitor system resources
   - Adjust duration based on needs

3. **Result Analysis**
   - Review all vulnerability checks
   - Analyze success rates
   - Document findings
   - Follow up on vulnerabilities

## Common Use Cases

### 1. Security Auditing

```bash
# Comprehensive security audit
sudo python3 dns_cache_poison.py \
  --target example.com \
  --nameserver 8.8.8.8 \
  --spoofed-ip 192.168.1.1 \
  --mode both \
  --duration 300 \
  --output audit_results.json
```

### 2. Quick Vulnerability Check

```bash
# Fast vulnerability detection
sudo python3 dns_cache_poison.py \
  --target example.com \
  --nameserver 8.8.8.8 \
  --spoofed-ip 192.168.1.1 \
  --mode detect
```

### 3. Performance Testing

```bash
# High-performance testing
sudo python3 dns_cache_poison.py \
  --target example.com \
  --nameserver 8.8.8.8 \
  --spoofed-ip 192.168.1.1 \
  --mode poison \
  --threads 25 \
  --duration 600
```

## Troubleshooting

### Common Issues

1. **Permission Errors**
   ```bash
   # Solution: Run with sudo
   sudo python3 dns_cache_poison.py ...
   ```

2. **Network Connectivity**
   - Check DNS server accessibility
   - Verify network permissions
   - Check firewall settings

3. **Resource Constraints**
   - Reduce thread count
   - Decrease duration
   - Monitor system load

## Integration Examples

### 1. Automation Scripts

```bash
#!/bin/bash
# Example automation script
for server in $(cat dns_servers.txt); do
  sudo python3 dns_cache_poison.py \
    --target example.com \
    --nameserver $server \
    --spoofed-ip 192.168.1.1 \
    --mode detect \
    --output "results_${server}.json"
done
```

### 2. Continuous Monitoring

```bash
#!/bin/bash
# Example monitoring script
while true; do
  sudo python3 dns_cache_poison.py \
    --target example.com \
    --nameserver 8.8.8.8 \
    --spoofed-ip 192.168.1.1 \
    --mode detect \
    --output "monitor_$(date +%Y%m%d_%H%M%S).json"
  sleep 3600
done
```

## Additional Resources

- [DNS Cache Poisoning Tool Documentation](dns-cache-poison.md)
- [Security Considerations](security.md)
- [API Reference](api/index.md)
- [Contributing Guidelines](contributing.md)

## Support

If you encounter issues:

1. Check the [Troubleshooting Guide](troubleshooting.md)
2. Review [Common Issues](#common-issues)
3. Search [GitHub Issues](https://github.com/rfs85/RFS-DNS-Framework/issues)
4. Create a new issue with detailed information 