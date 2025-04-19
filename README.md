# RFS-DNS-Framework - Bug Bounty Edition

A comprehensive DNS reconnaissance and enumeration framework designed for bug bounty hunters, penetration testers, and security researchers. This framework consists of two powerful tools that work together to provide extensive DNS analysis capabilities.

## Features

### DNS Enumerator (`dns_enum.py`)

A feature-rich DNS enumeration tool that provides:

- **Comprehensive DNS Record Enumeration**
  - Supports all common DNS record types
  - Automated nameserver detection and analysis
  - Zone transfer attempt capabilities
  - DNSSEC analysis
  
- **Advanced Subdomain Discovery**
  - Memory-efficient subdomain bruteforcing
  - Intelligent wildcard detection and filtering
  - Multiple wordlist options (tiny to extra-large)
  - Support for custom wordlists
  
- **Infrastructure Analysis**
  - Cloud provider detection (AWS, Azure, GCP, etc.)
  - DNS delegation analysis
  - Reverse DNS lookup capabilities
  - Email security analysis (SPF, DMARC)
  
- **Security Assessments**
  - Subdomain takeover checks
  - Security header analysis
  - SMTP security checks
  - Sensitive file detection
  
- **Flexible Output Options**
  - JSON export
  - CSV export
  - Text report
  - HTML report generation
  - Result caching for interrupted scans

### DNS Server Tester (`find_dnsserver.py`)

A specialized tool for testing and validating DNS servers:

- **Multiple DNS Server Testing**
  - Test against top public DNS servers
  - Regional DNS server testing (Netherlands, Egypt)
  - Provider-specific testing (Vodafone)
  - Root DNS server testing
  - AWS DNS server testing
  
- **Performance Analysis**
  - Response time measurement
  - TCP/UDP protocol support
  - Timeout handling
  
- **Flexible Input Options**
  - Single server testing
  - Batch testing from CSV files
  - Built-in server lists
  - Random server selection option

## Requirements

```bash
pip install dnspython requests tqdm colorama pandas jinja2
```

## Usage

### DNS Enumerator

```bash
python dns_enum.py domain.com [options]

Options:
  --wordlist WORDLIST     Specify wordlist (tiny/small/medium/large/xl)
  --threads THREADS       Number of concurrent threads (default: 10)
  --timeout TIMEOUT      Query timeout in seconds (default: 2)
  --output OUTPUT        Output file path
  --format FORMAT        Output format (json/csv/txt/html)
  --verbose             Enable verbose output
  --max-depth DEPTH     Maximum recursion depth
  --resolve-ips         Enable reverse DNS lookups
  --no-wildcard         Disable wildcard detection
  --resume              Resume from cached results
  --no-providers        Disable cloud provider detection
```

### DNS Server Tester

```bash
python find_dnsserver.py domain.com [options]

Options:
  -s, --server          Test specific DNS server
  -t, --timeout         Timeout in seconds (default: 2)
  --top                 Test against top public DNS servers
  --nl, --holland       Test Netherlands DNS servers
  --eg, --egypt         Test Egypt DNS servers
  --vodafone           Test Vodafone DNS servers
  --root               Test root DNS servers
  --aws                Test AWS DNS servers
  --all                Test all known DNS servers
  --list FILE          Test servers from CSV file
  --shuffle            Randomize server testing order
  --tcp                Use TCP instead of UDP
```

## Examples

### Basic Enumeration
```bash
python dns_enum.py example.com
```

### Advanced Enumeration with HTML Report
```bash
python dns_enum.py example.com --wordlist large --threads 20 --format html --output report.html
```

### Testing Multiple DNS Servers
```bash
python find_dnsserver.py example.com --all --shuffle
```

### Testing Specific DNS Server
```bash
python find_dnsserver.py example.com -s 8.8.8.8 --tcp
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is open source and available under the MIT License.

## Author

rfs85

## Acknowledgments

- SecLists project for wordlists
- Various public DNS providers
- Open source security community