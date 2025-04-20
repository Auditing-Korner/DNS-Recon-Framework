# RFS DNS Framework

A comprehensive DNS reconnaissance and security assessment framework consisting of multiple specialized tools for DNS enumeration, cloud provider detection, subdomain takeover detection, and TLD discovery.

## Features

### Core Components

1. **DNS Enumerator (`dns_enum.py`)**
   - Comprehensive DNS record enumeration (A, AAAA, CNAME, MX, NS, TXT, SOA, etc.)
   - DNSSEC analysis and validation
   - Zone transfer attempts
   - Subdomain bruteforcing with memory-efficient processing
   - Wildcard detection and filtering
   - DNS infrastructure analysis
   - Result caching for interrupted scans
   - Multiple export formats (JSON, CSV, TXT, HTML)
   - Security header analysis
   - Email security configuration checks
   - Detailed HTML report generation

2. **DNS Server Finder (`find_dnsserver.py`)**
   - DNS server discovery and testing
   - Support for multiple DNS protocols (UDP/TCP)
   - Colored output for better readability
   - Response time measurement
   - Custom timeout configuration
   - Support for various DNS server lists:
     - Top public DNS servers
     - Country-specific servers (Netherlands, Egypt)
     - Provider-specific servers (Vodafone)
     - Root DNS servers
     - AWS DNS servers

3. **Cloud Provider Enumerator (`enumerate_cloud_providers.py`)**
   - Detection and analysis of cloud service providers
   - DNS record analysis for provider identification
   - Provider categorization
   - Infrastructure mapping
   - Detailed provider analysis
   - Support for major cloud providers:
     - AWS, Azure, GCP, Cloudflare
     - DigitalOcean, Heroku, Netlify
     - And many more

4. **TLD Bruteforcer (`dns_tld_bruteforce.py`)**
   - Multi-threaded TLD discovery
   - Categorized TLD lists:
     - Common TLDs (.com, .net, .org, etc.)
     - Country-code TLDs
     - Business TLDs
     - Tech TLDs
   - Advanced bruteforce mode
   - Custom wordlist support
   - Progress tracking
   - MX record detection

5. **Cloud Takeover Detector (`cloud_takeover_detector.py`)**
   - Subdomain takeover vulnerability detection
   - Support for multiple cloud providers
   - Risk assessment and categorization
   - Detailed vulnerability reporting
   - Remediation guidance
   - Support for various service types:
     - Cloud Storage (S3, Azure Blob, etc.)
     - Web Hosting (GitHub Pages, Netlify, etc.)
     - CDN Services (Cloudflare, Fastly, etc.)
     - Government and Military Services
     - Enterprise Service Providers

## Installation

1. Clone this repository:
```bash
git clone https://github.com/yourusername/RFS-DNS-Framework.git
cd RFS-DNS-Framework
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### DNS Enumeration
```bash
python dns_enum.py example.com [options]
# For comprehensive DNS enumeration and analysis
```

### Find DNS Servers
```bash
python find_dnsserver.py google.com
# Test domain resolution against various DNS servers

# Test specific DNS server
python find_dnsserver.py google.com -s 8.8.8.8

# Test against top public DNS servers
python find_dnsserver.py google.com --top
```

### Cloud Provider Enumeration
```bash
python enumerate_cloud_providers.py
# List and analyze cloud providers

# Enumerate specific provider
python enumerate_cloud_providers.py -p "Amazon Web Services"

# Show DNS information
python enumerate_cloud_providers.py -d "Microsoft Azure"
```

### TLD Bruteforce
```bash
python dns_tld_bruteforce.py example
# Basic TLD discovery

# Use specific TLD category
python dns_tld_bruteforce.py example --type country

# Enable bruteforce mode
python dns_tld_bruteforce.py example -b --min-length 2 --max-length 3
```

### Cloud Takeover Detection
```bash
python cloud_takeover_detector.py example.com
# Basic takeover scan

# Scan with custom subdomain list
python cloud_takeover_detector.py example.com -s subdomains.txt

# Generate detailed report
python cloud_takeover_detector.py example.com -o report.json
```

## Advanced Features

### DNS Enumeration
- DNSSEC validation and analysis
- Email security configuration checks
- Infrastructure analysis
- Security header analysis
- HTML report generation
- Multiple export formats

### Cloud Provider Detection
- Provider fingerprinting
- Service categorization
- Risk assessment
- Infrastructure mapping
- Detailed provider analysis

### TLD Discovery
- Pattern-based generation
- Category-based scanning
- Custom wordlist support
- Progress tracking
- Rate limiting

### Takeover Detection
- Risk categorization
- Remediation guidance
- Provider-specific checks
- Detailed vulnerability reporting
- Multi-threaded scanning

## Security Considerations

- Always ensure you have permission to test domains
- Use rate limiting when necessary
- Follow responsible disclosure practices
- Be cautious with government and military domains
- Respect usage policies of DNS servers

## Contributing

Contributions are welcome! Please feel free to submit pull requests or create issues for bugs and feature requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

rfs85

## Acknowledgments

- DNS Python library contributors
- Cloud provider documentation
- Security research community