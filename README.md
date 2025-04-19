# DNS TLD Bruteforcer

A Python script to discover valid domain names by bruteforcing different Top Level Domain (TLD) extensions, with special focus on country-code TLDs (ccTLDs) and categorized TLD lists.

## Features

- Multi-threaded DNS resolution
- Categorized TLD lists:
  - Common TLDs (.com, .net, .org, etc.)
  - Country-code TLDs (.pt, .es, .fr, etc.)
  - Business TLDs (.shop, .store, .company, etc.)
  - Tech TLDs (.ai, .dev, .cloud, etc.)
- Advanced TLD bruteforce mode:
  - Systematic TLD combination generation
  - Common pattern detection (co.xx, com.xx, etc.)
  - Configurable length range
  - Progress tracking
- Support for custom TLD wordlists
- Configurable timeout and thread count
- MX record detection
- Error handling and rate limiting

## Installation

1. Clone this repository or download the scripts
2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Basic usage with all TLD categories:
```bash
python dns_tld_bruteforce.py example
```

Check only country-code TLDs:
```bash
python dns_tld_bruteforce.py example --type country
```

Enable bruteforce mode:
```bash
python dns_tld_bruteforce.py example -b
```

Bruteforce with custom length range:
```bash
python dns_tld_bruteforce.py example -b --min-length 2 --max-length 4
```

Using a custom TLD wordlist:
```bash
python dns_tld_bruteforce.py example -w tlds.txt
```

Advanced usage with custom threads and timeout:
```bash
python dns_tld_bruteforce.py example -t 20 --timeout 3
```

### Arguments

- `domain`: Base domain name without TLD (required)
- `-w, --wordlist`: Path to custom TLD wordlist file (optional)
- `-t, --threads`: Number of concurrent threads (default: 10)
- `--timeout`: DNS query timeout in seconds (default: 2)
- `--type`: Type of TLDs to check (choices: all, common, country, business, tech)
- `-b, --bruteforce`: Enable TLD bruteforce mode
- `--min-length`: Minimum TLD length for bruteforce mode (default: 2)
- `--max-length`: Maximum TLD length for bruteforce mode (default: 3)

## Example Output

Normal mode:
```
Starting DNS TLD bruteforce for base domain: example
Mode: TLD category (country)
Testing 42 TLDs with 10 threads

[+] Found: example.pt
    IP(s): 93.184.216.34
    MX: mail.example.pt

[+] Found: example.es
    IP(s): 93.184.216.34
    MX: mail.example.es

[+] Found: example.fr
    IP(s): 93.184.216.34

Bruteforce complete. Found 3 valid domains.
```

Bruteforce mode:
```
Starting DNS TLD bruteforce for base domain: example
Mode: Bruteforce
Generating TLD combinations (length 2-3)...
Generated 12876 TLD combinations
Testing 12876 TLDs with 10 threads

[+] Found: example.co.uk
    IP(s): 93.184.216.34
    MX: mail.example.co.uk

Progress: 1000/12876 TLDs tested (7.8%)
Progress: 2000/12876 TLDs tested (15.5%)
...

Bruteforce complete. Found 5 valid domains.
```

## Note

This tool is for educational and legitimate security testing purposes only. Always ensure you have permission to test domains before using this tool.