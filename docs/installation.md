# Installation Guide

This guide will help you set up the RFS DNS Framework on your system.

## System Requirements

- Python 3.7 or higher
- Root/Administrator privileges (for packet manipulation)
- Git (for cloning the repository)
- pip (Python package manager)

## Operating System Support

- Linux (Primary support)
- macOS
- Windows (with limitations)

## Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/rfs85/RFS-DNS-Framework.git
cd RFS-DNS-Framework
```

### 2. Create a Virtual Environment (Recommended)

```bash
# Linux/macOS
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
.\venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Verify Installation

```bash
# Test the DNS cache poisoning tool
sudo python3 dns_cache_poison.py --help

# Test other tools
python3 dns_enum.py --help
python3 find_dnsserver.py --help
```

## Dependencies

The framework requires the following Python packages:

```text
requests==2.31.0
dnspython==2.4.2
rich==13.7.0
tqdm>=4.67.1
colorama>=0.4.6
jinja2>=3.1.6
scapy>=2.5.0
```

## Platform-Specific Instructions

### Linux

1. **Install system dependencies**:
   ```bash
   # Debian/Ubuntu
   sudo apt-get update
   sudo apt-get install python3-dev python3-pip libpcap-dev
   
   # RHEL/CentOS
   sudo yum install python3-devel python3-pip libpcap-devel
   ```

2. **Configure permissions**:
   ```bash
   # Allow raw socket access (if not running as root)
   sudo setcap cap_net_raw+ep /usr/bin/python3
   ```

### macOS

1. **Install Homebrew** (if not already installed):
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```

2. **Install dependencies**:
   ```bash
   brew install python3 libpcap
   ```

### Windows

1. **Install Npcap**:
   - Download and install [Npcap](https://nmap.org/npcap/)
   - Choose "Install Npcap in WinPcap API-compatible Mode"

2. **Configure Python**:
   - Ensure Python is added to PATH
   - Run Command Prompt as Administrator for tools requiring privileges

## Common Installation Issues

### 1. Scapy Installation Errors

If you encounter issues installing Scapy:

```bash
# Linux/macOS
pip install --no-binary :all: scapy

# Windows
pip install --no-cache-dir scapy
```

### 2. Permission Issues

If you get permission errors:

```bash
# Linux/macOS
sudo chmod +x *.py
sudo chown $(whoami) venv

# Windows
# Run Command Prompt as Administrator
```

### 3. Missing Compiler

If you need to compile extensions:

```bash
# Debian/Ubuntu
sudo apt-get install build-essential python3-dev

# RHEL/CentOS
sudo yum groupinstall "Development Tools"
```

## Development Installation

For contributing to the project:

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install
```

## Docker Installation

We also provide a Docker image for containerized usage:

```bash
# Build the image
docker build -t rfs-dns-framework .

# Run a tool
docker run --rm -it --network host rfs-dns-framework dns_cache_poison.py --help
```

## Updating

To update to the latest version:

```bash
git pull origin main
pip install -r requirements.txt --upgrade
```

## Uninstallation

To remove the framework:

```bash
# Deactivate virtual environment
deactivate

# Remove directory
rm -rf RFS-DNS-Framework
```

## Next Steps

- Read the [Usage Guide](usage.md)
- Check the [Security Considerations](security.md)
- Review the [Contributing Guidelines](contributing.md)

## Support

If you encounter any issues during installation:

1. Check the [Troubleshooting Guide](troubleshooting.md)
2. Search existing [GitHub Issues](https://github.com/rfs85/RFS-DNS-Framework/issues)
3. Create a new issue with detailed information about your problem 