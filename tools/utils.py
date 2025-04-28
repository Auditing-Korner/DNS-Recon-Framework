"""Utility functions for RFS DNS Framework tools."""

import os
import sys
import socket
import dns.resolver
import dns.zone
import dns.query
import dns.exception
import dns.rdatatype
import dns.name
from typing import Dict, List, Any, Optional, Tuple, Set
import subprocess
import json
import re
import ssl
import OpenSSL
from datetime import datetime
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

def is_valid_domain(domain: str) -> bool:
    """
    Check if a domain name is valid.
    
    Args:
        domain: Domain name to validate
        
    Returns:
        bool: True if domain is valid
    """
    if not domain:
        return False
        
    # Basic domain format validation
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    if not re.match(domain_pattern, domain):
        return False
        
    try:
        # Try to resolve the domain
        dns.resolver.resolve(domain, 'A')
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        # Domain exists but might not have A record
        try:
            dns.resolver.resolve(domain, 'NS')
            return True
        except:
            return False
    except Exception:
        return False

def check_privileges() -> Tuple[bool, str]:
    """
    Check if the current user has sufficient privileges.
    
    Returns:
        Tuple[bool, str]: (has_privileges, privilege_type)
    """
    try:
        return os.geteuid() == 0, "root"
    except AttributeError:
        # Windows systems
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0, "administrator"
        except:
            return False, "unknown"

def check_operation_requirements(operation: str) -> Tuple[bool, Optional[str]]:
    """
    Check if the system meets requirements for a specific operation.
    
    Args:
        operation: Operation to check requirements for
        
    Returns:
        Tuple[bool, Optional[str]]: (requirements_met, error_message)
    """
    if operation == "raw_socket":
        has_privs, priv_type = check_privileges()
        if not has_privs:
            return False, f"Raw socket operations require {priv_type} privileges"
    elif operation == "packet_capture":
        has_privs, priv_type = check_privileges()
        if not has_privs:
            return False, f"Packet capture requires {priv_type} privileges"
            
    return True, None

def elevate_privileges() -> bool:
    """
    Attempt to elevate privileges if needed.
    
    Returns:
        bool: True if successful
    """
    has_privs, _ = check_privileges()
    if has_privs:
        return True
        
    try:
        if os.name == 'nt':  # Windows
            if sys.argv[0].endswith('.py'):
                args = [sys.executable] + sys.argv
            else:
                args = sys.argv
                
            try:
                subprocess.run(['runas', '/user:Administrator'] + args, check=True)
                return True
            except:
                return False
        else:  # Unix-like
            if sys.argv[0].endswith('.py'):
                args = [sys.executable] + sys.argv
            else:
                args = sys.argv
                
            try:
                subprocess.run(['sudo'] + args, check=True)
                return True
            except:
                return False
    except Exception as e:
        logging.error(f"Failed to elevate privileges: {str(e)}")
        return False

def check_raw_socket_access() -> Tuple[bool, Optional[str]]:
    """Check if raw socket operations are allowed."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.close()
        return True, None
    except PermissionError:
        return False, "Raw socket access requires root privileges"
    except:
        return False, "Raw socket operations not supported"

def check_dns_server_access() -> Tuple[bool, Optional[str]]:
    """Check if DNS server operations are allowed."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(('', 53))
        s.close()
        return True, None
    except PermissionError:
        return False, "DNS server operations require root privileges"
    except:
        return False, "DNS server operations not supported"

def check_ssl_requirements() -> Tuple[bool, Optional[str]]:
    """Check if SSL scanning requirements are met."""
    try:
        import ssl
        import OpenSSL
        return True, None
    except ImportError as e:
        return False, f"Missing SSL requirements: {str(e)}"

def check_cloud_access() -> Tuple[bool, Optional[str]]:
    """Check if cloud service access is available."""
    providers = {
        'aws': 'https://aws.amazon.com',
        'azure': 'https://azure.microsoft.com',
        'gcp': 'https://cloud.google.com'
    }
    
    for provider, url in providers.items():
        try:
            requests.get(url, timeout=5)
        except:
            return False, f"Cannot access {provider} cloud services"
    
    return True, None

def resolve_domain(domain: str, record_type: str = 'A', nameserver: Optional[str] = None) -> List[str]:
    """
    Resolve DNS records for a domain.
    
    Args:
        domain: Domain to resolve
        record_type: DNS record type
        nameserver: Optional nameserver to use
        
    Returns:
        List[str]: Resolved records
    """
    try:
        resolver = dns.resolver.Resolver()
        if nameserver:
            resolver.nameservers = [nameserver]
            
        answers = resolver.resolve(domain, record_type)
        return [str(rdata) for rdata in answers]
    except Exception:
        return []

def check_zone_transfer(domain: str, nameserver: str) -> Optional[dns.zone.Zone]:
    """
    Attempt a zone transfer for a domain.
    
    Args:
        domain: Target domain
        nameserver: Nameserver to query
        
    Returns:
        Optional[dns.zone.Zone]: Zone data if successful
    """
    try:
        zone = dns.zone.from_xfr(
            dns.query.xfr(nameserver, domain, lifetime=10)
        )
        return zone
    except:
        return None

def get_ssl_info(hostname: str, port: int = 443) -> Dict[str, Any]:
    """
    Get SSL certificate information for a host.
    
    Args:
        hostname: Target hostname
        port: Target port
        
    Returns:
        Dict[str, Any]: SSL certificate information
    """
    try:
        cert = ssl.get_server_certificate((hostname, port))
        x509 = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM,
            cert
        )
        
        return {
            'subject': dict(x509.get_subject().get_components()),
            'issuer': dict(x509.get_issuer().get_components()),
            'version': x509.get_version(),
            'serial_number': x509.get_serial_number(),
            'not_before': x509.get_notBefore().decode(),
            'not_after': x509.get_notAfter().decode(),
            'has_expired': x509.has_expired()
        }
    except Exception as e:
        return {'error': str(e)}

def parallel_dns_query(
    domains: List[str],
    record_types: List[str] = ['A'],
    nameserver: Optional[str] = None,
    max_workers: int = 10
) -> Dict[str, Dict[str, List[str]]]:
    """
    Perform parallel DNS queries.
    
    Args:
        domains: List of domains to query
        record_types: List of record types to query
        nameserver: Optional nameserver to use
        max_workers: Maximum number of parallel workers
        
    Returns:
        Dict[str, Dict[str, List[str]]]: Results by domain and record type
    """
    results = {}
    
    def query_domain(domain: str) -> Dict[str, Dict[str, List[str]]]:
        domain_results = {}
        for record_type in record_types:
            records = resolve_domain(domain, record_type, nameserver)
            if records:
                domain_results[record_type] = records
        return {domain: domain_results}
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {
            executor.submit(query_domain, domain): domain
            for domain in domains
        }
        
        for future in as_completed(future_to_domain):
            try:
                result = future.result()
                results.update(result)
            except Exception:
                continue
    
    return results

def is_wildcard_domain(domain: str, nameserver: Optional[str] = None) -> bool:
    """
    Check if a domain uses wildcard DNS records.
    
    Args:
        domain: Domain to check
        nameserver: Optional nameserver to use
        
    Returns:
        bool: True if wildcard records exist
    """
    random_prefix = f"wildcard-test-{datetime.now().timestamp()}"
    test_domain = f"{random_prefix}.{domain}"
    
    records = resolve_domain(test_domain, 'A', nameserver)
    return len(records) > 0

def get_domain_nameservers(domain: str) -> List[str]:
    """
    Get authoritative nameservers for a domain.
    
    Args:
        domain: Domain to query
        
    Returns:
        List[str]: List of nameserver IP addresses
    """
    try:
        resolver = dns.resolver.Resolver()
        ns_records = resolver.resolve(domain, 'NS')
        
        nameservers = []
        for record in ns_records:
            ns_hostname = str(record.target).rstrip('.')
            try:
                # Get IP for nameserver
                answers = resolver.resolve(ns_hostname, 'A')
                for answer in answers:
                    nameservers.append(str(answer))
            except:
                continue
                
        return nameservers
    except:
        return []

def check_dnssec(domain: str) -> Dict[str, Any]:
    """
    Check DNSSEC configuration for a domain.
    
    Args:
        domain: Domain to check
        
    Returns:
        Dict[str, Any]: DNSSEC status and configuration
    """
    try:
        resolver = dns.resolver.Resolver()
        
        # Check for DNSKEY records
        try:
            dnskey = resolver.resolve(domain, 'DNSKEY')
            has_dnskey = True
        except:
            has_dnskey = False
            
        # Check for DS records
        try:
            ds = resolver.resolve(domain, 'DS')
            has_ds = True
        except:
            has_ds = False
            
        # Check for RRSIG records
        try:
            rrsig = resolver.resolve(domain, 'RRSIG')
            has_rrsig = True
        except:
            has_rrsig = False
            
        return {
            'enabled': has_dnskey and has_ds,
            'has_dnskey': has_dnskey,
            'has_ds': has_ds,
            'has_rrsig': has_rrsig
        }
    except:
        return {
            'enabled': False,
            'error': 'Failed to check DNSSEC'
        }

def get_ptr_record(ip: str) -> Optional[str]:
    """
    Get PTR record for an IP address.
    
    Args:
        ip: IP address to query
        
    Returns:
        Optional[str]: PTR record if found
    """
    try:
        addr = dns.reversename.from_address(ip)
        resolver = dns.resolver.Resolver()
        ptr = resolver.resolve(addr, 'PTR')
        return str(ptr[0].target).rstrip('.')
    except:
        return None

def detect_dns_server(ip: str, port: int = 53) -> Dict[str, Any]:
    """
    Detect DNS server software and version.
    
    Args:
        ip: Server IP address
        port: Server port
        
    Returns:
        Dict[str, Any]: Server information
    """
    try:
        # Try version.bind query
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [ip]
        resolver.port = port
        
        version_query = dns.message.make_query(
            'version.bind',
            dns.rdatatype.TXT,
            dns.rdataclass.CH
        )
        
        response = dns.query.udp(version_query, ip, port=port, timeout=5)
        
        if response.answer:
            version = str(response.answer[0][0]).strip('"')
            return {
                'ip': ip,
                'port': port,
                'software': detect_software_from_version(version),
                'version': version,
                'protocol': 'udp'
            }
    except:
        pass
        
    # Try TCP connection for banner grabbing
    try:
        with socket.create_connection((ip, port), timeout=5) as sock:
            banner = sock.recv(1024).decode()
            return {
                'ip': ip,
                'port': port,
                'banner': banner,
                'protocol': 'tcp'
            }
    except:
        pass
        
    return {
        'ip': ip,
        'port': port,
        'error': 'Could not detect server information'
    }

def detect_software_from_version(version: str) -> str:
    """
    Detect DNS server software from version string.
    
    Args:
        version: Version string
        
    Returns:
        str: Detected software name
    """
    version = version.lower()
    
    if 'bind' in version:
        return 'BIND'
    elif 'unbound' in version:
        return 'Unbound'
    elif 'power' in version:
        return 'PowerDNS'
    elif 'microsoft' in version:
        return 'Microsoft DNS'
    else:
        return 'Unknown'

def is_domain_registered(domain: str) -> bool:
    """
    Check if a domain is registered.
    
    Args:
        domain: Domain to check
        
    Returns:
        bool: True if domain is registered
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.resolve(domain, 'NS')
        return True
    except dns.resolver.NXDOMAIN:
        return False
    except:
        return True  # Assume registered if query fails

def get_common_subdomains(domain: str, wordlist: Optional[str] = None) -> Set[str]:
    """
    Get common subdomains for a domain.
    
    Args:
        domain: Base domain
        wordlist: Optional path to wordlist file
        
    Returns:
        Set[str]: Set of discovered subdomains
    """
    subdomains = set()
    
    # Default common subdomain prefixes
    common_prefixes = {
        'www', 'mail', 'remote', 'blog', 'webmail', 'server',
        'ns1', 'ns2', 'smtp', 'secure', 'vpn', 'api', 'dev',
        'staging', 'app', 'admin', 'portal', 'test', 'demo'
    }
    
    # Load custom wordlist if provided
    if wordlist and os.path.exists(wordlist):
        try:
            with open(wordlist) as f:
                common_prefixes.update(line.strip() for line in f)
        except:
            pass
    
    # Query each potential subdomain
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_subdomain = {
            executor.submit(resolve_domain, f"{prefix}.{domain}"): prefix
            for prefix in common_prefixes
        }
        
        for future in as_completed(future_to_subdomain):
            prefix = future_to_subdomain[future]
            try:
                if future.result():
                    subdomains.add(f"{prefix}.{domain}")
            except:
                continue
    
    return subdomains 