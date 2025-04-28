#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(
    name="rfs-dns-framework",
    version="2.1.0",
    description="RFS DNS Framework - A comprehensive DNS reconnaissance and security assessment framework",
    author="rfs85",
    author_email="",  # Add author email if available
    url="https://github.com/rfs85/RFS-DNS-Framework",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "rich>=10.0.0",
        "dnspython>=2.4.2",
        "requests>=2.31.0",
        "pyyaml>=6.0.1",
        "jinja2>=3.0.0",
        "scapy>=2.4.5",
        "ipaddress>=1.0.23",
        "cryptography>=42.0.2",
        "pyopenssl>=24.0.0",
        "sslyze>=5.2.0",
        "nassl>=5.1.0",
        "tlslite-ng>=0.8.0",
        "python-dateutil>=2.8.2",
    ],
    entry_points={
        'console_scripts': [
            'rfs-dns-framework=rfs_dns_framework:main',
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Networking",
    ],
    python_requires=">=3.8",
) 