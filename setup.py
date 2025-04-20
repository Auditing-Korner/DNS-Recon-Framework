#!/usr/bin/env python3

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="rfs-dns-framework",
    version="1.0",
    author="rfs85",
    author_email="rfs85@github.com",
    description="A comprehensive DNS security testing framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/rfs85/RFS-DNS-Framework",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "rfs-dns=rfs_dns_framework.rfs_dns_framework:main",
        ],
    },
    include_package_data=True,
    package_data={
        "rfs_dns_framework": [
            "data/*",
            "config/*.yaml",
        ],
    },
    extras_require={
        "cloud": [
            "boto3>=1.26.0",
            "azure-mgmt-dns>=8.0.0",
            "google-cloud-dns>=0.34.0",
        ],
        "mobile": [
            "scapy>=2.4.5",
            "pyshark>=0.4.3",
        ],
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "isort>=5.0.0",
            "mypy>=1.0.0",
        ],
    },
) 