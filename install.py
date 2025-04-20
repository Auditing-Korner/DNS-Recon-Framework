#!/usr/bin/env python3

import os
import sys
import subprocess
import platform
from pathlib import Path

def check_python_version():
    """Check if Python version meets requirements"""
    required_version = (3, 7)
    current_version = sys.version_info[:2]
    
    if current_version < required_version:
        print(f"Error: Python {required_version[0]}.{required_version[1]} or higher is required")
        print(f"Current version: Python {current_version[0]}.{current_version[1]}")
        sys.exit(1)

def create_virtual_env():
    """Create a virtual environment"""
    if os.path.exists('venv'):
        print("Virtual environment already exists")
        return
    
    try:
        subprocess.run([sys.executable, '-m', 'venv', 'venv'], check=True)
        print("Created virtual environment")
    except subprocess.CalledProcessError as e:
        print(f"Error creating virtual environment: {e}")
        sys.exit(1)

def get_venv_python():
    """Get the path to the virtual environment Python executable"""
    if platform.system() == 'Windows':
        return os.path.join('venv', 'Scripts', 'python.exe')
    return os.path.join('venv', 'bin', 'python')

def install_requirements():
    """Install required packages"""
    venv_python = get_venv_python()
    if not os.path.exists(venv_python):
        print("Error: Virtual environment Python not found")
        sys.exit(1)
    
    try:
        # Upgrade pip first
        subprocess.run([venv_python, '-m', 'pip', 'install', '--upgrade', 'pip'], check=True)
        print("Upgraded pip to latest version")
        
        # Install requirements
        subprocess.run([venv_python, '-m', 'pip', 'install', '-r', 'requirements.txt'], check=True)
        print("Installed required packages")
    except subprocess.CalledProcessError as e:
        print(f"Error installing requirements: {e}")
        sys.exit(1)

def check_installation():
    """Verify installation by importing key packages"""
    venv_python = get_venv_python()
    test_imports = [
        'import rich',
        'import dns',
        'import requests',
        'import jinja2',
        'import scapy'
    ]
    
    print("\nVerifying installation...")
    for import_stmt in test_imports:
        try:
            subprocess.run([venv_python, '-c', import_stmt], check=True)
            print(f"✓ {import_stmt}")
        except subprocess.CalledProcessError:
            print(f"✗ Failed to import: {import_stmt}")
            return False
    return True

def setup_permissions():
    """Setup necessary permissions for network operations"""
    if platform.system() != 'Windows':
        try:
            # Allow raw socket access for non-root users
            python_path = get_venv_python()
            if os.path.exists(python_path):
                subprocess.run(['sudo', 'setcap', 'cap_net_raw+ep', python_path], check=True)
                print("Set raw socket capabilities for Python")
        except subprocess.CalledProcessError as e:
            print(f"Warning: Could not set raw socket capabilities: {e}")
            print("Some features may require root privileges")

def main():
    print("RFS DNS Framework - Installation Script")
    print("======================================")
    
    # Check Python version
    check_python_version()
    
    # Create virtual environment
    create_virtual_env()
    
    # Install requirements
    install_requirements()
    
    # Setup permissions
    setup_permissions()
    
    # Verify installation
    if check_installation():
        print("\nInstallation completed successfully!")
        print("\nTo start using the framework:")
        if platform.system() == 'Windows':
            print("1. Activate the virtual environment:")
            print("   .\\venv\\Scripts\\activate")
        else:
            print("1. Activate the virtual environment:")
            print("   source venv/bin/activate")
        print("2. Run the framework:")
        print("   python rfs_dns_framework.py --help")
    else:
        print("\nInstallation verification failed.")
        print("Please check the error messages above and try again.")
        sys.exit(1)

if __name__ == "__main__":
    main() 