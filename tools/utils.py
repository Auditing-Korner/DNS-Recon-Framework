#!/usr/bin/env python3

import os
import sys
import socket
import logging
from typing import Tuple, Optional

logger = logging.getLogger(__name__)

def check_privileges() -> Tuple[bool, str]:
    """
    Check if the script has the required privileges.
    Returns:
        Tuple[bool, str]: (has_privileges, message)
    """
    try:
        if os.name == 'nt':  # Windows
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin(), "Administrator privileges"
        else:  # Unix/Linux/macOS
            return os.geteuid() == 0, "Root privileges"
    except:
        return False, "Unknown privileges"

def requires_root(func):
    """
    Decorator to check if root/admin privileges are required for a function.
    """
    def wrapper(*args, **kwargs):
        has_privs, priv_type = check_privileges()
        if not has_privs:
            error_msg = f"This operation requires {priv_type}"
            logger.error(error_msg)
            raise PermissionError(error_msg)
        return func(*args, **kwargs)
    return wrapper

def can_bind_socket(port: int) -> bool:
    """
    Check if we can bind to a specific port without root privileges.
    Args:
        port: The port number to test
    Returns:
        bool: True if we can bind to the port, False otherwise
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('127.0.0.1', port))
        sock.close()
        return True
    except:
        return False

def check_operation_requirements(operation: str) -> Tuple[bool, Optional[str]]:
    """
    Check if the current user has sufficient privileges for a specific operation.
    Args:
        operation: The type of operation to check ('raw_socket', 'low_port', 'file_access', etc.)
    Returns:
        Tuple[bool, Optional[str]]: (has_required_privileges, error_message)
    """
    if operation == 'raw_socket':
        try:
            # Try to create a raw socket
            socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            return True, None
        except PermissionError:
            return False, "Raw socket creation requires root privileges"
        except:
            return False, "Unable to create raw socket"
            
    elif operation == 'low_port':
        if can_bind_socket(53):  # Test with DNS port
            return True, None
        return False, "Binding to low ports requires root privileges"
        
    elif operation == 'file_access':
        # Check if we can write to system directories
        try:
            test_file = '/tmp/test_access'
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
            return True, None
        except:
            return False, "Insufficient file access privileges"
            
    return True, None  # Default to allowing the operation

def elevate_privileges() -> bool:
    """
    Attempt to elevate privileges if possible.
    Returns:
        bool: True if successful, False otherwise
    """
    if os.name == 'nt':  # Windows
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
                return True
        except:
            pass
    else:  # Unix/Linux/macOS
        if os.geteuid() != 0:
            try:
                os.execvp('sudo', ['sudo', 'python3'] + sys.argv)
                return True
            except:
                pass
    return False 