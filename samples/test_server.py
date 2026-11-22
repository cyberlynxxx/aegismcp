"""Test MCP server with vulnerabilities for AST scanning."""
import subprocess
import os
import pickle
import yaml
import requests


def unsafe_shell(user_input: str) -> str:
    """Vulnerable to command injection."""
    # AMCP101: Direct shell execution with user input
    result = subprocess.run(f"echo {user_input}", shell=True, capture_output=True, text=True)
    return result.stdout


def unsafe_subprocess(user_input: str) -> str:
    """Vulnerable to command injection via subprocess."""
    # AMCP101: subprocess with shell=True and dynamic command
    result = subprocess.run(["bash", "-c", f"echo {user_input}"], capture_output=True, text=True)
    return result.stdout


def safe_subprocess(user_input: str) -> str:
    """Safe subprocess usage."""
    # This should NOT trigger - shell=False, args as list
    result = subprocess.run(["echo", user_input], capture_output=True, text=True)
    return result.stdout


def ssrf_vulnerable(url: str) -> str:
    """Potential SSRF - user-controlled URL."""
    # AMCP103: HTTP request to user-controlled URL
    response = requests.get(url)
    return response.text


def path_traversal_vulnerable(filename: str) -> str:
    """Potential path traversal."""
    # AMCP104: File operation with user-controlled path
    with open(filename, "r") as f:
        return f.read()


def unsafe_deserialization(data: bytes) -> object:
    """Insecure deserialization."""
    # AMCP105: pickle.loads
    return pickle.loads(data)


def unsafe_yaml_load(data: str) -> object:
    """Unsafe YAML loading."""
    # AMCP105: yaml.load without SafeLoader
    return yaml.load(data)


# This should be safe
def safe_yaml_load(data: str) -> object:
    """Safe YAML loading."""
    return yaml.safe_load(data)


# Safe function - no issues
def safe_function(user_input: str) -> str:
    """Completely safe function."""
    return f"Hello, {user_input}!"