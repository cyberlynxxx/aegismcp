"""Pytest configuration and fixtures for AegisMCP tests."""
import pytest
from pathlib import Path
import tempfile
import json
import os

# Add src to path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aegismcp import (
    scan_file,
    scan_directory,
    discover_mcp_files,
    Config,
    Lockfile,
    create_lock_from_config,
    verify_lockfile,
    scan_python_file,
    scan_python_directory,
    export_sarif,
)


@pytest.fixture
def vulnerable_mcp_path():
    """Path to the vulnerable MCP config sample."""
    return Path(__file__).parent.parent / "samples" / "vulnerable_mcp.json"


@pytest.fixture
def test_server_path():
    """Path to the test Python server sample."""
    return Path(__file__).parent.parent / "samples" / "test_server.py"


@pytest.fixture
def clean_config():
    """A clean MCP config without violations."""
    return {
        "mcpServers": {
            "safe-server": {
                "command": "python",
                "args": ["server.py"],
                "env": {}
            }
        }
    }


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmp:
        yield Path(tmp)