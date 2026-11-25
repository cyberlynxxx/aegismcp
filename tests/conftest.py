"""Pytest configuration and fixtures for AegisMCP tests."""

# Add src to path
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))



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
                "env": {
                    "RATE_LIMIT": "100/minute"
                }
            }
        }
    }


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmp:
        yield Path(tmp)