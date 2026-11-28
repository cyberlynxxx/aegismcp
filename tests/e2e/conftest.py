"""Conftest for E2E tests."""

from pathlib import Path

import pytest


@pytest.fixture
def e2e_test_dir(tmp_path: Path) -> Path:
    """Create a temporary directory for E2E tests."""
    return tmp_path


@pytest.fixture
def vulnerable_server():
    """Provide a vulnerable MCP server instance."""
    from tests.e2e.servers.vulnerable_server import VulnerableMCPServer
    return VulnerableMCPServer()


@pytest.fixture
def hardened_server():
    """Provide a hardened MCP server instance."""
    from tests.e2e.servers.hardened_server import HardenedMCPServer
    return HardenedMCPServer()


@pytest.fixture
def taint_firewall():
    """Provide a TaintFirewall instance."""
    from aegismcp.taint_firewall import TaintFirewall
    return TaintFirewall()