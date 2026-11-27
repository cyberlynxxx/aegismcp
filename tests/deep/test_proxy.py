"""Deep tests for Proxy module."""
import tempfile
from pathlib import Path

from aegismcp.proxy import MCPProxy, ProxyConfig
from aegismcp.security import validate_file_size


def test_proxy_config_creation():
    """Test ProxyConfig creation."""
    config = ProxyConfig(
        command=["python", "server.py"],
        bind_host="127.0.0.1",
        bind_port=8080,
        timeout=30.0,
        fail_on="HIGH",
        mode="enforce"
    )
    assert config.bind_host == "127.0.0.1"
    assert config.bind_port == 8080
    assert config.mode == "enforce"

def test_proxy_config_monitor_mode():
    """Test ProxyConfig monitor mode."""
    config = ProxyConfig(
        command=["python", "server.py"],
        mode="monitor"
    )
    assert config.mode == "monitor"

def test_load_policy_config_valid(tmp_path):
    """Test loading valid policy config."""
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("""
block_critical: true
block_high: true
block_medium: false
block_low: false
""", encoding="utf-8")

    config = MCPProxy.load_policy_config(policy_file)
    assert config["block_critical"] is True
    assert config["block_medium"] is False

def test_load_policy_config_nonexistent():
    """Test loading non-existent policy config."""
    config = MCPProxy.load_policy_config(Path("nonexistent.yaml"))
    # Should return empty dict on error
    assert config == {}

def test_load_policy_config_invalid_yaml(tmp_path):
    """Test loading invalid YAML policy config."""
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("invalid: [", encoding="utf-8")

    config = MCPProxy.load_policy_config(policy_file)
    # Should return empty dict on error
    assert config == {}

def test_validate_file_size():
    """Test file size validation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        small_file = tmp_path / "small.txt"
        small_file.write_text("small", encoding="utf-8")

        large_file = tmp_path / "large.txt"
        large_file.write_text("x" * (3 * 1024 * 1024), encoding="utf-8")  # 3MB

        valid, msg = validate_file_size(small_file, max_size=2 * 1024 * 1024)
        assert valid is True
        assert msg == ""

        valid, msg = validate_file_size(large_file, max_size=2 * 1024 * 1024)
        assert valid is False
        assert "exceeds limit" in msg