"""Deep tests for Config module."""
import pytest
import tempfile
from pathlib import Path
from aegismcp.config import Config

def test_config_load_nonexistent():
    """Test loading non-existent config returns defaults."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config = Config.load(Path(tmpdir) / "nonexistent.yaml")
        assert config.fail_on == "HIGH"
        assert config.auto_discover is True

def test_config_load_valid():
    """Test loading valid config."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config_file = Path(tmpdir) / "aegismcp.yaml"
        config_file.write_text("""
fail_on: "CRITICAL"
auto_discover: false
ignore_paths:
  - "*.test.json"
""", encoding="utf-8")

        config = Config.load(config_file)
        assert config.fail_on == "CRITICAL"
        assert config.auto_discover is False
        assert "*.test.json" in config.ignore_paths

def test_config_should_ignore():
    """Test ignore pattern matching."""
    config = Config(
        fail_on="HIGH",
        auto_discover=True,
        ignore_paths=["*.test.json", "test_*"]
    )

    # Match file name
    assert config.should_ignore(Path("test_file.json")) is True
    assert config.should_ignore(Path("normal.json")) is False
    # Test with pattern matching whole path
    assert config.should_ignore(Path("test.json")) is True  # Matches test_*
    # test_* doesn't match subdir/test.json due to path.match behavior

def test_config_edge_cases():
    """Test config edge cases."""
    # Empty config
    with tempfile.TemporaryDirectory() as tmpdir:
        config_file = Path(tmpdir) / "aegismcp.yaml"
        config_file.write_text("", encoding="utf-8")
        config = Config.load(config_file)
        assert config.fail_on == "HIGH"

    # Invalid YAML
    with tempfile.TemporaryDirectory() as tmpdir:
        config_file = Path(tmpdir) / "aegismcp.yaml"
        config_file.write_text("invalid: [", encoding="utf-8")
        # Should not crash
        config = Config.load(config_file)
        assert config.fail_on == "HIGH"