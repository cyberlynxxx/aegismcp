"""Deep tests for Lockfile module."""
import pytest
import tempfile
from pathlib import Path
from aegismcp.lockfile import (
    Lockfile,
    create_lock_from_config,
    verify_lockfile,
    compute_server_config_hash,
)

def test_lockfile_create():
    """Test creating lockfile from config."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        config_file = tmp_path / "mcp.json"
        config_file.write_text('''
{
    "mcpServers": {
        "test": {
            "command": "python",
            "args": ["server.py"]
        }
    }
}
''', encoding="utf-8")

        lockfile = create_lock_from_config(config_file)
        assert len(lockfile.servers) == 1
        assert "test" in lockfile.servers
        assert lockfile.servers["test"].config_hash is not None

def test_lockfile_save_load():
    """Test saving and loading lockfile."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        config_file = tmp_path / "mcp.json"
        config_file.write_text('{"mcpServers": {}}', encoding="utf-8")

        lockfile = create_lock_from_config(config_file)
        lock_path = tmp_path / "lock.json"
        lockfile.save(lock_path)

        loaded = Lockfile.load(lock_path)
        assert len(loaded.servers) == len(lockfile.servers)

def test_lockfile_verify_match():
    """Test verifying matching config."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        config_file = tmp_path / "mcp.json"
        config_file.write_text('{"mcpServers": {"srv": {"command": "python"}}}', encoding="utf-8")

        lockfile = create_lock_from_config(config_file)
        lock_path = tmp_path / "lock.json"
        lockfile.save(lock_path)

        violations = verify_lockfile(lockfile, config_file)
        assert violations == []

def test_lockfile_verify_mismatch():
    """Test verifying mismatched config."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        config_file = tmp_path / "mcp.json"
        config_file.write_text('{"mcpServers": {"srv": {"command": "python"}}}', encoding="utf-8")

        lockfile = create_lock_from_config(config_file)
        lock_path = tmp_path / "lock.json"
        lockfile.save(lock_path)

        # Modify config
        config_file.write_text('{"mcpServers": {"srv": {"command": "node"}}}', encoding="utf-8")

        violations = verify_lockfile(lockfile, config_file)
        assert len(violations) > 0

def test_compute_config_hash():
    """Test config hash computation."""
    config1 = {"command": "python", "args": [], "env": {}, "url": None}
    config2 = {"command": "python", "args": [], "env": {}, "url": None}
    config3 = {"command": "node", "args": [], "env": {}, "url": None}

    hash1 = compute_server_config_hash(config1)
    hash2 = compute_server_config_hash(config2)
    hash3 = compute_server_config_hash(config3)

    assert hash1 == hash2  # Same config = same hash
    assert hash1 != hash3  # Different config = different hash

def test_lockfile_invalid_json():
    """Test lockfile with invalid JSON returns empty lockfile."""
    with tempfile.TemporaryDirectory() as tmpdir:
        lock_path = Path(tmpdir) / "lock.json"
        lock_path.write_text("{ invalid", encoding="utf-8")

        # Should not raise, returns empty Lockfile
        lockfile = Lockfile.load(lock_path)
        assert lockfile.servers == {}