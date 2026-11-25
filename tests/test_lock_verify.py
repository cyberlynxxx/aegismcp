"""Tests for lock and verify commands."""
import json


class TestLockVerify:
    """Tests for lock and verify functionality."""

    def test_lock_creates_lockfile(self, vulnerable_mcp_path, temp_dir):
        """Test that lock command creates a valid lockfile."""
        from aegismcp import create_lock_from_config

        lockfile = create_lock_from_config(vulnerable_mcp_path)

        assert lockfile is not None
        assert len(lockfile.servers) == 2  # unsafe-shell and filesystem
        assert "unsafe-shell" in lockfile.servers
        assert "filesystem" in lockfile.servers

        # Each server should have a config hash
        for server in lockfile.servers.values():
            assert hasattr(server, "config_hash")
            assert len(server.config_hash) == 64  # SHA-256 hex

    def test_lock_save_and_load(self, vulnerable_mcp_path, temp_dir):
        """Test saving and loading a lockfile."""
        from aegismcp import Lockfile, create_lock_from_config

        lockfile = create_lock_from_config(vulnerable_mcp_path)
        lock_path = temp_dir / "test.lock.json"
        lockfile.save(lock_path)

        assert lock_path.exists()

        loaded = Lockfile.load(lock_path)
        assert len(loaded.servers) == len(lockfile.servers)
        for name in lockfile.servers:
            assert loaded.servers[name].config_hash == lockfile.servers[name].config_hash

    def test_verify_matching_config(self, vulnerable_mcp_path, temp_dir):
        """Test verify with matching config passes."""
        from aegismcp import create_lock_from_config, verify_lockfile

        lockfile = create_lock_from_config(vulnerable_mcp_path)
        lock_path = temp_dir / "test.lock.json"
        lockfile.save(lock_path)

        violations = verify_lockfile(lockfile, vulnerable_mcp_path)
        assert len(violations) == 0, f"Matching config should have no violations: {violations}"

    def test_verify_modified_config_fails(self, vulnerable_mcp_path, temp_dir):
        """Test verify catches modified config."""
        from aegismcp import Lockfile, create_lock_from_config, verify_lockfile

        lockfile = create_lock_from_config(vulnerable_mcp_path)
        lock_path = temp_dir / "test.lock.json"
        lockfile.save(lock_path)

        # Modify the config
        data = json.loads(vulnerable_mcp_path.read_text())
        data["mcpServers"]["unsafe-shell"]["args"] = ["modified_arg"]
        modified_path = temp_dir / "modified_mcp.json"
        modified_path.write_text(json.dumps(data))

        # Load lockfile and verify against modified config
        loaded_lockfile = Lockfile.load(lock_path)
        violations = verify_lockfile(loaded_lockfile, modified_path)

        assert len(violations) > 0, "Modified config should have violations"
        # Should detect config hash mismatch (type is "config_changed")
        types = {v["type"] for v in violations}
        assert "config_changed" in types

    def test_verify_missing_server(self, vulnerable_mcp_path, temp_dir):
        """Test verify catches missing server."""
        from aegismcp import Lockfile, create_lock_from_config, verify_lockfile

        lockfile = create_lock_from_config(vulnerable_mcp_path)
        lock_path = temp_dir / "test.lock.json"
        lockfile.save(lock_path)

        # Create config with missing server
        data = json.loads(vulnerable_mcp_path.read_text())
        del data["mcpServers"]["unsafe-shell"]
        modified_path = temp_dir / "modified_mcp.json"
        modified_path.write_text(json.dumps(data))

        loaded_lockfile = Lockfile.load(lock_path)
        violations = verify_lockfile(loaded_lockfile, modified_path)

        assert len(violations) > 0
        types = {v["type"] for v in violations}
        assert "server_removed" in types

    def test_verify_new_server(self, vulnerable_mcp_path, temp_dir):
        """Test verify catches new server not in lockfile."""
        from aegismcp import Lockfile, create_lock_from_config, verify_lockfile

        lockfile = create_lock_from_config(vulnerable_mcp_path)
        lock_path = temp_dir / "test.lock.json"
        lockfile.save(lock_path)

        # Create config with new server
        data = json.loads(vulnerable_mcp_path.read_text())
        data["mcpServers"]["new-server"] = {
            "command": "python",
            "args": ["server.py"]
        }
        modified_path = temp_dir / "modified_mcp.json"
        modified_path.write_text(json.dumps(data))

        loaded_lockfile = Lockfile.load(lock_path)
        violations = verify_lockfile(loaded_lockfile, modified_path)

        assert len(violations) > 0
        types = {v["type"] for v in violations}
        assert "server_added" in types