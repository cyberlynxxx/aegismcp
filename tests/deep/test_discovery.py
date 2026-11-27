"""Deep tests for Discovery module."""
import pytest
import tempfile
from pathlib import Path
from aegismcp.discovery import (
    discover_mcp_files,
    iter_json_files,
    _looks_like_mcp_config,
)

def test_iter_json_files():
    """Test iterating JSON files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        (tmp_path / "a.json").write_text("{}", encoding="utf-8")
        (tmp_path / "b.json").write_text("{}", encoding="utf-8")
        (tmp_path / "subdir").mkdir()
        (tmp_path / "subdir" / "c.json").write_text("{}", encoding="utf-8")
        (tmp_path / "not_json.txt").write_text("text", encoding="utf-8")

        files = list(iter_json_files(tmp_path))
        assert len(files) == 3
        assert all(f.suffix == ".json" for f in files)

def test_iter_json_files_nonexistent():
    """Test iterating non-existent directory."""
    files = list(iter_json_files(Path("nonexistent")))
    assert files == []

def test_looks_like_mcp_config():
    """Test MCP config detection."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        # Valid MCP config
        mcp_file = tmp_path / "mcp.json"
        mcp_file.write_text('{"mcpServers": {}}', encoding="utf-8")
        assert _looks_like_mcp_config(mcp_file) is True

        # Not MCP config
        other_file = tmp_path / "other.json"
        other_file.write_text('{"other": "config"}', encoding="utf-8")
        assert _looks_like_mcp_config(other_file) is False

        # Invalid JSON
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("{ invalid", encoding="utf-8")
        assert _looks_like_mcp_config(bad_file) is False

def test_discover_mcp_files_auto():
    """Test auto-discovery with a local root."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        # Create platform-like config in the temp directory
        config_dir = tmp_path / "Claude"
        config_dir.mkdir()
        (config_dir / "claude_desktop_config.json").write_text(
            '{"mcpServers": {}}', encoding="utf-8"
        )

        files = discover_mcp_files(root=tmp_path, auto_discover=False)
        # Should find the config
        assert any("claude_desktop_config.json" in str(f) for f in files)

def test_discover_mcp_files_no_auto():
    """Test no auto-discovery with non-existent root."""
    files = discover_mcp_files(root=Path("nonexistent_dir"), auto_discover=False)
    assert files == []