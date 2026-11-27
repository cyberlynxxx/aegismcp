"""Deep tests for Scanner module."""
import tempfile
from pathlib import Path

from aegismcp.config import Config
from aegismcp.scanner import scan_file


def test_scan_file_nonexistent():
    """Test scanning non-existent file returns AMCP000 finding."""
    config = Config.load(None)
    findings = scan_file(Path("nonexistent.json"), config)
    # Should return AMCP000 finding for unreadable file
    assert len(findings) == 1
    assert findings[0].rule_id == "AMCP000"
    assert findings[0].severity == "LOW"

def test_scan_file_invalid_json():
    """Test scanning invalid JSON."""
    config = Config.load(None)
    with tempfile.TemporaryDirectory() as tmpdir:
        bad_file = Path(tmpdir) / "bad.json"
        bad_file.write_text("{ invalid json", encoding="utf-8")
        findings = scan_file(bad_file, config)
        # Should handle gracefully
        assert isinstance(findings, list)

def test_scan_file_empty():
    """Test scanning empty file."""
    config = Config.load(None)
    with tempfile.TemporaryDirectory() as tmpdir:
        empty_file = Path(tmpdir) / "empty.json"
        empty_file.write_text("{}", encoding="utf-8")
        findings = scan_file(empty_file, config)
        assert isinstance(findings, list)

def test_scan_file_valid_mcp():
    """Test scanning valid MCP config."""
    config = Config.load(None)
    with tempfile.TemporaryDirectory() as tmpdir:
        mcp_file = Path(tmpdir) / "mcp.json"
        mcp_file.write_text('''
{
    "mcpServers": {
        "test": {
            "command": "python",
            "args": ["server.py"]
        }
    }
}
''', encoding="utf-8")
        findings = scan_file(mcp_file, config)
        assert isinstance(findings, list)

def test_scan_file_with_ignore():
    """Test scanning with ignore pattern."""
    config = Config(
        fail_on="HIGH",
        auto_discover=True,
        ignore_paths=["ignored*"]
    )
    with tempfile.TemporaryDirectory() as tmpdir:
        ignored_file = Path(tmpdir) / "ignored.json"
        ignored_file.write_text('{"mcpServers": {}}', encoding="utf-8")
        # Should be ignored
        assert config.should_ignore(ignored_file) is True

        normal_file = Path(tmpdir) / "normal.json"
        normal_file.write_text('{"mcpServers": {}}', encoding="utf-8")
        assert config.should_ignore(normal_file) is False