from pathlib import Path

import pytest

from aegismcp.security import safe_json_load


def test_safe_json_load_size_limit():
    """Test that safe_json_load respects size limits."""
    # Create a dummy large file with valid JSON
    large_file = Path("test_large.json")
    large_json = '{"a": "' + 'b' * 2000 + '"}'
    large_file.write_text(large_json, encoding="utf-8")

    with pytest.raises(ValueError, match="exceeds maximum"):
        safe_json_load(large_file, max_size=1024)  # 1KB limit

    large_file.unlink()

def test_safe_json_load_valid():
    """Test valid JSON loading."""
    valid_file = Path("test_valid.json")
    valid_file.write_text('{"key": "value"}', encoding="utf-8")

    data = safe_json_load(valid_file)
    assert data == {"key": "value"}

    valid_file.unlink()
