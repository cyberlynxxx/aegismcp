"""Tests for the --version CLI command."""

import subprocess
import sys
from pathlib import Path


def test_version_flag_short():
    """Test -V flag outputs version."""
    result = subprocess.run(
        [sys.executable, "-m", "aegismcp", "-V"],
        capture_output=True,
        text=True,
        check=False,
        cwd=Path(__file__).parent.parent,
    )
    assert result.returncode == 0
    assert "aegismcp " in result.stdout.strip()


def test_version_flag_long():
    """Test --version flag outputs version."""
    result = subprocess.run(
        [sys.executable, "-m", "aegismcp", "--version"],
        capture_output=True,
        text=True,
        check=False,
        cwd=Path(__file__).parent.parent,
    )
    assert result.returncode == 0
    assert "aegismcp " in result.stdout.strip()


def test_version_format():
    """Test version output follows semantic versioning format."""
    result = subprocess.run(
        [sys.executable, "-m", "aegismcp", "--version"],
        capture_output=True,
        text=True,
        check=False,
        cwd=Path(__file__).parent.parent,
    )
    assert result.returncode == 0
    version_output = result.stdout.strip()
    # Should be like "aegismcp 3.1.1"
    assert version_output.startswith("aegismcp ")
    version_str = version_output[len("aegismcp "):]
    # Basic semver check (major.minor.patch)
    parts = version_str.split(".")
    assert len(parts) == 3
    for part in parts:
        assert part.isdigit() or (part and part[0].isdigit())