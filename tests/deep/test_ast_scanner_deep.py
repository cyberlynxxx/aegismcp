"""Deep tests for AST Scanner module."""
import pytest
import tempfile
from pathlib import Path
from aegismcp.ast_scanner import (
    scan_python_file,
    scan_python_directory,
    _is_test_file,
    _is_in_test_dir,
)

def test_scan_python_file_nonexistent():
    """Test scanning non-existent Python file."""
    findings = scan_python_file(Path("nonexistent.py"))
    assert findings == []

def test_scan_python_file_invalid():
    """Test scanning invalid Python file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        bad_file = Path(tmpdir) / "bad.py"
        bad_file.write_text("def foo(:\n    pass", encoding="utf-8")
        findings = scan_python_file(bad_file)
        # Should handle syntax errors gracefully
        assert isinstance(findings, list)

def test_scan_python_file_empty():
    """Test scanning empty Python file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        empty_file = Path(tmpdir) / "empty.py"
        empty_file.write_text("", encoding="utf-8")
        findings = scan_python_file(empty_file)
        assert findings == []

def test_scan_python_directory_nonexistent():
    """Test scanning non-existent directory."""
    findings = scan_python_directory(Path("nonexistent"))
    assert findings == []

def test_scan_python_directory():
    """Test scanning Python directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        (tmp_path / "main.py").write_text("""
import subprocess
def run_cmd(cmd):
    subprocess.run(cmd, shell=True)
""", encoding="utf-8")
        (tmp_path / "utils.py").write_text("""
def safe():
    print("safe")
""", encoding="utf-8")

        findings = scan_python_directory(tmp_path)
        assert isinstance(findings, list)

def test_taint_tracker_basic():
    """Test basic taint tracking via scan_python_file."""
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "test_taint.py"
        test_file.write_text("""
user_input = input()
eval(user_input)
""", encoding="utf-8")

        findings = scan_python_file(test_file)
        # Should detect tainted eval (AMCP102 for eval)
        assert len(findings) > 0
        assert any(f.rule_id == "AMCP102" for f in findings)

def test_taint_tracker_safe_path():
    """Test safe path detection via scan_python_file."""
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "test_safe.py"
        test_file.write_text("""
from pathlib import Path
p = Path("safe.txt")
p.read_text()
""", encoding="utf-8")

        findings = scan_python_file(test_file)
        # Path() with literal should not trigger AMCP104
        amcp104 = [f for f in findings if f.rule_id == "AMCP104"]
        assert len(amcp104) == 0

def test_is_user_controlled_path():
    """Test user controlled path detection."""
    import ast
    from aegismcp.ast_scanner import PythonASTVisitor

    visitor = PythonASTVisitor(Path("test.py"))

    # Literal path - not user controlled
    literal = ast.Constant(value="safe.txt")
    assert visitor._is_user_controlled_path(literal) is False

    # Variable - user controlled
    name = ast.Name(id="user_path", ctx=ast.Load())
    assert visitor._is_user_controlled_path(name) is True

def test_is_test_file():
    """Test test file detection."""
    assert _is_test_file(Path("test_foo.py")) is True
    assert _is_test_file(Path("foo_test.py")) is True
    assert _is_test_file(Path("normal.py")) is False

def test_is_in_test_dir():
    """Test test directory detection."""
    assert _is_in_test_dir(Path("tests/test_foo.py")) is True
    assert _is_in_test_dir(Path("test/foo.py")) is True
    assert _is_in_test_dir(Path("src/main.py")) is False