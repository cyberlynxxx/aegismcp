"""Tests for AST scanner functionality."""
import pytest
from pathlib import Path
import tempfile


class TestASTScanner:
    """Tests for Python AST scanning."""

    def test_ast_scan_test_server(self, test_server_path):
        """Test scanning the sample test server."""
        from aegismcp import scan_python_file

        findings = scan_python_file(test_server_path)

        # Should find at least some vulnerabilities
        rule_ids = {f.rule_id for f in findings}

        # AMCP101 - command injection
        assert "AMCP101" in rule_ids, "AMCP101 should be found"
        # AMCP102 - dynamic code execution (eval/exec)
        # Note: eval/exec might be detected as AMCP101 or AMCP102 depending on implementation
        # AMCP103 - SSRF
        assert "AMCP103" in rule_ids, "AMCP103 (SSRF) should be found"
        # AMCP104 - path traversal
        assert "AMCP104" in rule_ids, "AMCP104 (Path Traversal) should be found"
        # AMCP105 - insecure deserialization
        assert "AMCP105" in rule_ids, "AMCP105 (Insecure Deserialization) should be found"

    def test_ast_scan_clean_file(self, temp_dir):
        """Test scanning a clean Python file."""
        from aegismcp import scan_python_file

        clean_code = '''
def safe_function():
    """A safe function."""
    return "hello"

class SafeClass:
    def method(self):
        return 42
'''
        clean_file = temp_dir / "clean.py"
        clean_file.write_text(clean_code)

        findings = scan_python_file(clean_file)
        assert len(findings) == 0, f"Clean file should have no findings: {findings}"

    def test_ast_scan_excludes_tests_by_default(self, temp_dir):
        """Test that test files are excluded by default in directory scan."""
        from aegismcp import scan_python_directory

        # Create a test file
        test_code = '''
import subprocess
subprocess.run("rm -rf /", shell=True)  # Dangerous but in test file
'''
        test_file = temp_dir / "test_dangerous.py"
        test_file.write_text(test_code)

        # Create a non-test file with same code
        prod_file = temp_dir / "server.py"
        prod_file.write_text(test_code)

        # Default scan should only find in prod file
        findings = scan_python_directory(temp_dir)
        rule_ids = {f.rule_id for f in findings}
        files = {f.file_path.name for f in findings}

        assert "AMCP101" in rule_ids
        assert "server.py" in files
        assert "test_dangerous.py" not in files, "Test files should be excluded by default"

    def test_ast_scan_include_tests_flag(self, temp_dir):
        """Test --include-tests includes test files."""
        from aegismcp import scan_python_directory

        test_code = '''
import subprocess
subprocess.run("rm -rf /", shell=True)
'''
        test_file = temp_dir / "test_dangerous.py"
        test_file.write_text(test_code)

        prod_file = temp_dir / "server.py"
        prod_file.write_text(test_code)

        # With include_tests=True, should find in both
        findings = scan_python_directory(temp_dir, include_tests=True)
        files = {f.file_path.name for f in findings}

        assert "server.py" in files
        assert "test_dangerous.py" in files, "Test files should be included with include_tests=True"

    def test_ast_scan_excludes_test_directory(self, temp_dir):
        """Test that tests/ directory is excluded by default."""
        from aegismcp import scan_python_directory

        # Create tests/ directory
        tests_dir = temp_dir / "tests"
        tests_dir.mkdir()

        test_code = '''
import subprocess
subprocess.run("rm -rf /", shell=True)
'''
        (tests_dir / "test_something.py").write_text(test_code)
        (temp_dir / "server.py").write_text(test_code)

        findings = scan_python_directory(temp_dir)
        files = {f.file_path.name for f in findings}

        assert "server.py" in files
        # test_something.py should be excluded because it's in tests/ directory
        test_findings = [f for f in findings if "test_something" in f.file_path.name]
        assert len(test_findings) == 0, "Files in tests/ directory should be excluded"

    def test_ast_scan_amcp101_shell_true(self, temp_dir):
        """Test AMCP101 detects shell=True."""
        from aegismcp import scan_python_file

        code = '''
import subprocess
subprocess.run("ls -la", shell=True)
'''
        f = temp_dir / "test.py"
        f.write_text(code)

        findings = scan_python_file(f)
        rule_ids = {f.rule_id for f in findings}
        assert "AMCP101" in rule_ids

    def test_ast_scan_amcp101_dynamic_args(self, temp_dir):
        """Test AMCP101 detects dynamic command arguments."""
        from aegismcp import scan_python_file

        code = '''
import subprocess
user_input = "ls"
subprocess.run([user_input, "-la"])
'''
        f = temp_dir / "test.py"
        f.write_text(code)

        findings = scan_python_file(f)
        rule_ids = {f.rule_id for f in findings}
        assert "AMCP101" in rule_ids

    def test_ast_scan_amcp102_eval_exec(self, temp_dir):
        """Test AMCP102 detects eval/exec."""
        from aegismcp import scan_python_file

        code = '''
user_code = "print('hello')"
eval(user_code)
exec(user_code)
'''
        f = temp_dir / "test.py"
        f.write_text(code)

        findings = scan_python_file(f)
        rule_ids = {f.rule_id for f in findings}
        assert "AMCP102" in rule_ids

    def test_ast_scan_amcp103_ssrf(self, temp_dir):
        """Test AMCP103 detects SSRF."""
        from aegismcp import scan_python_file

        code = '''
import requests
user_url = "http://internal-api/admin"
requests.get(user_url)
'''
        f = temp_dir / "test.py"
        f.write_text(code)

        findings = scan_python_file(f)
        rule_ids = {f.rule_id for f in findings}
        assert "AMCP103" in rule_ids

    def test_ast_scan_amcp104_path_traversal(self, temp_dir):
        """Test AMCP104 detects path traversal with user input."""
        from aegismcp import scan_python_file

        code = '''
user_path = "../../../etc/passwd"
with open(user_path) as f:
    pass
'''
        f = temp_dir / "test.py"
        f.write_text(code)

        findings = scan_python_file(f)
        rule_ids = {f.rule_id for f in findings}
        assert "AMCP104" in rule_ids

    def test_ast_scan_amcp104_safe_literal_path(self, temp_dir):
        """Test AMCP104 does NOT flag safe literal paths."""
        from aegismcp import scan_python_file

        code = '''
# These should NOT trigger AMCP104
with open("config.json") as f:
    pass
with open("data/file.txt") as f:
    pass
from pathlib import Path
Path("safe.txt").write_text("hello")
'''
        f = temp_dir / "test.py"
        f.write_text(code)

        findings = scan_python_file(f)
        rule_ids = {f.rule_id for f in findings}
        assert "AMCP104" not in rule_ids, f"Safe literal paths should not trigger AMCP104: {findings}"

    def test_ast_scan_amcp104_f_string_path(self, temp_dir):
        """Test AMCP104 detects f-string paths."""
        from aegismcp import scan_python_file

        code = '''
user_input = "data.txt"
with open(f"uploads/{user_input}") as f:
    pass
'''
        f = temp_dir / "test.py"
        f.write_text(code)

        findings = scan_python_file(f)
        rule_ids = {f.rule_id for f in findings}
        assert "AMCP104" in rule_ids

    def test_ast_scan_amcp105_pickle(self, temp_dir):
        """Test AMCP105 detects pickle.loads."""
        from aegismcp import scan_python_file

        code = '''
import pickle
data = b"malicious"
pickle.loads(data)
'''
        f = temp_dir / "test.py"
        f.write_text(code)

        findings = scan_python_file(f)
        rule_ids = {f.rule_id for f in findings}
        assert "AMCP105" in rule_ids

    def test_ast_scan_amcp105_yaml_unsafe(self, temp_dir):
        """Test AMCP105 detects yaml.load without SafeLoader."""
        from aegismcp import scan_python_file

        code = '''
import yaml
yaml.load("!!python/object/apply:os.system ['rm -rf /']")
'''
        f = temp_dir / "test.py"
        f.write_text(code)

        findings = scan_python_file(f)
        rule_ids = {f.rule_id for f in findings}
        assert "AMCP105" in rule_ids

    def test_ast_scan_amcp105_yaml_safe_loader_ok(self, temp_dir):
        """Test AMCP105 allows yaml.load with SafeLoader."""
        from aegismcp import scan_python_file

        code = '''
import yaml
yaml.load(data, Loader=yaml.SafeLoader)
'''
        f = temp_dir / "test.py"
        f.write_text(code)

        findings = scan_python_file(f)
        rule_ids = {f.rule_id for f in findings}
        assert "AMCP105" not in rule_ids, "yaml.load with SafeLoader should be allowed"

    def test_ast_scan_sarif_export(self, test_server_path, temp_dir):
        """Test SARIF export from AST findings."""
        from aegismcp import scan_python_file, export_sarif
        from aegismcp.rules_core import Finding

        findings = scan_python_file(test_server_path)

        # Convert to Findings for SARIF
        sarif_findings = [
            Finding(
                rule_id=f.rule_id,
                severity=f.severity,
                title=f.title,
                message=f.message,
                location=f"{f.file_path}:{f.line}:{f.column}",
                remediation=f.remediation,
            )
            for f in findings
        ]

        sarif_path = temp_dir / "ast_report.sarif"
        export_sarif(sarif_findings, sarif_path)

        assert sarif_path.exists()

        import json
        sarif_data = json.loads(sarif_path.read_text())
        assert sarif_data["version"] == "2.1.0"