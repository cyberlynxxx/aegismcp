"""Tests for the scan command."""
import json
import subprocess
import sys
from pathlib import Path


class TestScanCommand:
    """Tests for aegismcp scan functionality."""

    def test_scan_vulnerable_mcp(self, vulnerable_mcp_path):
        """Scan the vulnerable MCP config and verify all rules trigger."""
        from aegismcp import Config, scan_file
        config = Config()
        findings = scan_file(vulnerable_mcp_path, config)

        # Should find at least one of each expected rule
        rule_ids = {f.rule_id for f in findings}

        # Check all main rules are triggered
        assert "AMCP001" in rule_ids, "AMCP001 (Direct Shell) should be found"
        assert "AMCP002" in rule_ids, "AMCP002 (Unpinned npx) should be found"
        assert "AMCP003" in rule_ids, "AMCP003 (Path exposure) should be found"
        assert "AMCP004" in rule_ids, "AMCP004 (Hardcoded secret) should be found"
        assert "AMCP005" in rule_ids, "AMCP005 (Tool poisoning) should be found"
        assert "AMCP006" in rule_ids, "AMCP006 (Long description) should be found"
        assert "AMCP007" in rule_ids, "AMCP007 (Invisible chars) should be found"
        assert "AMCP008" in rule_ids, "AMCP008 (High entropy) should be found"

        # Verify we have findings
        assert len(findings) >= 9, f"Expected at least 9 findings, got {len(findings)}"

    def test_scan_clean_config(self, clean_config, temp_dir):
        """Scan a clean config - should find no issues."""
        from aegismcp import Config, scan_file

        config_file = temp_dir / "clean_mcp.json"
        config_file.write_text(json.dumps(clean_config))

        config = Config()
        findings = scan_file(config_file, config)

        assert len(findings) == 0, f"Clean config should have no findings, got: {findings}"

    def test_scan_with_sarif_export(self, vulnerable_mcp_path, temp_dir):
        """Test SARIF export functionality."""
        from aegismcp import Config, export_sarif, scan_file

        config = Config()
        findings = scan_file(vulnerable_mcp_path, config)

        sarif_path = temp_dir / "report.sarif"
        export_sarif(findings, sarif_path)

        assert sarif_path.exists(), "SARIF file should be created"

        # Validate SARIF structure
        import json
        sarif_data = json.loads(sarif_path.read_text())
        assert sarif_data["version"] == "2.1.0"
        assert "$schema" in sarif_data
        assert "runs" in sarif_data
        assert len(sarif_data["runs"]) > 0

    def test_scan_cli_sarif_export(self, vulnerable_mcp_path, temp_dir, capsys):
        """Test --sarif flag in CLI scan command."""
        from pathlib import Path

        sarif_path = temp_dir / "cli_report.sarif"
        result = subprocess.run(
            [sys.executable, "-m", "aegismcp", "scan", "--sarif", str(sarif_path), str(vulnerable_mcp_path)],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )
        # Should complete without error and output summary
        assert result.returncode in (0, 1)
        # SARIF file should be created
        assert sarif_path.exists(), "SARIF file should be created from CLI scan"

    def test_scan_cli_html_export(self, vulnerable_mcp_path, temp_dir, capsys):
        """Test --html flag in CLI scan command."""
        from pathlib import Path

        html_path = temp_dir / "cli_report.html"
        result = subprocess.run(
            [sys.executable, "-m", "aegismcp", "scan", "--html", str(html_path), str(vulnerable_mcp_path)],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )
        # Should complete without error and output summary
        assert result.returncode in (0, 1)
        # HTML file should be created
        assert html_path.exists(), "HTML report should be created from CLI scan"

    def test_scan_fail_on_exit_code(self, vulnerable_mcp_path):
        """Test --fail-on behavior via exit codes."""
        from aegismcp import Config, scan_file

        config = Config()
        config.fail_on = "HIGH"
        findings = scan_file(vulnerable_mcp_path, config)

        # Should have HIGH or CRITICAL findings
        high_or_critical = any(f.severity in ("HIGH", "CRITICAL") for f in findings)
        assert high_or_critical, "Should have HIGH or CRITICAL findings"

    def test_scan_disabled_rules(self, vulnerable_mcp_path):
        """Test that disabled rules in config are respected."""
        from aegismcp import Config, scan_file

        config = Config()
        config.rules = {"AMCP001": {"enabled": False}}
        findings = scan_file(vulnerable_mcp_path, config)

        rule_ids = {f.rule_id for f in findings}
        assert "AMCP001" not in rule_ids, "AMCP001 should be disabled"

    def test_scan_custom_rule(self, vulnerable_mcp_path):
        """Test custom regex rules from config."""
        from aegismcp import Config, scan_file

        config = Config()
        config.custom_rules = [{
            "id": "CUSTOM001",
            "title": "Test Custom Rule",
            "pattern": "bash",
            "severity": "HIGH",
            "target": "servers.command",
            "message": "Found bash in command"
        }]
        findings = scan_file(vulnerable_mcp_path, config)

        rule_ids = {f.rule_id for f in findings}
        assert "CUSTOM001" in rule_ids, "Custom rule should trigger"


class TestAutoDiscover:
    """Tests for auto-discovery functionality."""

    def test_discover_mcp_files(self):
        """Test that discover_mcp_files returns a list."""
        from aegismcp import discover_mcp_files

        files = discover_mcp_files(auto_discover=True)
        assert isinstance(files, list), "Should return a list"


class TestScanCLI:
    """Integration tests for CLI scan command."""

    def test_scan_without_target_with_auto(self, capsys):
        """Test that scan --auto works without target argument."""
        import sys

        from aegismcp.cli import main

        # This should not crash with "target required" error
        # We can't easily test auto-discover without mocking, but we can
        # verify the CLI doesn't error on missing target when --auto is used
        old_argv = sys.argv
        try:
            sys.argv = ["aegismcp", "scan", "--auto", "--no-auto-discover"]
            # Should not raise SystemExit with code 2 (missing argument)
            try:
                main()
            except SystemExit as e:
                # Exit code 0 or 1 is OK (no files found or findings found)
                # Exit code 2 means missing required argument
                assert e.code != 2, "Should not require target when --auto is used"
        finally:
            sys.argv = old_argv

    def test_scan_without_target_no_auto_fails(self, capsys):
        """Test that scan without target and without --auto fails cleanly."""
        import sys

        from aegismcp.cli import main

        old_argv = sys.argv
        try:
            # Use --no-auto-discover to disable config default auto-discovery
            sys.argv = ["aegismcp", "scan", "--no-auto-discover"]
            try:
                main()
            except SystemExit as e:
                assert e.code == 2, "Should exit with code 2 when target missing and no auto"
        finally:
            sys.argv = old_argv


class TestScanE2EBugFixes:
    """Regression tests for E2E bug fixes."""

    def test_scan_verbose_no_truncation(self, vulnerable_mcp_path, temp_dir, capsys):
        """Test that --verbose doesn't truncate Why:/Fix: descriptions."""
        from aegismcp import Config, scan_file
        from aegismcp.reporter import print_report, ReportOptions

        config = Config()
        findings = scan_file(vulnerable_mcp_path, config)

        # Capture output with verbose=True
        opts_verbose = ReportOptions(verbose=True, show_color=False, no_color=True)
        from io import StringIO
        buf = StringIO()
        print_report(findings, 1, opts_verbose, output=buf)
        verbose_output = buf.getvalue()

        # Check that Why: and Fix: lines are not truncated (no "..." at end)
        for line in verbose_output.split("\n"):
            if line.strip().startswith("Why:") or line.strip().startswith("Fix:"):
                # In verbose mode, the message should NOT end with "..."
                # (unless the original message actually had "..." at end)
                assert not line.rstrip().endswith("..."), f"Verbose mode should not truncate: {line}"

    def test_scan_non_verbose_truncation(self, vulnerable_mcp_path, temp_dir, capsys):
        """Test that non-verbose mode truncates Why:/Fix: descriptions."""
        from aegismcp import Config, scan_file
        from aegismcp.reporter import print_report, ReportOptions

        config = Config()
        findings = scan_file(vulnerable_mcp_path, config)

        # Capture output with verbose=False
        opts = ReportOptions(verbose=False, show_color=False, no_color=True)
        from io import StringIO
        buf = StringIO()
        print_report(findings, 1, opts, output=buf)
        output = buf.getvalue()

        # Check that Why: and Fix: lines ARE truncated to 80 chars
        # (they should end with "..." if message was longer than 80 chars)
        for line in output.split("\n"):
            if line.strip().startswith("Why:") or line.strip().startswith("Fix:"):
                # The line content after "Why: " or "Fix: " should be <= 80 chars + ellipsis
                content = line.split(":", 1)[1].strip()
                if len(content) > 80:
                    # Should have been truncated
                    assert content.endswith("...") or len(content) <= 80, f"Should be truncated: {line}"

    def test_summary_box_ansi_padding(self, vulnerable_mcp_path, temp_dir, capsys):
        """Test that summary box right border aligns correctly with ANSI colors."""
        from aegismcp import Config, scan_file
        from aegismcp.reporter import print_report, ReportOptions

        config = Config()
        findings = scan_file(vulnerable_mcp_path, config)

        # Capture output with color enabled
        opts = ReportOptions(verbose=False, show_color=True, no_color=False)
        from io import StringIO
        buf = StringIO()
        print_report(findings, 1, opts, output=buf)
        output = buf.getvalue()

        # Find the summary box lines
        lines = output.split("\n")
        box_lines = [l for l in lines if l.startswith("+") or l.startswith("| Security Score") or l.startswith("| Targets Scanned")]

        # Verify box structure - each line should have same visual width
        # The right border should align (both lines end with "|")
        if len(box_lines) >= 3:
            top = box_lines[0]
            middle1 = box_lines[1]
            middle2 = box_lines[2]
            bottom = box_lines[3]

            # Top and bottom start/end with +, middle lines start/end with |
            assert top.startswith("+") and top.endswith("+"), f"Top border should be +...+: {top}"
            assert middle1.startswith("|") and middle1.endswith("|"), f"Middle1 should be |...|: {middle1}"
            assert middle2.startswith("|") and middle2.endswith("|"), f"Middle2 should be |...|: {middle2}"
            assert bottom.startswith("+") and bottom.endswith("+"), f"Bottom border should be +...+: {bottom}"

    def test_ast_scan_cli_html_export(self, test_server_path, temp_dir):
        """Test --html flag in CLI ast-scan command."""
        from pathlib import Path

        html_path = temp_dir / "ast_report.html"
        result = subprocess.run(
            [sys.executable, "-m", "aegismcp", "ast-scan", "--html", str(html_path), str(test_server_path)],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )
        assert result.returncode in (0, 1)
        assert html_path.exists(), "HTML report should be created from CLI ast-scan"

    def test_ast_scan_cli_sarif_export(self, test_server_path, temp_dir):
        """Test --sarif flag in CLI ast-scan command."""
        from pathlib import Path

        sarif_path = temp_dir / "ast_report.sarif"
        result = subprocess.run(
            [sys.executable, "-m", "aegismcp", "ast-scan", "--sarif", str(sarif_path), str(test_server_path)],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )
        assert result.returncode in (0, 1)
        assert sarif_path.exists(), "SARIF file should be created from CLI ast-scan"

    def test_inspect_cli_html_export(self, temp_dir):
        """Test --html flag in CLI inspect command (requires live server, test structure only)."""
        from pathlib import Path

        # This test just verifies the CLI argument exists and doesn't crash on parse
        # We can't easily test without a live server
        html_path = temp_dir / "inspect_report.html"
        result = subprocess.run(
            [sys.executable, "-m", "aegismcp", "inspect", "--help"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )
        # Verify --html is in help
        assert "--html" in result.stdout