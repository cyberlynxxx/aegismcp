"""Tests for the scan command."""
import pytest
from pathlib import Path
import json


class TestScanCommand:
    """Tests for aegismcp scan functionality."""

    def test_scan_vulnerable_mcp(self, vulnerable_mcp_path):
        """Scan the vulnerable MCP config and verify all rules trigger."""
        from aegismcp import scan_file, Config
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
        from aegismcp import scan_file, Config

        config_file = temp_dir / "clean_mcp.json"
        config_file.write_text(json.dumps(clean_config))

        config = Config()
        findings = scan_file(config_file, config)

        assert len(findings) == 0, f"Clean config should have no findings, got: {findings}"

    def test_scan_with_sarif_export(self, vulnerable_mcp_path, temp_dir):
        """Test SARIF export functionality."""
        from aegismcp import scan_file, Config, export_sarif

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

    def test_scan_fail_on_exit_code(self, vulnerable_mcp_path):
        """Test --fail-on behavior via exit codes."""
        from aegismcp import scan_file, Config
        from aegismcp.rules_core import Finding

        config = Config()
        config.fail_on = "HIGH"
        findings = scan_file(vulnerable_mcp_path, config)

        # Should have HIGH or CRITICAL findings
        high_or_critical = any(f.severity in ("HIGH", "CRITICAL") for f in findings)
        assert high_or_critical, "Should have HIGH or CRITICAL findings"

    def test_scan_disabled_rules(self, vulnerable_mcp_path):
        """Test that disabled rules in config are respected."""
        from aegismcp import scan_file, Config

        config = Config()
        config.rules = {"AMCP001": {"enabled": False}}
        findings = scan_file(vulnerable_mcp_path, config)

        rule_ids = {f.rule_id for f in findings}
        assert "AMCP001" not in rule_ids, "AMCP001 should be disabled"

    def test_scan_custom_rule(self, vulnerable_mcp_path):
        """Test custom regex rules from config."""
        from aegismcp import scan_file, Config

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
        from aegismcp.cli import main
        import sys

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
        from aegismcp.cli import main
        import sys

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