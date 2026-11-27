import pytest
from pathlib import Path
from aegismcp.sarif import export_sarif
from aegismcp.rules_core import Finding

def test_sarif_export(tmp_path):
    """Test SARIF export works correctly."""
    output_file = tmp_path / "test.sarif"
    findings = [
        Finding(
            rule_id="AMCP000",
            severity="MEDIUM",
            title="Issue",
            message="Msg",
            location="file.py:1:1",
            remediation="fix"
        ) for _ in range(10)
    ]

    export_sarif(findings, output_file)
    assert output_file.exists()

    # Verify content
    import json
    with open(output_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
        assert len(data["runs"][0]["results"]) == 10

def test_sarif_large_output_truncation(tmp_path):
    """Test SARIF export truncates very large output."""
    output_file = tmp_path / "test_large.sarif"
    # Create findings with very long messages to trigger size limit
    findings = [
        Finding(
            rule_id="AMCP000",
            severity="MEDIUM",
            title="Issue",
            message="X" * 100000,  # 100KB per finding
            location="file.py:1:1",
            remediation="fix"
        ) for _ in range(200)
    ]

    export_sarif(findings, output_file)
    assert output_file.exists()

    # Verify file size is limited
    file_size = output_file.stat().st_size
    assert file_size <= 11 * 1024 * 1024  # ~11MB (10MB limit + overhead)