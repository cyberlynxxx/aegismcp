"""Deep tests for HTML Report module."""
import pytest
import tempfile
from pathlib import Path
from aegismcp.html_report import save_html_report, HTMLReportOptions
from aegismcp.rules_core import Finding

def test_html_report_basic(tmp_path):
    """Test basic HTML report generation."""
    output_file = tmp_path / "report.html"
    findings = [
        Finding(
            rule_id="AMCP001",
            severity="HIGH",
            title="Test Issue",
            message="Description",
            location="test.py:10:5",
            remediation="Fix it"
        )
    ]

    opts = HTMLReportOptions(title="Test Report", theme="dark")
    metadata = {"FilesScanned": 1, "FindingsCount": 1}

    save_html_report(findings, output_file, 1, opts, metadata)
    assert output_file.exists()

    content = output_file.read_text(encoding="utf-8")
    assert "Test Report" in content
    assert "AMCP001" in content
    assert "HIGH" in content

def test_html_report_light_theme(tmp_path):
    """Test HTML report with light theme."""
    output_file = tmp_path / "report.html"
    findings = [
        Finding(
            rule_id="AMCP001",
            severity="MEDIUM",
            title="Test Issue",
            message="Description",
            location="test.py:10:5",
            remediation="Fix it"
        )
    ]

    opts = HTMLReportOptions(title="Test Report", theme="light")
    metadata = {"FilesScanned": 1, "FindingsCount": 1}

    save_html_report(findings, output_file, 1, opts, metadata)
    content = output_file.read_text(encoding="utf-8")
    assert "light" in content.lower()

def test_html_report_empty_findings(tmp_path):
    """Test HTML report with no findings."""
    output_file = tmp_path / "report.html"
    findings = []

    opts = HTMLReportOptions(title="Clean Report", theme="dark")
    metadata = {"FilesScanned": 5, "FindingsCount": 0}

    save_html_report(findings, output_file, 5, opts, metadata)
    assert output_file.exists()

    content = output_file.read_text(encoding="utf-8")
    assert "Clean Report" in content
    assert "No Security Issues Found" in content

def test_html_report_many_findings(tmp_path):
    """Test HTML report with many findings."""
    output_file = tmp_path / "report.html"
    findings = [
        Finding(
            rule_id=f"AMCP{i:03d}",
            severity="MEDIUM",
            title=f"Issue {i}",
            message=f"Description {i}",
            location=f"test.py:{i}:1",
            remediation=f"Fix {i}"
        ) for i in range(100)
    ]

    opts = HTMLReportOptions(title="Large Report", theme="dark")
    metadata = {"FilesScanned": 10, "FindingsCount": 100}

    save_html_report(findings, output_file, 10, opts, metadata)
    assert output_file.exists()
    assert output_file.stat().st_size > 10000  # Should be substantial

def test_html_report_special_characters(tmp_path):
    """Test HTML report with special characters."""
    output_file = tmp_path / "report.html"
    findings = [
        Finding(
            rule_id="AMCP001",
            severity="HIGH",
            title="<script>alert('xss')</script>",
            message="Description with & < > \" ' characters",
            location="test.py:10:5",
            remediation="Fix it & escape"
        )
    ]

    opts = HTMLReportOptions(title="XSS Test", theme="dark")
    metadata = {"FilesScanned": 1, "FindingsCount": 1}

    save_html_report(findings, output_file, 1, opts, metadata)
    content = output_file.read_text(encoding="utf-8")
    # Should be escaped
    assert "<script>" in content
    assert "&" in content