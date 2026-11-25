import json
from pathlib import Path

from .rules_core import Finding

SEVERITY_MAP = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}

def export_sarif(findings: list[Finding], output_path: Path) -> None:
    sarif_doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AegisMCP",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/cyberlynxxx/aegismcp",
                    }
                },
                "results": [
                    {
                        "ruleId": f.rule_id,
                        "level": SEVERITY_MAP.get(f.severity, "warning"),
                        "message": {"text": f"{f.title}: {f.message} Fix: {f.remediation}"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": f.location.split(":")[0]}
                                }
                            }
                        ],
                    }
                    for f in findings
                ],
            }
        ],
    }
    output_path.write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")