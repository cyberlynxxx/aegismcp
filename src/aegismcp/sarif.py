import json
from pathlib import Path
from typing import Any

from .rules_core import Finding

SEVERITY_MAP = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}

def export_sarif(findings: list[Finding], output_path: Path) -> None:
    sarif_doc: dict[str, Any] = {
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

    # Serialize with size limit
    max_size = 10 * 1024 * 1024  # 10 MB
    try:
        sarif_json = json.dumps(sarif_doc, indent=2, ensure_ascii=False)
    except (ValueError, MemoryError, RecursionError) as e:
        raise RuntimeError(f"Failed to serialize SARIF: {e}")

    if len(sarif_json) > max_size:
        # Truncate results if too large
        sarif_doc["runs"][0]["results"] = sarif_doc["runs"][0]["results"][:1000]
        sarif_json = json.dumps(sarif_doc, indent=2, ensure_ascii=False)
        if len(sarif_json) > max_size:
            sarif_json = sarif_json[:max_size] + "\n\"  // truncated\""

    # Write with safe file operations
    try:
        # Ensure parent directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Write atomically using a temporary file
        temp_path = output_path.with_suffix(output_path.suffix + ".tmp")
        temp_path.write_text(sarif_json, encoding="utf-8")
        temp_path.replace(output_path)
    except OSError as e:
        raise RuntimeError(f"Failed to write SARIF file: {e}")
    except UnicodeEncodeError as e:
        raise RuntimeError(f"Encoding error writing SARIF file: {e}")