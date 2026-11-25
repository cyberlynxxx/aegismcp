"""AST scanning rules (AMCP101-105).

These rules are implemented natively in PythonASTVisitor (ast_scanner.py)
and do not have check_fn - they are descriptors for documentation/registry.
"""
from ..registry import Rule

# AST rules are implemented natively in PythonASTVisitor (ast_scanner.py)
# This module defines the Rule descriptors for documentation and registry purposes.
# check_fn is None because these are not config-file rules - they scan Python source code.

AST_RULES = [
    Rule("AMCP101", "CRITICAL", "Command Injection via subprocess/os.system",
         "Detects shell command injection", "Use subprocess.run with shell=False.", check_fn=None),
    Rule("AMCP102", "CRITICAL", "Dynamic Code Execution (eval/exec)",
         "Detects dynamic code execution", "Avoid eval/exec.", check_fn=None),
    Rule("AMCP103", "HIGH", "Potential Server-Side Request Forgery (SSRF)",
         "Detects HTTP calls with dynamic URLs", "Validate URLs against allowlist.", check_fn=None),
    Rule("AMCP104", "HIGH", "Potential Path Traversal",
         "Detects file operations with user paths", "Validate and resolve paths.", check_fn=None),
    Rule("AMCP105", "CRITICAL", "Insecure Deserialization",
         "Detects unsafe pickle/yaml deserialization", "Use safe alternatives like json.loads.", check_fn=None),
]