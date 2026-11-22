"""AST-based scanning for Python MCP server source code."""
from __future__ import annotations

import ast
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class ASTFinding:
    """A security finding from AST analysis."""
    rule_id: str
    severity: str
    title: str
    message: str
    file_path: Path
    line: int
    column: int
    remediation: str


class PythonASTVisitor(ast.NodeVisitor):
    """AST visitor that detects security issues in Python MCP servers."""

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.findings: list[ASTFinding] = []

    def _add_finding(self, rule_id: str, severity: str, title: str, message: str,
                     node: ast.AST, remediation: str) -> None:
        """Add a finding with location info."""
        self.findings.append(ASTFinding(
            rule_id=rule_id,
            severity=severity,
            title=title,
            message=message,
            file_path=self.file_path,
            line=node.lineno,
            column=node.col_offset,
            remediation=remediation,
        ))

    def visit_Call(self, node: ast.Call) -> None:
        """Single visit_Call that runs all security checks."""
        # Command Injection (AMCP101, AMCP102)
        self._check_command_injection(node)

        # SSRF (AMCP103)
        self._check_ssrf(node)

        # Path Traversal (AMCP104)
        self._check_path_traversal(node)

        # Insecure Deserialization (AMCP105)
        self._check_insecure_deserialization(node)

        self.generic_visit(node)

    # === Command Injection (AMCP101, AMCP102) ===
    def _check_command_injection(self, node: ast.Call) -> None:
        # subprocess.run, Popen, call, check_call, check_output
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ("run", "Popen", "call", "check_call", "check_output"):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                    self._check_subprocess_call(node)
            # os.system, os.popen
            elif node.func.attr in ("system", "popen"):
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                    self._add_finding(
                        "AMCP101", "CRITICAL",
                        "Direct shell execution via os.system/popen",
                        f"Use of os.{node.func.attr}() detected - allows arbitrary command execution",
                        node,
                        "Use subprocess.run() with shell=False and validate/sanitize all inputs"
                    )

        # eval, exec
        elif isinstance(node.func, ast.Name):
            if node.func.id in ("eval", "exec"):
                self._add_finding(
                    "AMCP102", "CRITICAL",
                    f"Use of {node.func.id}()",
                    f"Dynamic code execution via {node.func.id}() - severe security risk",
                    node,
                    f"Avoid {node.func.id}(). Use ast.literal_eval() for safe evaluation or redesign."
                )

    def _check_subprocess_call(self, node: ast.Call) -> None:
        """Analyze subprocess call for injection risks."""
        # Check if shell=True
        shell_true = False
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                shell_true = True
                break

        # Check if command is built from variables (not just literals)
        args = node.args
        if args:
            first_arg = args[0]
            if not self._is_safe_command(first_arg):
                severity = "CRITICAL" if shell_true else "HIGH"
                self._add_finding(
                    "AMCP101", severity,
                    "Command injection via subprocess" + (" (shell=True)" if shell_true else ""),
                    "subprocess call with dynamic command arguments detected",
                    node,
                    "Use shell=False, pass args as list, validate/sanitize all inputs"
                )

    def _is_safe_command(self, node: ast.AST) -> bool:
        """Check if a command argument is a safe literal list."""
        # If it's a list/tuple of arguments, check if first element (the command) is a constant
        if isinstance(node, (ast.List, ast.Tuple)):
            if node.elts:
                first = node.elts[0]
                return isinstance(first, ast.Constant) and isinstance(first.value, str)
            return False
        # If it's a string constant (shell command), not safe for shell=False
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return False
        return False

    # === SSRF (AMCP103) ===
    def _check_ssrf(self, node: ast.Call) -> None:
        """Detect potential SSRF in HTTP calls."""
        http_methods = {"get", "post", "put", "patch", "delete", "head", "options", "request"}
        http_libs = {"requests", "httpx", "urllib", "urllib3", "aiohttp", "http.client"}

        func = node.func
        method_name = None
        lib_name = None

        if isinstance(func, ast.Attribute):
            method_name = func.attr
            if isinstance(func.value, ast.Name):
                lib_name = func.value.id
            elif isinstance(func.value, ast.Attribute):
                # e.g., requests.get, httpx.Client.get
                if isinstance(func.value.value, ast.Name):
                    lib_name = func.value.value.id

        if method_name in http_methods and lib_name in http_libs:
            # Check if URL argument is dynamic
            url_arg = None
            if node.args:
                url_arg = node.args[0]
            else:
                for kw in node.keywords:
                    if kw.arg in ("url", "uri"):
                        url_arg = kw.value
                        break

            if url_arg and not self._is_safe_url(url_arg):
                self._add_finding(
                    "AMCP103", "HIGH",
                    "Potential SSRF (Server-Side Request Forgery)",
                    f"HTTP request with dynamic URL detected ({lib_name}.{method_name})",
                    node,
                    "Validate URLs against allowlist, block private/internal IPs (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x)"
                )

    def _is_safe_url(self, node: ast.AST) -> bool:
        """Check if URL is a safe literal."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            url = node.value
            # Check for obviously safe patterns (but this is heuristic)
            return url.startswith(("https://api.", "https://www."))
        return False

    # === Path Traversal (AMCP104) ===
    def _check_path_traversal(self, node: ast.Call) -> None:
        """Detect path traversal vulnerabilities."""
        dangerous_funcs = {
            "open": ("builtins",),
            "read": ("pathlib", "Path"),
            "write_text": ("pathlib", "Path"),
            "write_bytes": ("pathlib", "Path"),
            "unlink": ("pathlib", "Path"),
            "rmdir": ("pathlib", "Path"),
            "mkdir": ("pathlib", "Path"),
            "remove": ("os",),
            "unlink": ("os",),
            "rmdir": ("os",),
            "mkdir": ("os",),
        }

        func = node.func
        if isinstance(func, ast.Name):
            if func.id in dangerous_funcs:
                # Check first argument for path traversal patterns
                if node.args:
                    if self._has_path_traversal(node.args[0]):
                        self._add_finding(
                            "AMCP104", "HIGH",
                            "Potential Path Traversal",
                            f"File operation with user-controlled path: {func.id}()",
                            node,
                            "Validate/resolve paths, use Path.resolve(), restrict to allowed directories"
                        )
        elif isinstance(func, ast.Attribute):
            if func.attr in dangerous_funcs:
                if node.args and self._has_path_traversal(node.args[0]):
                    self._add_finding(
                        "AMCP104", "HIGH",
                        "Potential Path Traversal",
                        f"File operation with user-controlled path: {func.attr}()",
                        node,
                        "Validate/resolve paths, use Path.resolve(), restrict to allowed directories"
                    )

    def _has_path_traversal(self, node: ast.AST) -> bool:
        """Heuristic: does this path expression contain user input?"""
        # If it's a variable, function call, or formatted string - potentially unsafe
        return not self._is_safe_path(node)

    def _is_safe_path(self, node: ast.AST) -> bool:
        """Check if path is a safe literal."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return ".." not in node.value and not node.value.startswith("/")
        if isinstance(node, ast.JoinedStr):  # f-string
            return False  # Dynamic
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):  # string concat
            return False
        if isinstance(node, ast.Call):  # function call
            return False
        if isinstance(node, ast.Name):  # variable
            return False
        return True

    # === Insecure Deserialization (AMCP105) ===
    def _check_insecure_deserialization(self, node: ast.Call) -> None:
        """Detect pickle.loads, yaml.load (unsafe), etc."""
        unsafe_funcs = {
            "pickle": ["loads", "load"],
            "yaml": ["load", "unsafe_load"],
            "marshal": ["loads", "load"],
            "shelve": ["open"],
            "dill": ["loads", "load"],
        }

        func = node.func
        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name):
                lib = func.value.id
                method = func.attr
                if lib in unsafe_funcs and method in unsafe_funcs[lib]:
                    # Check if it's yaml.load without Loader=SafeLoader
                    if lib == "yaml" and method == "load":
                        has_safe_loader = any(
                            kw.arg == "Loader" for kw in node.keywords
                        )
                        if has_safe_loader:
                            return
                    self._add_finding(
                        "AMCP105", "CRITICAL",
                        f"Insecure Deserialization ({lib}.{method})",
                        f"Use of {lib}.{method}() can lead to arbitrary code execution",
                        node,
                        f"Use safe alternatives: yaml.safe_load(), json.loads(), or specify Loader=yaml.SafeLoader"
                    )


def scan_python_file(file_path: Path) -> list[ASTFinding]:
    """Scan a single Python file for security issues."""
    try:
        with file_path.open("r", encoding="utf-8") as f:
            source = f.read()
    except Exception:
        return []

    try:
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError:
        return []

    visitor = PythonASTVisitor(file_path)
    visitor.visit(tree)
    return visitor.findings


def scan_python_directory(root: Path) -> list[ASTFinding]:
    """Recursively scan all Python files in a directory."""
    findings = []
    ignore_dirs = {".git", "__pycache__", ".venv", "venv", "env", "dist", "build", ".pytest_cache", ".mypy_cache", "node_modules"}

    for py_file in root.rglob("*.py"):
        if any(part in ignore_dirs for part in py_file.parts):
            continue
        findings.extend(scan_python_file(py_file))

    return findings