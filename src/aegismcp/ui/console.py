"""Smart console with TTY detection and cp1252 fallback for cross-platform rendering."""

from __future__ import annotations

import os
import sys
from typing import TextIO

from rich.console import Console as RichConsole

# ASCII glyph fallbacks for cp1252 terminals
ASCII_GLYPHS = {
    "check": "[OK]",
    "cross": "[FAIL]",
    "warning": "[WARN]",
    "info": "[INFO]",
    "bullet": "*",
    "arrow": "->",
    "block": "#",
    "line_h": "-",
    "line_v": "|",
    "corner_tl": "+",
    "corner_tr": "+",
    "corner_bl": "+",
    "corner_br": "+",
    "tee_l": "+",
    "tee_r": "+",
    "tee_t": "+",
    "tee_b": "+",
    "cross_box": "+",
}


UNICODE_GLYPHS = {
    "check": "✓",
    "cross": "✗",
    "warning": "⚠",
    "info": "ℹ",
    "bullet": "•",
    "arrow": "→",
    "block": "█",
    "line_h": "─",
    "line_v": "│",
    "corner_tl": "┌",
    "corner_tr": "┐",
    "corner_bl": "└",
    "corner_br": "┘",
    "tee_l": "├",
    "tee_r": "┤",
    "tee_t": "┬",
    "tee_b": "┴",
    "cross_box": "┼",
}


def _is_cp1252_terminal(stream: TextIO | None = None) -> bool:
    """Detect if terminal uses cp1252 encoding (common on Windows)."""
    if stream is None:
        stream = sys.stderr
    try:
        encoding = getattr(stream, "encoding", None) or "utf-8"
        return encoding.lower() in ("cp1252", "windows-1252")
    except Exception as e:  # noqa: BLE001
        print(f"Error checking terminal encoding: {e}", file=sys.stderr)
        return False


def _is_tty(stream: TextIO | None = None) -> bool:
    """Check if stream is a TTY."""
    if stream is None:
        stream = sys.stderr
    try:
        return stream.isatty()
    except Exception as e:  # noqa: BLE001
        print(f"Error checking TTY status: {e}", file=sys.stderr)
        return False


def _is_piped_or_ci() -> bool:
    """Detect if output is piped or running in CI."""
    # Check common CI environment variables
    ci_vars = ["CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "TRAVIS", "CIRCLECI", "APPVEYOR"]
    if any(os.getenv(var) for var in ci_vars):
        return True
    # Check if stderr is not a TTY (piped)
    return not _is_tty(sys.stderr)


class GlyphSet:
    """Glyph set that auto-selects Unicode or ASCII based on terminal capabilities."""

    def __init__(self, force_ascii: bool = False, force_unicode: bool = False) -> None:
        self.force_ascii = force_ascii
        self.force_unicode = force_unicode
        self._glyphs = self._select_glyphs()

    def _select_glyphs(self) -> dict:
        if self.force_ascii:
            return ASCII_GLYPHS
        if self.force_unicode:
            return UNICODE_GLYPHS
        # Auto-detect
        if _is_cp1252_terminal() or _is_piped_or_ci():
            return ASCII_GLYPHS
        return UNICODE_GLYPHS

    def __getattr__(self, name: str) -> str:
        return self._glyphs.get(name, ASCII_GLYPHS.get(name, ""))


class SmartConsole:
    """Smart console that handles TTY detection, cp1252 fallback, and stderr binding."""

    def __init__(
        self,
        force_ascii: bool = False,
        force_unicode: bool = False,
        stderr: bool = True,
        quiet: bool = False,
    ) -> None:
        self.force_ascii = force_ascii
        self.force_unicode = force_unicode
        self.quiet = quiet
        self.glyphs = GlyphSet(force_ascii=force_ascii, force_unicode=force_unicode)
        self._console: RichConsole | None = None
        self._stderr = stderr
        self._init_console()

    def _init_console(self) -> None:
        """Initialize the Rich console bound to stderr."""
        if self._stderr:
            self._console = RichConsole(stderr=True, force_terminal=_is_tty(sys.stderr))
        else:
            self._console = RichConsole(stderr=False, force_terminal=_is_tty(sys.stdout))

    @property
    def console(self) -> RichConsole:
        """Get the underlying Rich console."""
        if self._console is None:
            self._init_console()
        assert self._console is not None, "Console not initialized"
        return self._console

    def print(self, *args, **kwargs) -> None:
        """Print to console (stderr by default)."""
        if not self.quiet and self._console:
            self._console.print(*args, **kwargs)

    def print_stderr(self, *args, **kwargs) -> None:
        """Explicitly print to stderr."""
        if not self.quiet:
            # Ensure we're using stderr console
            if self._console and self._console.file is not sys.stderr:
                self._console = RichConsole(stderr=True, force_terminal=_is_tty(sys.stderr))
            assert self._console is not None, "Console not initialized"
            self._console.print(*args, **kwargs)

    def print_stdout(self, *args, **kwargs) -> None:
        """Explicitly print to stdout (for JSON-RPC frames only)."""
        if not self.quiet:
            stdout_console = RichConsole(stderr=False, force_terminal=_is_tty(sys.stdout))
            stdout_console.print(*args, **kwargs)

    def rule(self, title: str = "", **kwargs) -> None:
        """Print a horizontal rule."""
        if not self.quiet and self._console:
            self._console.rule(title, **kwargs)

    def status(self, message: str, **kwargs):
        """Create a status context manager."""
        if self._console:
            return self._console.status(message, **kwargs)
        return None

    def log(self, *args, **kwargs) -> None:
        """Log with timestamp."""
        if not self.quiet and self._console:
            self._console.log(*args, **kwargs)

    def clear(self) -> None:
        """Clear the console."""
        if self._console:
            self._console.clear()

    def is_tty(self) -> bool:
        """Check if console is attached to a TTY."""
        return _is_tty(sys.stderr if self._stderr else sys.stdout)

    def is_piped(self) -> bool:
        """Check if output is piped."""
        return _is_piped_or_ci()


# Global smart console instance
_global_console: SmartConsole | None = None
_console_lock = __import__("threading").Lock()


def get_console(
    force_ascii: bool = False,
    force_unicode: bool = False,
    stderr: bool = True,
    quiet: bool = False,
) -> SmartConsole:
    """Get or create the global smart console."""
    global _global_console
    with _console_lock:
        if _global_console is None:
            _global_console = SmartConsole(
                force_ascii=force_ascii,
                force_unicode=force_unicode,
                stderr=stderr,
                quiet=quiet,
            )
        return _global_console


def set_console(console: SmartConsole) -> None:
    """Set the global console (for testing)."""
    global _global_console
    with _console_lock:
        _global_console = console