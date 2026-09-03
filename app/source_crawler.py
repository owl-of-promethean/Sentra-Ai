"""
Source-code crawler for Sentra AI security audits.

Recursively discovers and reads source files from a local project
directory.  Returns structured results with exact file paths, line
numbers, and source content.

Safety rules:
- Never executes discovered source code.
- Never modifies the scanned project.
- Skips secrets files (.env, credentials, key files).
- Skips VCS, dependency, build, and cache directories.
- Enforces per-file and total-file size limits.
- Skips binary files (detected by null-byte probe).
- Returns only text content with exact 1-based line numbers.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional

# ==============================================================
# SUPPORTED EXTENSIONS
# ==============================================================

SUPPORTED_EXTENSIONS: frozenset[str] = frozenset({
    # Python
    ".py",
    # JavaScript / TypeScript
    ".js", ".jsx", ".ts", ".tsx",
    # PHP
    ".php",
    # Java
    ".java",
    # Go
    ".go",
    # Ruby
    ".rb",
    # Web / Template
    ".html", ".htm",
    # Data / Config
    ".sql", ".json", ".yaml", ".yml",
    # Shell (read-only, analysis only)
    ".sh",
    # C / C++ (future)
    ".c", ".cpp", ".h",
    # Manifest / dependency files
    ".txt",   # requirements.txt, constraints.txt
    ".toml",  # pyproject.toml, Cargo.toml
    ".mod",   # go.mod
    ".gradle", # build.gradle
    ".xml",   # pom.xml
    # No-extension manifest files (Pipfile, Gemfile, Dockerfile etc.)
    # are handled via the empty-extension path "" below
    "",
})

# ==============================================================
# IGNORED DIRECTORY NAMES  (exact directory-name match)
# ==============================================================

_IGNORED_DIRS: frozenset[str] = frozenset({
    # Version control
    ".git", ".svn", ".hg",
    # Node / JS
    "node_modules", ".npm", ".yarn",
    # Python virtualenvs
    "venv", ".venv", "env", ".env",
    "virtualenv", "__pycache__", ".mypy_cache", ".pytest_cache",
    # Build / dist / generated
    "dist", "build", "out", "target", "bin", "obj",
    ".next", ".nuxt", ".output",
    # IDE / editor
    ".idea", ".vscode", ".vs",
    # Coverage / test artefacts
    "coverage", ".coverage", "htmlcov",
    # Docker / CI
    ".docker",
    # Logs
    "logs",
})

# ==============================================================
# IGNORED FILE NAMES / PATTERNS  (exact basename match)
# ==============================================================

_IGNORED_FILENAMES: frozenset[str] = frozenset({
    # Secrets / credentials
    ".env", ".env.local", ".env.production", ".env.staging",
    ".env.development", ".env.test",
    # Key / certificate files
    "id_rsa", "id_ed25519", "id_dsa", "id_ecdsa",
    "private.key", "privkey.pem", "server.key",
    # Compiled / lock files that add no audit value
    "package-lock.json", "yarn.lock", "poetry.lock",
    "Pipfile.lock", "composer.lock", "Gemfile.lock",
})

# Filename suffixes that indicate secrets (checked case-insensitively)
_IGNORED_SUFFIXES: tuple[str, ...] = (
    ".pem", ".key", ".p12", ".pfx", ".cer", ".crt",
)

# ==============================================================
# LIMITS
# ==============================================================

# Maximum bytes to read from a single file.
DEFAULT_MAX_FILE_BYTES: int = 200_000  # 200 KB

# Maximum number of source files collected in one crawl.
DEFAULT_MAX_FILES: int = 500


# ==============================================================
# RESULT DATACLASSES
# ==============================================================

@dataclass
class SourceFile:
    """
    A single source file discovered by the crawler.

    line_count reflects the actual number of lines in the file.
    lines is a list of (line_number, text) tuples where line_number
    is 1-based and matches the position in the original file exactly.
    Callers can slice lines[start-1 : end] to extract any range.
    """
    rel_path: str          # Relative path from the project root
    abs_path: str          # Absolute path (used for reading; not sent to Gemini)
    language: str          # Derived from extension (e.g. "python", "javascript")
    size_bytes: int        # File size on disk
    line_count: int        # Total lines in file
    lines: List[tuple[int, str]]   # [(1, "first line\n"), (2, "second line\n"), ...]
    truncated: bool = False        # True if file was cut at max_file_bytes

    def get_snippet(self, start_line: int, end_line: int) -> str:
        """
        Return the source text for lines [start_line, end_line] (1-based, inclusive).

        Lines outside the file range are silently clamped.
        Returns an empty string if the range is entirely out of bounds.
        """
        # lines list is 0-indexed; line_number = index + 1
        lo = max(start_line, 1) - 1
        hi = min(end_line, self.line_count)
        return "".join(text for _, text in self.lines[lo:hi])


@dataclass
class CrawlResult:
    """
    Result of crawling a project directory.

    files   — all discovered and read source files
    skipped — relative paths of files that were skipped (with reason)
    errors  — relative paths of files that raised read errors
    """
    root_path: str
    files: List[SourceFile] = field(default_factory=list)
    skipped: List[dict] = field(default_factory=list)   # [{path, reason}]
    errors: List[dict] = field(default_factory=list)    # [{path, error}]
    truncated_to_limit: bool = False  # True if max_files was reached

    @property
    def file_count(self) -> int:
        return len(self.files)

    @property
    def total_lines(self) -> int:
        return sum(f.line_count for f in self.files)


# ==============================================================
# EXTENSION -> LANGUAGE MAP
# ==============================================================

_LANG_MAP: dict[str, str] = {
    ".py":   "python",
    ".js":   "javascript",
    ".jsx":  "javascript",
    ".ts":   "typescript",
    ".tsx":  "typescript",
    ".php":  "php",
    ".java": "java",
    ".go":   "go",
    ".rb":   "ruby",
    ".html": "html",
    ".htm":  "html",
    ".sql":  "sql",
    ".json": "json",
    ".yaml": "yaml",
    ".yml":  "yaml",
    ".sh":   "shell",
    ".c":    "c",
    ".cpp":  "cpp",
    ".h":    "c",
}


def _ext_to_language(ext: str) -> str:
    return _LANG_MAP.get(ext.lower(), ext.lstrip(".") or "unknown")


# ==============================================================
# BINARY FILE DETECTION
# ==============================================================

def _is_binary(path: str, probe_bytes: int = 8192) -> bool:
    """
    Return True if the file appears to be binary.

    Reads the first `probe_bytes` bytes and checks for null bytes,
    which reliably indicate binary content for our purposes.
    """
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(probe_bytes)
        return b"\x00" in chunk
    except OSError:
        return False


# ==============================================================
# CRAWLER
# ==============================================================

class SourceCrawler:
    """
    Recursively discovers and reads source files from a local directory.

    Usage:
        crawler = SourceCrawler()
        result  = crawler.crawl("/path/to/project")

    The result contains structured SourceFile objects with exact line
    numbers, ready to be passed to the audit engine.
    """

    def __init__(
        self,
        supported_extensions: Optional[frozenset[str]] = None,
        ignored_dirs: Optional[frozenset[str]] = None,
        ignored_filenames: Optional[frozenset[str]] = None,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_files: int = DEFAULT_MAX_FILES,
    ) -> None:
        self.supported_extensions = supported_extensions or SUPPORTED_EXTENSIONS
        self.ignored_dirs = ignored_dirs or _IGNORED_DIRS
        self.ignored_filenames = ignored_filenames or _IGNORED_FILENAMES
        self.max_file_bytes = max_file_bytes
        self.max_files = max_files

    # ----------------------------------------------------------
    # PUBLIC API
    # ----------------------------------------------------------

    def crawl(self, root_path: str) -> CrawlResult:
        """
        Recursively scan root_path and return a CrawlResult.

        Args:
            root_path: Absolute or relative path to the project root.

        Returns:
            CrawlResult with all discovered SourceFile objects.

        Raises:
            ValueError: if root_path does not exist or is not a directory.
        """
        abs_root = os.path.abspath(root_path)
        if not os.path.isdir(abs_root):
            raise ValueError(f"Not a directory: {root_path!r}")

        result = CrawlResult(root_path=abs_root)

        for dirpath, dirnames, filenames in os.walk(abs_root, topdown=True):
            # Prune ignored directories in-place so os.walk doesn't descend.
            dirnames[:] = [
                d for d in dirnames
                if d not in self.ignored_dirs and not d.startswith(".")
                or d in {".", ".."}
            ]
            # Re-add any non-hidden dirs that were accidentally removed
            # by the dot-prefix check (edge case: hidden dirs we still want).
            # Simpler: just exclude hidden AND named-ignore dirs.
            dirnames[:] = [
                d for d in dirnames
                if d not in self.ignored_dirs and not d.startswith(".")
            ]

            for filename in filenames:
                if len(result.files) >= self.max_files:
                    result.truncated_to_limit = True
                    return result

                abs_path = os.path.join(dirpath, filename)
                rel_path = os.path.relpath(abs_path, abs_root).replace("\\", "/")

                # --- filter checks ---
                skip_reason = self._should_skip(filename, abs_path)
                if skip_reason:
                    result.skipped.append({"path": rel_path, "reason": skip_reason})
                    continue

                # --- read file ---
                source_file = self._read_file(abs_path, rel_path)
                if source_file is None:
                    result.errors.append({
                        "path": rel_path,
                        "error": "Could not read file",
                    })
                    continue

                result.files.append(source_file)

        return result

    # ----------------------------------------------------------
    # INTERNAL HELPERS
    # ----------------------------------------------------------

    def _should_skip(self, filename: str, abs_path: str) -> Optional[str]:
        """
        Return a reason string if the file should be skipped, else None.
        """
        lower = filename.lower()

        # Exact filename match
        if filename in self.ignored_filenames or lower in self.ignored_filenames:
            return "secrets/ignored filename"

        # Suffix match (private keys, certs, etc.)
        for suffix in _IGNORED_SUFFIXES:
            if lower.endswith(suffix):
                return f"secrets/ignored suffix ({suffix})"

        # Extension check
        _, ext = os.path.splitext(filename)
        if ext.lower() not in self.supported_extensions:
            return f"unsupported extension ({ext or 'none'})"

        # Size check (avoid reading header just for size)
        try:
            size = os.path.getsize(abs_path)
        except OSError:
            return "stat error"

        if size > self.max_file_bytes:
            return f"file too large ({size} bytes > {self.max_file_bytes})"

        # Binary check
        if _is_binary(abs_path):
            return "binary file"

        return None  # All clear

    def _read_file(self, abs_path: str, rel_path: str) -> Optional[SourceFile]:
        """
        Read a source file and return a SourceFile with exact line numbers.

        Returns None on any OS error.
        """
        _, ext = os.path.splitext(abs_path)
        language = _ext_to_language(ext)

        try:
            size = os.path.getsize(abs_path)
            with open(abs_path, "r", encoding="utf-8", errors="replace") as fh:
                raw = fh.read(self.max_file_bytes)
            truncated = size > self.max_file_bytes

            # Split into lines preserving line endings so line_count is accurate.
            raw_lines = raw.splitlines(keepends=True)
            lines: List[tuple[int, str]] = [
                (i + 1, line) for i, line in enumerate(raw_lines)
            ]

            return SourceFile(
                rel_path=rel_path,
                abs_path=abs_path,
                language=language,
                size_bytes=size,
                line_count=len(lines),
                lines=lines,
                truncated=truncated,
            )
        except OSError:
            return None
