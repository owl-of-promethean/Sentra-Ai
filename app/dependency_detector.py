"""
Dependency and technology detector for Sentra AI security audits.

Inspects project manifest files inside a crawled source tree and
extracts package names, versions, and the package ecosystem.

Design rules:
- Reads only files already discovered by the crawler (no extra I/O).
- Never executes manifests or installs packages.
- Presence of a dependency is NOT evidence of vulnerability.
  This module only identifies what technologies are present so the
  audit retriever can look up relevant security reference material.
- All version strings are taken verbatim from the manifest.
  Version ranges/constraints are preserved as-is.
"""

from __future__ import annotations

import json
import re
from typing import List

from app.audit_schemas import DependencyInfo
from app.source_crawler import CrawlResult, SourceFile


# ==============================================================
# MANIFEST FILENAMES
# ==============================================================

# Exact filenames (case-sensitive) that contain dependency information.
_MANIFEST_FILENAMES: frozenset[str] = frozenset({
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "package.json",
    "composer.json",
    "pom.xml",
    "build.gradle",
    "go.mod",
    "Gemfile",
    "Cargo.toml",
})

# Language/technology markers — files whose *presence* (not contents)
# indicate a technology stack.  Mapped to a tech label.
_PRESENCE_MARKERS: dict[str, str] = {
    "requirements.txt":  "python",
    "pyproject.toml":    "python",
    "Pipfile":           "python",
    "manage.py":         "django",
    "app.py":            "flask",
    "package.json":      "nodejs",
    "tsconfig.json":     "typescript",
    "composer.json":     "php",
    "pom.xml":           "java",
    "build.gradle":      "java",
    "go.mod":            "go",
    "Gemfile":           "ruby",
    "Cargo.toml":        "rust",
}


# ==============================================================
# DETECTOR
# ==============================================================

class DependencyDetector:
    """
    Extracts dependency and technology information from a CrawlResult.

    After crawling a project directory with SourceCrawler, pass the
    CrawlResult to detect() to get:
      - dependencies: list of DependencyInfo
      - technologies: deduplicated list of technology labels

    Usage:
        detector   = DependencyDetector()
        deps, tech = detector.detect(crawl_result)
    """

    def detect(
        self,
        crawl_result: CrawlResult,
    ) -> tuple[List[DependencyInfo], List[str]]:
        """
        Inspect all files in the CrawlResult and return dependency
        and technology information.

        Args:
            crawl_result: The output of SourceCrawler.crawl().

        Returns:
            (dependencies, technologies):
              dependencies — list of DependencyInfo (may have duplicates across files)
              technologies — deduplicated, sorted list of technology strings
        """
        all_deps: List[DependencyInfo] = []
        tech_set: set[str] = set()

        # Detect technology from language distribution in crawled files
        for sf in crawl_result.files:
            if sf.language and sf.language not in ("unknown",):
                tech_set.add(sf.language)

        for sf in crawl_result.files:
            basename = sf.rel_path.split("/")[-1]  # works on posix-normalised paths

            # Presence-based technology markers
            if basename in _PRESENCE_MARKERS:
                tech_set.add(_PRESENCE_MARKERS[basename])

            # Dependency parsing
            if basename not in _MANIFEST_FILENAMES:
                continue

            deps = self._parse_manifest(sf)
            all_deps.extend(deps)

        return all_deps, sorted(tech_set)

    # ----------------------------------------------------------
    # MANIFEST PARSERS
    # ----------------------------------------------------------

    def _parse_manifest(self, sf: SourceFile) -> List[DependencyInfo]:
        """Dispatch to the appropriate parser based on filename."""
        basename = sf.rel_path.split("/")[-1]
        content  = "".join(line for _, line in sf.lines)

        parsers = {
            "requirements.txt": self._parse_requirements_txt,
            "pyproject.toml":   self._parse_pyproject_toml,
            "Pipfile":          self._parse_pipfile,
            "package.json":     self._parse_package_json,
            "composer.json":    self._parse_composer_json,
            "go.mod":           self._parse_go_mod,
            "pom.xml":          self._parse_pom_xml,
            "build.gradle":     self._parse_build_gradle,
            "Gemfile":          self._parse_gemfile,
            "Cargo.toml":       self._parse_cargo_toml,
        }
        parser = parsers.get(basename)
        if parser is None:
            return []

        try:
            return parser(content, sf.rel_path)
        except Exception:
            # Never crash the audit over a malformed manifest.
            return []

    # ── Python ────────────────────────────────────────────────

    def _parse_requirements_txt(
        self, content: str, source_file: str
    ) -> List[DependencyInfo]:
        """
        Parse requirements.txt format.

        Handles:
          package==1.2.3
          package>=1.0,<2.0
          package          (no version)
          -r other.txt     (ignored)
          # comments        (ignored)
        """
        deps = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Split on first version specifier character
            match = re.match(
                r"^([A-Za-z0-9_.\-]+)\s*([><=!~^,\s].+)?$", line
            )
            if match:
                name    = match.group(1).strip()
                version = (match.group(2) or "").strip() or None
                deps.append(DependencyInfo(
                    name=name,
                    version=version,
                    manager="pip",
                    source_file=source_file,
                ))
        return deps

    def _parse_pyproject_toml(
        self, content: str, source_file: str
    ) -> List[DependencyInfo]:
        """
        Extract dependencies from pyproject.toml using regex.
        Handles [project] dependencies and [tool.poetry.dependencies].
        """
        deps = []
        # Match strings inside dependencies = [...] or dependencies = {...}
        # Simple approach: find lines like '  "flask>=2.0"' or 'flask = "^2.0"'
        for line in content.splitlines():
            line = line.strip()
            # poetry style: flask = "^2.0"
            m = re.match(r'^([A-Za-z0-9_.\-]+)\s*=\s*["\']([^"\']*)["\']', line)
            if m and m.group(1).lower() not in (
                "name", "version", "description", "python",
                "authors", "readme", "license",
            ):
                deps.append(DependencyInfo(
                    name=m.group(1),
                    version=m.group(2) or None,
                    manager="pip",
                    source_file=source_file,
                ))
                continue
            # PEP 621 style: "flask>=2.0"
            m2 = re.match(r'^["\']([A-Za-z0-9_.\-]+)\s*([><=!~^,\s][^"\']*)?["\']', line)
            if m2:
                deps.append(DependencyInfo(
                    name=m2.group(1),
                    version=(m2.group(2) or "").strip() or None,
                    manager="pip",
                    source_file=source_file,
                ))
        return deps

    def _parse_pipfile(
        self, content: str, source_file: str
    ) -> List[DependencyInfo]:
        """Parse Pipfile [packages] and [dev-packages] sections."""
        deps = []
        in_section = False
        for line in content.splitlines():
            line = line.strip()
            if line in ("[packages]", "[dev-packages]"):
                in_section = True
                continue
            if line.startswith("[") and line not in ("[packages]", "[dev-packages]"):
                in_section = False
                continue
            if in_section and "=" in line:
                name, _, version_raw = line.partition("=")
                name = name.strip()
                version = version_raw.strip().strip('"').strip("'") or None
                if name:
                    deps.append(DependencyInfo(
                        name=name,
                        version=version,
                        manager="pip",
                        source_file=source_file,
                    ))
        return deps

    # ── JavaScript / Node ─────────────────────────────────────

    def _parse_package_json(
        self, content: str, source_file: str
    ) -> List[DependencyInfo]:
        """Parse package.json dependencies and devDependencies."""
        deps = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return deps

        for section in ("dependencies", "devDependencies", "peerDependencies"):
            section_data = data.get(section, {})
            if isinstance(section_data, dict):
                for name, version in section_data.items():
                    deps.append(DependencyInfo(
                        name=name,
                        version=str(version) if version else None,
                        manager="npm",
                        source_file=source_file,
                    ))
        return deps

    # ── PHP ───────────────────────────────────────────────────

    def _parse_composer_json(
        self, content: str, source_file: str
    ) -> List[DependencyInfo]:
        """Parse composer.json require and require-dev."""
        deps = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return deps

        for section in ("require", "require-dev"):
            section_data = data.get(section, {})
            if isinstance(section_data, dict):
                for name, version in section_data.items():
                    if name == "php":  # skip PHP version constraint
                        continue
                    deps.append(DependencyInfo(
                        name=name,
                        version=str(version) if version else None,
                        manager="composer",
                        source_file=source_file,
                    ))
        return deps

    # ── Go ────────────────────────────────────────────────────

    def _parse_go_mod(
        self, content: str, source_file: str
    ) -> List[DependencyInfo]:
        """
        Parse go.mod require blocks.

        Handles:
          require github.com/gin-gonic/gin v1.9.1
          require (
              github.com/some/pkg v1.0.0
          )
        """
        deps = []
        in_require = False
        for line in content.splitlines():
            line = line.strip()
            if line == "require (":
                in_require = True
                continue
            if line == ")" and in_require:
                in_require = False
                continue
            if in_require or line.startswith("require "):
                # Strip leading 'require '
                entry = line.removeprefix("require ").strip()
                parts = entry.split()
                if len(parts) >= 2 and parts[0].count("/") >= 1:
                    deps.append(DependencyInfo(
                        name=parts[0],
                        version=parts[1],
                        manager="go",
                        source_file=source_file,
                    ))
        return deps

    # ── Java ─────────────────────────────────────────────────

    def _parse_pom_xml(
        self, content: str, source_file: str
    ) -> List[DependencyInfo]:
        """
        Parse Maven pom.xml <dependency> blocks using regex.
        Avoids pulling in an XML parser dependency.
        """
        deps = []
        # Find all <dependency>...</dependency> blocks
        for block in re.findall(
            r"<dependency>(.*?)</dependency>", content, re.DOTALL
        ):
            group_id = re.search(r"<groupId>(.*?)</groupId>", block)
            artifact = re.search(r"<artifactId>(.*?)</artifactId>", block)
            version  = re.search(r"<version>(.*?)</version>", block)
            if group_id and artifact:
                name = f"{group_id.group(1).strip()}:{artifact.group(1).strip()}"
                deps.append(DependencyInfo(
                    name=name,
                    version=version.group(1).strip() if version else None,
                    manager="maven",
                    source_file=source_file,
                ))
        return deps

    def _parse_build_gradle(
        self, content: str, source_file: str
    ) -> List[DependencyInfo]:
        """
        Parse Gradle build.gradle dependency declarations.

        Handles:
          implementation 'group:artifact:version'
          implementation "group:artifact:version"
          compile(...)
        """
        deps = []
        pattern = re.compile(
            r"""(?:implementation|compile|testImplementation|api)\s+['"]([^'"]+)['"]"""
        )
        for match in pattern.finditer(content):
            parts = match.group(1).split(":")
            if len(parts) >= 2:
                name    = f"{parts[0]}:{parts[1]}"
                version = parts[2].strip() if len(parts) >= 3 else None
                deps.append(DependencyInfo(
                    name=name,
                    version=version,
                    manager="gradle",
                    source_file=source_file,
                ))
        return deps

    # ── Ruby ─────────────────────────────────────────────────

    def _parse_gemfile(
        self, content: str, source_file: str
    ) -> List[DependencyInfo]:
        """
        Parse Gemfile gem declarations.

        Handles:
          gem 'rails', '~> 7.0'
          gem 'devise'
        """
        deps = []
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("gem "):
                parts = re.findall(r"""['"]([^'"]+)['"]""", line)
                if parts:
                    name    = parts[0]
                    version = parts[1] if len(parts) >= 2 else None
                    deps.append(DependencyInfo(
                        name=name,
                        version=version,
                        manager="bundler",
                        source_file=source_file,
                    ))
        return deps

    # ── Rust ─────────────────────────────────────────────────

    def _parse_cargo_toml(
        self, content: str, source_file: str
    ) -> List[DependencyInfo]:
        """Parse Cargo.toml [dependencies] section."""
        deps = []
        in_deps = False
        for line in content.splitlines():
            line = line.strip()
            if line == "[dependencies]" or line == "[dev-dependencies]":
                in_deps = True
                continue
            if line.startswith("[") and "dependencies" not in line:
                in_deps = False
                continue
            if in_deps and "=" in line and not line.startswith("#"):
                name, _, version_raw = line.partition("=")
                name    = name.strip()
                version = version_raw.strip().strip('"').strip("'") or None
                if name:
                    deps.append(DependencyInfo(
                        name=name,
                        version=version,
                        manager="cargo",
                        source_file=source_file,
                    ))
        return deps
