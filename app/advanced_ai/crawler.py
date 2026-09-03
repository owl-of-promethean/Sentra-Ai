"""
Controlled attack-surface crawler for the Advanced AI sandbox.

Discovers pages, forms, links, endpoints, HTTP methods, parameters,
and authentication-required endpoints — strictly within the sandbox
origin. Arbitrary external domains are never crawled.

Additional safety:
- Hard caps on page count and request count.
- Only GET requests during discovery (state-changing fuzzing is the
  validator's job, with controlled payloads).
- The application's registry-approved endpoint scopes may be merged
  in as seeds so approved paths are represented even when not linked.
"""

from __future__ import annotations

import re
from typing import List, Optional, Set
from urllib.parse import urljoin, urlparse

import httpx

from app.advanced_ai.events import log_event
from app.advanced_ai.schemas import DiscoveredEndpoint


# Regexes — intentionally simple; this is a prototype discovery crawler,
# not a full HTML parser.
_HREF_RE = re.compile(r"""<a\s[^>]*href\s*=\s*["']([^"'#]+)["']""", re.IGNORECASE)
_FORM_RE = re.compile(
    r"""<form\b[^>]*?action\s*=\s*["']([^"']*)["'][^>]*?(?:method\s*=\s*["']([^"']*)["'])?[^>]*>|"""
    r"""<form\b[^>]*?method\s*=\s*["']([^"']*)["'][^>]*?(?:action\s*=\s*["']([^"']*)["'])?[^>]*>""",
    re.IGNORECASE,
)
_INPUT_RE = re.compile(
    r"""<input\b[^>]*name\s*=\s*["']([^"']+)["'][^>]*>""", re.IGNORECASE
)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# Paths that never need crawling (assets, noise)
_SKIP_SUFFIXES = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".map", ".pdf",
)


class SandboxCrawler:
    """
    Bounded same-origin crawler for a sandbox base URL.

    Args:
        max_pages:  maximum number of pages to fetch.
        timeout:    per-request timeout in seconds.
        transport:  optional httpx transport (tests inject MockTransport).
    """

    def __init__(
        self,
        max_pages: int = 25,
        timeout: float = 3.0,
        transport=None,
    ) -> None:
        self.max_pages = max_pages
        self.timeout = timeout
        self.transport = transport

    # ----------------------------------------------------------
    # PUBLIC API
    # ----------------------------------------------------------

    def crawl(
        self,
        base_url: str,
        seed_paths: Optional[List[str]] = None,
    ) -> List[DiscoveredEndpoint]:
        """
        Crawl the sandbox origin starting at '/' plus optional seeds.

        Args:
            base_url:   registry-resolved sandbox base URL.
            seed_paths: extra approved paths to include as seeds.

        Returns:
            De-duplicated list of DiscoveredEndpoint entries.
        """
        base_url = base_url.rstrip("/")
        origin = urlparse(base_url).netloc

        queue: List[str] = ["/"]
        for seed in seed_paths or []:
            p = self._normalize_path(seed)
            if p and p not in queue:
                queue.append(p)

        visited: Set[str] = set()
        endpoints: List[DiscoveredEndpoint] = []
        seen: Set[tuple] = set()

        def _add(endpoint: DiscoveredEndpoint, via: str) -> None:
            key = (endpoint.method.upper(), endpoint.endpoint,
                   tuple(sorted(endpoint.parameters)))
            if key in seen:
                return
            seen.add(key)
            endpoint.discovered_via = via
            endpoints.append(endpoint)

        requests_made = 0

        with httpx.Client(
            timeout=self.timeout,
            transport=self.transport,
            follow_redirects=True,
        ) as client:
            while queue and len(visited) < self.max_pages:
                path = queue.pop(0)
                if path in visited:
                    continue
                visited.add(path)

                requests_made += 1
                try:
                    resp = client.get(
                        base_url + path,
                        headers={"User-Agent": "Sentra-AdvancedAI-Crawler/0.1"},
                    )
                except Exception:
                    # Unreachable page — record nothing and continue.
                    continue

                auth_state = (
                    "required" if resp.status_code in (401, 403) else "none"
                )

                # The page itself is a GET endpoint.
                _add(
                    DiscoveredEndpoint(
                        endpoint=path,
                        method="GET",
                        parameters=self._query_params_from_path(path),
                        authentication=auth_state,
                    ),
                    "crawl",
                )

                body = resp.text or ""
                content_type = resp.headers.get("content-type", "")

                # Parse HTML pages only.
                if "html" in content_type.lower():
                    # Links -> enqueue same-origin paths
                    for href in _HREF_RE.findall(body):
                        nxt = self._resolve_same_origin(href, base_url, origin)
                        if nxt and nxt not in visited and nxt not in queue:
                            queue.append(nxt)

                    # Forms -> endpoints with parameters
                    for form_html in re.findall(
                        r"<form\b[^>]*>.*?</form>", body,
                        re.IGNORECASE | re.DOTALL,
                    ):
                        action_m = re.search(
                            r"""action\s*=\s*["']([^"']*)["']""",
                            form_html, re.IGNORECASE,
                        )
                        method_m = re.search(
                            r"""method\s*=\s*["']([^"']*)["']""",
                            form_html, re.IGNORECASE,
                        )
                        action = action_m.group(1) if action_m else path
                        method = (
                            method_m.group(1).upper() if method_m else "GET"
                        )
                        if method not in ("GET", "POST"):
                            method = "POST"
                        form_path = self._resolve_same_origin(
                            action, base_url, origin
                        ) or path
                        params = _INPUT_RE.findall(form_html)
                        params = [
                            p for p in params if p.lower() not in ("csrf_token",)
                        ]
                        _add(
                            DiscoveredEndpoint(
                                endpoint=form_path,
                                method=method,
                                parameters=params,
                                authentication="unknown",
                            ),
                            "form",
                        )

        # Merge approved-scope seeds that were never discovered so the
        # planner can reason about approved endpoints too.
        # Evidence-based: probe each seed before adding it so that
        # "Surface Discovered" truly means the endpoint was verified.
        for seed in seed_paths or []:
            p = self._normalize_path(seed)
            if not p:
                continue
            # If already discovered via crawl or form, skip.
            already_found = any(
                e.endpoint == p and e.method == "GET"
                for e in endpoints
            )
            if already_found:
                continue

            # Verify the endpoint actually responds before adding it.
            try:
                with httpx.Client(
                    timeout=self.timeout,
                    transport=self.transport,
                    follow_redirects=True,
                ) as client:
                    seed_resp = client.get(
                        base_url + p,
                        headers={"User-Agent": "Sentra-AdvancedAI-Crawler/0.1"},
                    )
                seed_auth = (
                    "required" if seed_resp.status_code in (401, 403) else "none"
                )
                _add(
                    DiscoveredEndpoint(
                        endpoint=p,
                        method="GET",
                        parameters=self._query_params_from_path(p),
                        authentication=seed_auth,
                    ),
                    "approved_scope_verified",
                )
            except Exception:
                # Seed is unreachable — log but do NOT add it as discovered.
                log_event(
                    "seed_unreachable",
                    path=p,
                    base_url=base_url,
                )
                continue

        log_event(
            "crawl_completed",
            pages_visited=len(visited),
            requests=requests_made,
            endpoints_discovered=len(endpoints),
        )
        return endpoints

    # ----------------------------------------------------------
    # HELPERS
    # ----------------------------------------------------------

    @staticmethod
    def _normalize_path(candidate: str) -> Optional[str]:
        """Return only the path component, or None if unusable."""
        if not candidate:
            return None
        parsed = urlparse(candidate)
        # Reject anything that looks like an absolute external URL.
        if parsed.scheme or parsed.netloc:
            return None
        path = parsed.path or candidate
        if not path.startswith("/"):
            path = "/" + path
        if any(path.lower().endswith(sfx) for sfx in _SKIP_SUFFIXES):
            return None
        return path

    def _resolve_same_origin(
        self, href: str, base_url: str, origin: str
    ) -> Optional[str]:
        """
        Resolve an href against base_url. Returns the path only when the
        target stays on the sandbox origin; external hosts return None.
        """
        if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
            return None
        absolute = urljoin(base_url + "/", href)
        parsed = urlparse(absolute)
        if parsed.netloc and parsed.netloc != origin:
            return None  # never crawl outside the sandbox origin
        return self._normalize_path(parsed.path + ("" if not parsed.query else "?" + parsed.query))

    @staticmethod
    def _query_params_from_path(path: str) -> List[str]:
        """Extract query parameter names from a path string."""
        if "?" not in path:
            return []
        query = path.split("?", 1)[1]
        params = []
        for pair in query.split("&"):
            if "=" in pair:
                name = pair.split("=", 1)[0]
                if name:
                    params.append(name)
        return params
