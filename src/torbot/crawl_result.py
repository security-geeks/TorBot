"""Versioned, integration-safe crawl results.

This module intentionally contains only data adaptation.  It does not import
GoTor or expose either crawler's implementation details.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from importlib import metadata
from time import monotonic
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4


SCHEMA_VERSION = 1
ENGINE = "torbot"


def _version() -> str:
    try:
        return metadata.version("torbot")
    except metadata.PackageNotFoundError:
        return "unknown"


def normalize_target(value: str) -> str:
    """Normalize a target without removing its meaningful path or query."""
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("target must be an absolute HTTP(S) URL")
    host = parsed.hostname.lower()
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("target has an invalid port") from exc
    if ":" in host:
        host = f"[{host}]"
    if port:
        host = f"{host}:{port}"
    return urlunsplit((parsed.scheme.lower(), host, parsed.path or "/", parsed.query, ""))


def error_category(error: BaseException | str | None) -> str:
    """Return a bounded category; never serialize an arbitrary exception message."""
    if error is None:
        return "unknown"
    value = str(error).lower()
    if "cancel" in value:
        return "cancelled"
    if "invalid" in value or "url" in value:
        return "invalid_input"
    if any(token in value for token in ("timeout", "connect", "network", "proxy", "request")):
        return "network"
    if any(token in value for token in ("parse", "html", "empty response")):
        return "parse"
    return "unknown"


class CrawlResultAdapter:
    """Adapt a completed :class:`LinkTree` to the shared crawl-result v1 shape."""

    def __init__(self, tree: Any, *, uses_tor: bool, started_at: datetime | None = None):
        self.tree = tree
        self.uses_tor = uses_tor
        self.started_at = (
            started_at
            or getattr(tree, "crawl_started_at", None)
            or datetime.now(timezone.utc)
        )
        self._started_monotonic = getattr(tree, "crawl_started_monotonic", monotonic())

    def result(
        self,
        *,
        terminal_status: str = "completed",
        run_id: str | None = None,
        diagnostics: dict[str, str] | None = None,
        include_text: bool = False,
    ) -> dict[str, Any]:
        if terminal_status not in {"completed", "cancelled", "failed", "invalid"}:
            raise ValueError("unsupported terminal status")
        ended_at = datetime.now(timezone.utc)
        pages = [self._page(node, include_text=include_text) for node in self.tree.all_nodes_itr()]
        pages.extend(getattr(self.tree, "crawl_failures", []))
        pages.sort(key=lambda page: (page["depth"], page["url"]))
        result = {
            "schemaVersion": SCHEMA_VERSION,
            "runId": run_id or str(uuid4()),
            "engine": ENGINE,
            "engineVersion": _version(),
            "target": normalize_target(self.tree._url),
            "settings": {"maxDepth": self.tree._depth, "usesTor": self.uses_tor},
            "terminalStatus": terminal_status,
            "cancelled": terminal_status == "cancelled",
            "startedAt": self.started_at.isoformat().replace("+00:00", "Z"),
            "endedAt": ended_at.isoformat().replace("+00:00", "Z"),
            "durationMs": int((monotonic() - self._started_monotonic) * 1000),
            "pages": pages,
            "diagnostics": _safe_diagnostics(diagnostics or {}),
        }
        return result

    def _page(self, node: Any, *, include_text: bool = False) -> dict[str, Any]:
        parent = self.tree.parent(node.identifier)
        depth = self.tree.depth(node.identifier)
        links = []
        for child in self.tree.children(node.identifier):
            links.append({"url": child.identifier, "source": "anchor"})
        contacts = []
        contacts.extend(
            {"value": email, "source": "mailto"} for email in sorted(node.data.emails)
        )
        contacts.extend(
            {"value": phone, "source": "tel"} for phone in sorted(node.data.numbers)
        )
        page = {
            "url": node.identifier,
            "parentUrl": parent.identifier if parent else None,
            "depth": depth,
            "outcome": "fetched",
            "status": node.data.status,
            "skippedReason": None,
            "errorCategory": None,
            "links": links,
            "contacts": contacts,
            "title": node.tag,
            "classification": {
                "label": node.data.classification,
                "accuracy": node.data.accuracy,
            },
        }
        if include_text:
            text = getattr(node.data, "text", "")
            page["content"] = {
                "mediaType": "text/plain",
                "text": text,
                "sha256": getattr(
                    node.data,
                    "content_hash",
                    hashlib.sha256(text.encode("utf-8")).hexdigest(),
                ),
            }
        return page


def failed_page(
    url: str, parent_url: str | None, depth: int, error: BaseException | str
) -> dict[str, Any]:
    """Create a privacy-safe per-page failure record."""
    return {
        "url": url,
        "parentUrl": parent_url,
        "depth": depth,
        "outcome": "failed",
        "status": None,
        "skippedReason": None,
        "errorCategory": error_category(error),
        "links": [],
        "contacts": [],
    }


def invalid_result(target: str, *, run_id: str | None = None) -> dict[str, Any]:
    """Return a terminal v1 result for invalid input without echoing it in diagnostics."""
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "schemaVersion": SCHEMA_VERSION,
        "runId": run_id or str(uuid4()),
        "engine": ENGINE,
        "engineVersion": _version(),
        "target": target,
        "settings": {},
        "terminalStatus": "invalid",
        "cancelled": False,
        "startedAt": now,
        "endedAt": now,
        "durationMs": 0,
        "pages": [failed_page(target, None, 0, "invalid input")],
        "diagnostics": {},
    }


def _safe_diagnostics(diagnostics: dict[str, str]) -> dict[str, str]:
    """Allow only caller-selected, scalar diagnostics and omit secret-like keys."""
    blocked = ("cookie", "token", "secret", "password", "authorization", "credential")
    return {
        key: str(value)
        for key, value in diagnostics.items()
        if isinstance(key, str) and isinstance(value, (str, int, float, bool))
        and not any(word in key.lower() for word in blocked)
    }
