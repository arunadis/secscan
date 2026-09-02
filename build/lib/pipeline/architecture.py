"""Architecture classification (FR-013–FR-014).

Determines the *execution shape* of a workspace member or segment, because a
weakness class can be structurally impossible for one shape and entirely real for
another. Server-side request forgery needs something that issues server-side
requests; a browser-only client has no internal network to reach, no ambient
credentials, and no metadata endpoint.

Two rules govern everything here, and both exist because the alternative is a
confident guess:

* **A recorded shape reflects positive evidence.** Every non-``undetermined``
  profile carries the facts that determined it (FR-013b).
* **Unknown is a state, not a default.** When nothing decides the question the
  shape is ``undetermined`` with a reason, and applicability-based suppression is
  switched off for that scope (FR-013a). An unknown must never buy silence.

Detection is deterministic, offline, and driven by dependency-manifest markers
plus the code model's own entry points — no model reasoning (FR-013).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SERVER = "server-request-issuer"
BROWSER = "browser-client"
CLI = "cli"
LIBRARY = "library"
UNDETERMINED = "undetermined"

SHAPES = (SERVER, BROWSER, CLI, LIBRARY, UNDETERMINED)

#: Dependency names that identify a server-side request issuer. Presence of a
#: server framework OR a server-side HTTP client is enough: both mean requests
#: can originate inside the trust boundary.
_SERVER_MARKERS = (
    "flask", "django", "fastapi", "starlette", "tornado", "bottle", "pyramid", "aiohttp",
    "express", "koa", "hapi", "@nestjs/core", "next", "nuxt", "fastify",
    "spring-boot-starter-web", "spring-webmvc", "javax.servlet", "jakarta.servlet",
    "github.com/gin-gonic/gin", "github.com/labstack/echo", "net/http",
    "requests", "httpx", "urllib3", "axios", "node-fetch", "got",
)

#: Dependency names that identify a browser-only client.
_BROWSER_MARKERS = (
    "@angular/platform-browser", "@angular/core", "react-dom", "vue", "svelte",
    "preact", "ember-source", "backbone", "jquery",
)

#: Markers that specifically mean "this runs in a browser and ships as static
#: assets", which outweighs a generic HTTP-client dependency.
_STATIC_BUILD_MARKERS = ("index.html", "firebase.json", "vercel.json", "netlify.toml")

_CLI_ENTRY = re.compile(
    r"(?:console_scripts|\[project\.scripts\]|argparse|click\.command|cobra\.Command|"
    r"\"bin\"\s*:)",
)


@dataclass(frozen=True)
class ArchitectureProfile:
    """A member's or segment's execution shape, with the evidence for it."""

    scope: str
    shape: str
    evidence: tuple[str, ...] = ()
    undetermined_reason: str | None = None

    def __post_init__(self) -> None:
        if self.shape not in SHAPES:
            raise ValueError(f"unknown architecture shape: {self.shape}")

    @property
    def determined(self) -> bool:
        return self.shape != UNDETERMINED

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"scope": self.scope, "shape": self.shape}
        if self.determined:
            out["evidence"] = list(self.evidence)
        else:
            out["undetermined_reason"] = self.undetermined_reason or "no decisive evidence found"
        return out

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ArchitectureProfile:
        return cls(
            scope=raw["scope"],
            shape=raw["shape"],
            evidence=tuple(raw.get("evidence") or ()),
            undetermined_reason=raw.get("undetermined_reason"),
        )


@dataclass
class _Signals:
    server: list[str] = field(default_factory=list)
    browser: list[str] = field(default_factory=list)
    cli: list[str] = field(default_factory=list)
    static_build: list[str] = field(default_factory=list)
    has_manifest: bool = False


def _read(path: Path) -> str:
    try:
        return path.read_text(errors="replace")
    except OSError:
        return ""


def _dependency_names(root: Path) -> tuple[set[str], bool]:
    """Declared dependency names across recognized manifests, and whether any existed."""
    names: set[str] = set()
    found = False

    package_json = root / "package.json"
    if package_json.exists():
        found = True
        try:
            document = json.loads(package_json.read_text())
        except (OSError, json.JSONDecodeError):
            document = {}
        for key in ("dependencies", "devDependencies", "peerDependencies"):
            names.update(document.get(key) or {})

    for name in ("requirements.txt", "pyproject.toml", "setup.py", "setup.cfg"):
        path = root / name
        if path.exists():
            found = True
            text = _read(path).lower()
            names.update(re.findall(r"^\s*([a-z0-9][a-z0-9._-]+)", text, re.M))

    for name in ("pom.xml", "build.gradle", "build.gradle.kts", "go.mod"):
        path = root / name
        if path.exists():
            found = True
            names.update(re.findall(r"[A-Za-z0-9._/\-]+", _read(path)))

    return {n.lower() for n in names}, found


def _collect(root: Path, manifest: dict[str, Any] | None) -> _Signals:
    signals = _Signals()
    names, signals.has_manifest = _dependency_names(root)

    for marker in _SERVER_MARKERS:
        if marker.lower() in names:
            signals.server.append(f"depends on '{marker}'")
    for marker in _BROWSER_MARKERS:
        if marker.lower() in names:
            signals.browser.append(f"depends on '{marker}'")
    for marker in _STATIC_BUILD_MARKERS:
        if (root / marker).exists():
            signals.static_build.append(f"ships '{marker}'")

    # Entry points recorded by discovery are the strongest server signal there is:
    # an HTTP route means this member answers requests.
    for entry in (manifest or {}).get("entrypoints") or []:
        kind = entry.get("kind")
        if kind in ("http", "rpc", "consumer"):
            signals.server.append(f"exposes {kind} entry point '{entry.get('symbol')}'")
        elif kind == "cli":
            signals.cli.append(f"exposes CLI entry point '{entry.get('symbol')}'")

    for name in ("pyproject.toml", "setup.py", "package.json", "main.go"):
        path = root / name
        if path.exists() and _CLI_ENTRY.search(_read(path)):
            signals.cli.append(f"declares a command entry point in '{name}'")

    return signals


def classify_member(
    root: Path, manifest: dict[str, Any] | None = None, scope: str = "member"
) -> ArchitectureProfile:
    """Classify one workspace member from its manifests and discovered entry points."""
    signals = _collect(root, manifest)

    # A static browser build outweighs a generic HTTP-client dependency: `axios`
    # in a single-page app issues requests from the victim's browser, not from
    # inside a trust boundary. This distinction is the whole point of the shape.
    browser_only = (signals.browser or signals.static_build) and not any(
        "entry point" in item for item in signals.server
    )

    if browser_only:
        evidence = [*signals.browser, *signals.static_build]
        evidence.append("no server-side entry point was discovered")
        return ArchitectureProfile(scope, BROWSER, tuple(sorted(evidence)))

    if signals.server:
        return ArchitectureProfile(scope, SERVER, tuple(sorted(set(signals.server))))

    if signals.cli:
        return ArchitectureProfile(scope, CLI, tuple(sorted(set(signals.cli))))

    if signals.has_manifest:
        return ArchitectureProfile(
            scope,
            LIBRARY,
            (
                "declares a package manifest",
                "no server, browser, or command entry point was discovered",
            ),
        )

    return ArchitectureProfile(
        scope,
        UNDETERMINED,
        undetermined_reason=(
            "no dependency manifest, entry point, or build marker identified an "
            "execution shape; applicability-based suppression is disabled for this scope"
        ),
    )


def shapes_for(profiles: dict[str, ArchitectureProfile], members: list[str]) -> set[str]:
    """The set of shapes across ``members``, for applicability evaluation.

    A member with no profile contributes ``undetermined`` rather than nothing,
    so a gap in classification can never silently narrow the reachable set.
    """
    return {
        profiles[name].shape if name in profiles else UNDETERMINED for name in members
    } or {UNDETERMINED}
