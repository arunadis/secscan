"""Stage 3: partition into security-relevant segments (FR-004).

Segments follow security/business boundaries — never line counts. The strategy:

1. group files by their functional module (the directory that carries meaning in
   the repository layout), which is what actually maps to auth / payments /
   upload style boundaries;
2. attach each module's entry points, data stores, and dependencies from the
   code graph;
3. derive the vulnerability domains relevant to the segment (FR-011);
4. subdivide any segment that cannot fit the context budget, rather than
   truncating code (edge case).
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path
from typing import Any

from pipeline import architecture
from pipeline.budget import estimate_tokens
from pipeline.discover_repo import member_paths
from pipeline.state import ArtifactStore

#: annotation -> domains worth analyzing when present
DOMAIN_BY_ANNOTATION: dict[str, tuple[str, ...]] = {
    "user_controlled_input": ("injection", "api-security"),
    "security_sink": ("injection", "deserialization"),
    "trust_boundary": ("authentication", "authorization", "api-security"),
    "authentication_required": ("authentication", "session-management"),
    "authorization_required": ("authorization",),
    "sensitive_data": ("data-protection", "secrets", "pii", "encryption"),
    "external_system": ("ssrf", "api-security", "pii"),
    "template_sink": ("injection",),
    "control_bypass": ("injection",),
    "fixed_prefix_sink": ("api-security",),
    # spec 007: modern-exploit category follows code facts; only segments with
    # LLM evidence receive the llm-security domain (FR-010 zero noise)
    "llm_invocation": ("llm-security",),
    "llm_prompt_sink": ("llm-security",),
    "tool_declaration": ("llm-security",),
    "external_content_source": ("llm-security",),
    "llm_undetermined": ("llm-security",),
}

#: file class -> domains worth analyzing when a segment contains one.
#:
#: Domains must follow the code facts present in a segment, not its name
#: (FR-028). The reviewed benchmark missed an analytics call sending user-bearing
#: paths to a third party because the personal-data domain had been assigned to
#: the segment *named* for users, while the call lived elsewhere.
DOMAIN_BY_FILE_CLASS: dict[str, tuple[str, ...]] = {
    "template": ("injection",),
    "dependency-manifest": ("dependencies",),
    "deploy-config": ("infrastructure", "data-protection"),
    "datastore-rules": ("authorization", "infrastructure"),
    "client-cache-config": ("infrastructure", "data-protection"),
    "ai-agent-config": ("llm-security",),
    "ai-mcp-config": ("llm-security",),
    "prompt-artifact": ("llm-security",),
}

#: module-name hint -> additional domains
DOMAIN_BY_NAME: dict[str, tuple[str, ...]] = {
    "auth": ("authentication", "authorization", "session-management"),
    "login": ("authentication", "session-management"),
    "user": ("authorization", "pii"),
    "admin": ("authorization",),
    "payment": ("authorization", "data-protection", "api-security"),
    "billing": ("authorization", "data-protection"),
    "upload": ("file-handling", "path-traversal"),
    "file": ("file-handling", "path-traversal"),
    "report": ("injection", "authorization"),
    "config": ("secrets", "infrastructure"),
    "settings": ("secrets", "infrastructure"),
    "order": ("authorization", "injection"),
    "crypto": ("encryption",),
    "session": ("session-management",),
    "api": ("api-security", "rate-limiting"),
}

_ALWAYS = ("injection", "authorization", "secrets")


def module_of(path: str) -> str:
    """The meaningful module for ``path`` (its owning package directory)."""
    parts = path.split("/")
    if len(parts) == 1:
        return "."
    # Skip conventional container directories so `src/orders/api.py` -> `orders`.
    skip = {"src", "app", "lib", "pkg", "internal", "main", "java", "resources", "test", "tests"}
    for part in parts[:-1]:
        if part not in skip:
            return part
    return parts[-2]


#: File classes that identify a segment as browser-delivered regardless of what
#: the member as a whole looks like.
_BROWSER_CLASSES = frozenset({"template", "client-cache-config"})


def segment_architecture(
    segment: dict[str, Any],
    member_profile: dict[str, Any] | None,
    file_classes: set[str],
    annotations: set[str],
) -> dict[str, Any] | None:
    """Segment-scope architecture, or ``None`` when it matches the member (FR-014).

    Recorded **only on difference**, which is what the schema says and what makes a
    hybrid repository representable: a Django project whose `templates/` segment is
    browser-delivered while its `api/` segment issues server-side requests. Writing
    the member's shape onto every segment would be noise, and would also make a
    genuine divergence harder to spot.

    Conservative by construction. A segment is reclassified only on positive
    evidence that it is browser-delivered *and* has no server-side entry point of
    its own; anything else inherits the member's shape by returning ``None``.
    Guessing here would feed the applicability relation a narrower architecture
    than the truth, and that direction produces false negatives.
    """
    if member_profile is None:
        return None

    member_shape = member_profile.get("shape")
    if member_shape in (architecture.BROWSER, architecture.UNDETERMINED):
        return None  # nothing to diverge from, or nothing known to diverge from

    browser_evidence = sorted(file_classes & _BROWSER_CLASSES)
    if not browser_evidence:
        return None
    if "trust_boundary" in annotations or segment.get("entrypoints"):
        # The segment answers requests itself, so it is not browser-only however
        # many templates it contains.
        return None

    return architecture.ArchitectureProfile(
        scope="segment",
        shape=architecture.BROWSER,
        evidence=(
            *(f"contains {name} files" for name in browser_evidence),
            "no server-side entry point in this segment",
            f"member '{segment['repos'][0]}' is {member_shape}, so this segment differs",
        ),
    ).to_dict()


def _domains_for(
    name: str, annotations: set[str], file_classes: set[str] | None = None
) -> list[str]:
    """Domains to analyze for a segment.

    Driven by the code facts the segment actually contains — annotations and file
    classes — with module-name hints kept only as an additional signal. Name-only
    assignment is what let a third-party egress call escape personal-data analysis
    in the reviewed benchmark (FR-028).
    """
    domains: set[str] = set(_ALWAYS)
    lowered = name.lower()
    for hint, extra in DOMAIN_BY_NAME.items():
        if hint in lowered:
            domains.update(extra)
    for annotation in annotations:
        domains.update(DOMAIN_BY_ANNOTATION.get(annotation, ()))
    for file_class in file_classes or ():
        domains.update(DOMAIN_BY_FILE_CLASS.get(file_class, ()))
    return sorted(domains)


def _segment_id(repo: str, module: str, suffix: str = "") -> str:
    base = f"seg-{repo}-{module}".replace("/", "-").replace(".", "root")
    return f"{base}{suffix}"


def build_segments(
    store: ArtifactStore,
    workspace: dict[str, Any],
    graph: dict[str, Any],
    max_context_tokens: int,
) -> list[dict[str, Any]]:
    nodes_by_file: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for node in graph["nodes"]:
        if node["path"] == "<datastore>":
            continue
        nodes_by_file[(node["repo"], node["path"])].append(node)

    roots = member_paths(store, workspace)
    # Member profiles, so a segment can be compared against its member's shape
    # and recorded only when the two differ (FR-014).
    manifests = {
        repo: store.read_optional(f"repository/{repo}.manifest.json") or {} for repo in roots
    }
    grouped: dict[tuple[str, str], dict[str, Any]] = {}

    for (repo, path), nodes in sorted(nodes_by_file.items()):
        module = module_of(path)
        key = (repo, module)
        bucket = grouped.setdefault(
            key,
            {
                "files": set(),
                "entrypoints": set(),
                "annotations": set(),
                "data_stores": set(),
                "symbols": set(),
                "file_classes": set(),
            },
        )
        bucket["files"].add(path)
        for node in nodes:
            bucket["annotations"].update(node.get("annotations") or [])
            if node.get("file_class"):
                bucket["file_classes"].add(node["file_class"])
            if node["type"] == "endpoint":
                bucket["entrypoints"].add(node.get("route", ""))
            if node.get("symbol"):
                bucket["symbols"].add(node["symbol"])

    # data stores and cross-file dependencies from edges
    deps: dict[tuple[str, str], set[str]] = defaultdict(set)
    stores: dict[tuple[str, str], set[str]] = defaultdict(set)
    node_index = {node["id"]: node for node in graph["nodes"]}
    for edge in graph["edges"]:
        source = node_index.get(edge["from"])
        target = node_index.get(edge["to"])
        if source is None or target is None:
            continue
        source_key = (source["repo"], module_of(source["path"]))
        if target["type"] == "datastore":
            stores[source_key].add(target.get("symbol") or "datastore")
            continue
        target_key = (target["repo"], module_of(target["path"]))
        if target_key != source_key:
            deps[source_key].add(f"{target_key[0]}/{target_key[1]}")

    segments: list[dict[str, Any]] = []
    for (repo, module), bucket in sorted(grouped.items()):
        root = roots[repo]
        files = sorted(bucket["files"])
        tokens = _tokens_for(root, files)
        segment = {
            "id": _segment_id(repo, module),
            "name": module.replace("_", " ").replace("-", " ").title() or repo,
            "repos": [repo],
            "purpose": _purpose(module, bucket),
            "domains": _domains_for(
                module, bucket["annotations"], bucket["file_classes"]
            ),
            "entrypoints": sorted(e for e in bucket["entrypoints"] if e),
            "files": files,
            "dependencies": sorted(deps[(repo, module)]),
            "data_stores": sorted(stores[(repo, module)]),
            "estimated_tokens": tokens,
        }
        profile = segment_architecture(
            segment,
            (manifests.get(repo) or {}).get("architecture"),
            bucket["file_classes"],
            bucket["annotations"],
        )
        if profile is not None:
            segment["architecture"] = profile
        segments.extend(_subdivide(segment, root, max_context_tokens))

    return sorted(segments, key=lambda s: s["id"])


def _tokens_for(root: Path, files: list[str]) -> int:
    total = 0
    for relative in files:
        path = root / relative
        try:
            total += estimate_tokens(path.read_text(errors="replace"))
        except OSError:
            continue
    return total


def _purpose(module: str, bucket: dict[str, Any]) -> str:
    label = module.replace("_", " ").replace("-", " ")
    bits = [f"Handles {label} functionality"]
    if bucket["entrypoints"]:
        bits.append(f"exposes {len(bucket['entrypoints'])} entry point(s)")
    if "security_sink" in bucket["annotations"]:
        bits.append("performs data-store operations")
    if "sensitive_data" in bucket["annotations"]:
        bits.append("touches sensitive data")
    return "; ".join(bits) + "."


def _subdivide(segment: dict[str, Any], root: Path, budget: int) -> list[dict[str, Any]]:
    """Split a segment that cannot fit the budget, never truncating code."""
    #: reserve room for the structural parts of a context packet
    usable = max(1, int(budget * 0.7))
    if segment["estimated_tokens"] <= usable or len(segment["files"]) <= 1:
        return [segment]

    parts: list[dict[str, Any]] = []
    current: list[str] = []
    current_tokens = 0
    for relative in segment["files"]:
        tokens = _tokens_for(root, [relative])
        if current and current_tokens + tokens > usable:
            parts.append(_part(segment, parts, current, current_tokens))
            current, current_tokens = [], 0
        current.append(relative)
        current_tokens += tokens
    if current:
        parts.append(_part(segment, parts, current, current_tokens))
    return parts


def _part(
    segment: dict[str, Any], existing: list[dict[str, Any]], files: list[str], tokens: int
) -> dict[str, Any]:
    index = len(existing) + 1
    part = dict(segment)
    part["id"] = f"{segment['id']}-p{index}"
    part["name"] = f"{segment['name']} (part {index})"
    part["files"] = sorted(files)
    part["estimated_tokens"] = tokens
    part["subdivided_from"] = segment["id"]
    part["entrypoints"] = sorted(segment["entrypoints"]) if index == 1 else []
    return part


def run(
    store: ArtifactStore,
    workspace: dict[str, Any],
    graph: dict[str, Any],
    max_context_tokens: int,
) -> list[dict[str, Any]]:
    segments = build_segments(store, workspace, graph, max_context_tokens)
    for segment in segments:
        store.write(f"segments/{segment['id']}.json", "partition_repo", segment, "segment")
    return segments


def main() -> None:  # pragma: no cover - CLI wrapper
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--max-context-tokens", type=int, default=12000)
    args = parser.parse_args()
    store = ArtifactStore(args.workdir)
    segments = run(
        store,
        store.read("workspace.json"),
        store.read("code-graph.json"),
        args.max_context_tokens,
    )
    print(f"partitioned into {len(segments)} segment(s)")


if __name__ == "__main__":  # pragma: no cover
    main()
