"""Configuration-file representation (FR-026, FR-029).

Dependency manifests, deployment config, datastore rules and client-cache config
were enumerated by the file walker but never given a graph node, so partitioning —
which groups by node — left them in no segment at all. In the reviewed benchmark
that meant `package.json`, `firebase.json`, `database.rules.json` and
`ngsw-config.json` were invisible: the dependency domain went entirely unassessed,
and the absence of a Content-Security-Policy was found only by a manual spot check.

Nothing here parses configuration semantically. These nodes exist so the files
belong to a segment, appear in the coverage statement, and can carry a finding —
claiming to understand their contents would be a different and much larger job.
"""

from __future__ import annotations

from dataclasses import dataclass

from pipeline import stacks


@dataclass(frozen=True)
class ConfigFile:
    """A security-relevant configuration file, recorded at file granularity."""

    path: str
    file_class: str
    #: the filename that identified it, which is also its format label
    format: str

    @property
    def annotations(self) -> tuple[str, ...]:
        # Deployment and datastore configuration decides what is exposed and to
        # whom, so it sits on a trust boundary even when nothing parses it.
        if self.file_class in ("deploy-config", "datastore-rules"):
            return ("trust_boundary",)
        # AI agent/tool configuration and prompt artifacts govern model behavior
        # (spec 007): they are reviewable artifacts and must be reachable so the
        # coverage statement can distinguish absent from unexamined (FR-011).
        if self.file_class in ("ai-agent-config", "ai-mcp-config", "prompt-artifact"):
            return ("ai_config",)
        return ()


def classify(relative: str) -> ConfigFile | None:
    """Recognize ``relative`` as a security-relevant config file, or ``None``.

    Driven by the shipped stack descriptors, so adding a manifest or platform
    file is a data change (FR-025b).
    """
    name = relative.rsplit("/", 1)[-1]
    file_class = stacks.file_class_for(name)
    if file_class is None:
        return None
    return ConfigFile(path=relative, file_class=file_class, format=name)


def is_config(relative: str) -> bool:
    return classify(relative) is not None
