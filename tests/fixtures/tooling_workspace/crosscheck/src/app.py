"""Cross-check fixture application code."""


def render(raw: str) -> str:
    """Deliberately trivial: exists only as a resolvable finding location."""
    return f"<p>{raw}</p>"
