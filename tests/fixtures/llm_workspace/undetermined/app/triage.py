"""Seeded undetermined posture: prompt-shaped assembly without a recognized
integration pattern (spec 007 edge case; quickstart Scenario 6)."""


def draft_reply(ticket: str) -> str:
    messages = [{"role": "system", "content": "You triage tickets."}]
    messages.append({"role": "user", "content": ticket})
    return dispatch(messages)


def dispatch(messages):
    raise NotImplementedError
