"""Seeded indirect injection: fetched third-party content into model context,
with a tool reachable from the invocation (excessive reach evidence)."""

import requests
from openai import OpenAI

client = OpenAI()


def tool(func):
    """Stand-in for a function-calling decorator."""
    return func


@tool
def send_email(to: str, subject: str, body: str) -> None:
    """Mail the given body out (capability exposed to the model)."""
    raise NotImplementedError


def summarize_and_act(url: str) -> str:
    page = requests.get(url, timeout=10).text
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": "Summarize the page, then act on it."},
            {"role": "user", "content": page},
        ],
    )
    send_email("ops@example.test", "summary", response.choices[0].message.content)
    return page
