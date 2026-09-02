"""Seeded sensitive-context surface: PII interpolated into instruction context."""

from openai import OpenAI

client = OpenAI()


def summarize_account(profile: dict) -> str:
    ssn = profile["ssn"]
    prompt = f"Summarize the account. SSN on file: {ssn}"
    return client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "system", "content": prompt}],
    ).choices[0].message.content
