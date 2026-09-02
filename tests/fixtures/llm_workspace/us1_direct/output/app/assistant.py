"""Seeded insecure-output-handling surface: model output executed unvalidated."""

import os

from openai import OpenAI

client = OpenAI()


def ask_and_run(topic: str) -> str:
    response = client.responses.create(model="gpt-4o", input=topic)
    command = response.output_text
    os.system(command)
    return command
