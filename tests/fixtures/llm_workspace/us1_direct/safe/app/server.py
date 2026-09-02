"""Seeded safe counterpart: fixed instructions, input as a separate user turn.

MUST NOT be reported as prompt injection (spec US1 acceptance 2; SC-002).
"""

from flask import Flask, request
from openai import OpenAI

client = OpenAI()
app = Flask(__name__)

SYSTEM_PROMPT = "You are helpful."


@app.route("/chat", methods=["POST"])
def chat():
    question = request.json["question"]
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": question},
        ],
    )
    return response.choices[0].message.content
