"""Seeded vulnerable surface: user input interpolated into the system prompt."""

from flask import Flask, request
from openai import OpenAI

client = OpenAI()
app = Flask(__name__)


@app.route("/chat", methods=["POST"])
def chat():
    question = request.json["question"]
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": f"You are helpful. User said: {question}"},
        ],
    )
    return response.choices[0].message.content
