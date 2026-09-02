"""Spec 007, T019/T026: deterministic LLM-integration recognition unit tests."""

from __future__ import annotations

from pipeline.extract import Symbol
from pipeline.extract.llm_integration import annotate, hint_notes_for


def sym(name: str, start: int, end: int) -> Symbol:
    return Symbol(name=name, kind="function", line_start=start, line_end=end)


VULNERABLE_PY = '''from openai import OpenAI

client = OpenAI()

def chat(question: str) -> str:
    system_prompt = f"You answer questions. The user said: {question}"
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "system", "content": system_prompt}],
    )
    return response.choices[0].message.content
'''

SAFE_PY = '''import openai

SYSTEM_PROMPT = "You answer customer questions."

def chat(question: str) -> str:
    response = openai.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": question},
        ],
    )
    return response.choices[0].message.content
'''

NO_LLM_PY = '''def add(a: int, b: int) -> int:
    return a + b
'''

CANDIDATE_PY = '''def draft_reply(ticket: str) -> str:
    messages = [{"role": "system", "content": "You triage tickets."}]
    messages.append({"role": "user", "content": ticket})
    return dispatch(messages)
'''

READER_PY = '''import requests
from openai import OpenAI

client = OpenAI()

def summarize(url: str) -> str:
    body = requests.get(url, timeout=10).text
    return client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": "Summarize the document."},
            {"role": "user", "content": body},
        ],
    ).choices[0].message.content
'''

TOOLS_PY = '''from anthropic import Anthropic

client = Anthropic()

def agent(query: str) -> str:
    return client.messages.create(
        model="claude-sonnet-4-5",
        tools=[{"name": "run_shell", "input_schema": {}}],
        messages=[{"role": "user", "content": query}],
    ).content[0].text
'''

LOCAL_PY = '''import requests

def chat_local(question: str) -> str:
    return requests.post(
        "http://localhost:11434/api/generate",
        json={"model": "llama3", "prompt": f"Context: {question}"},
        timeout=30,
    ).json()["response"]
'''


def _annotate(text: str, names: list[str]):
    symbols = [
        sym(name, start, end)
        for name, start, end in _symbol_spans(text, names)
    ]
    return annotate(text, symbols, language="python")


def _symbol_spans(text: str, names: list[str]):
    lines = text.splitlines()
    for name in names:
        start = next(
            i for i, ln in enumerate(lines, 1) if ln.startswith(f"def {name}(")
        )
        end = start
        for i in range(start + 1, len(lines) + 1):
            if lines[i - 1].startswith(("def ", "class ")):
                break
            end = i
        yield name, start, end


def test_vulnerable_prompt_construction_is_a_sink() -> None:
    marks = _annotate(VULNERABLE_PY, ["chat"])
    assert "llm_invocation" in marks.marks_for("chat")
    assert "llm_prompt_sink" in marks.marks_for("chat")


def test_structured_separation_is_recognized_but_not_a_sink() -> None:
    """Safe usage: fixed instructions, user input in a separate user turn."""
    marks = _annotate(SAFE_PY, ["chat"])
    assert "llm_invocation" in marks.marks_for("chat")
    assert "llm_prompt_sink" not in marks.marks_for("chat")
    assert "llm_undetermined" not in marks.file_annotations


def test_non_llm_code_is_unmarked() -> None:
    marks = _annotate(NO_LLM_PY, ["add"])
    assert not marks.marks_for("add")
    assert not marks.file_annotations


def test_unrecognized_integration_gets_an_undetermined_posture() -> None:
    marks = _annotate(CANDIDATE_PY, ["draft_reply"])
    assert "llm_undetermined" in marks.marks_for("draft_reply")
    assert "llm_undetermined" in marks.file_annotations
    notes = hint_notes_for(CANDIDATE_PY)
    assert notes and "undetermined" in notes[0]


def test_third_party_content_readers_are_sources() -> None:
    marks = _annotate(READER_PY, ["summarize"])
    assert "external_content_source" in marks.marks_for("summarize")
    assert "llm_invocation" in marks.marks_for("summarize")


def test_explicit_data_boundary_is_marked() -> None:
    const = BOUNDED_PY
    marks = _annotate(const, ["label_untrusted", "summarize"])
    assert "boundary_labeled" in marks.marks_for("label_untrusted")
    assert "boundary_labeled" in marks.marks_for("summarize")


BOUNDED_PY = '''import requests
from openai import OpenAI

client = OpenAI()

def label_untrusted(text: str) -> str:
    return "<data>" + text + "</data>"

def summarize(url: str) -> str:
    page = label_untrusted(requests.get(url, timeout=10).text)
    return client.chat.completions.create(
        model="x",
        messages=[{"role": "user", "content": page}],
    ).choices[0].message.content
'''


def test_tool_declarations_are_marked() -> None:
    marks = _annotate(TOOLS_PY, ["agent"])
    assert "tool_declaration" in marks.marks_for("agent")
    assert "llm_invocation" in marks.marks_for("agent")


def test_local_model_endpoints_are_recognized() -> None:
    marks = _annotate(LOCAL_PY, ["chat_local"])
    assert "llm_invocation" in marks.marks_for("chat_local")
    assert "llm_prompt_sink" in marks.marks_for("chat_local")


def test_raw_http_calls_to_model_api_hosts_are_recognized() -> None:
    text = '''import requests

def chat(q: str) -> str:
    return requests.post(
        "https://api.openai.com/v1/chat/completions",
        json={"messages": [{"role": "user", "content": f"{q}"}]},
        timeout=30,
    ).json()
'''
    marks = _annotate(text, ["chat"])
    assert "llm_invocation" in marks.marks_for("chat")
    assert "llm_prompt_sink" in marks.marks_for("chat")
