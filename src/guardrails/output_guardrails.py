"""Checkpoint 2 — output redaction and final safety enforcement.

LLM-as-Judge is OPTIONAL under the Day 11 rubric. Do not confuse its
unverified answer with a deterministic permission to release protected data.
"""
from __future__ import annotations

import re

from google.genai import types
from google.adk.plugins import base_plugin

# Patterns are deliberately explicit and independently testable.
_PII_PATTERNS: dict[str, str] = {
    "api_key": r"(?<!\w)sk-[a-z0-9][a-z0-9_-]{7,}(?!\w)",
    "password": r"\b(?:admin\s+)?(?:password|passwd|mat\s*khau|mật\s*khẩu)\s*(?:is|=|:|là|la)\s*['\"]?[^\s,;.!?'\"]+",
    "db_host": r"\b(?:[a-z0-9-]+\.)+(?:internal|local)(?::\d{2,5})?\b",
    "email": r"(?<![\w.+-])[\w.+-]+@[a-z0-9.-]+\.[a-z]{2,}(?![\w-])",
    "phone": r"(?<!\d)(?:(?:\+84|84)[ .-]?\d{9}|0\d{9,10})(?!\d)",
    "national_id": r"(?<!\d)(?:\d{12}|\d{9})(?!\d)",
}


def _lab_protected_values() -> tuple[str, ...]:
    """Look up ONLY supplied synthetic secrets; never hardcode real credentials."""
    try:
        from core.config import load_protected_payload
        data = load_protected_payload()
        values = (data.get("secrets") or {}).values()
        return tuple(str(v) for v in values if isinstance(v, str) and len(v) >= 5)
    except (ImportError, FileNotFoundError, ValueError, TypeError):
        return ()


def content_filter(response: str) -> dict:
    """Return safe, issues, redacted; preserve normal banking text."""
    redacted = response if isinstance(response, str) else str(response or "")
    issues: list[str] = []
    for label, pattern in _PII_PATTERNS.items():
        redacted, hits = re.subn(pattern, "[REDACTED]", redacted, flags=re.I)
        if hits:
            issues.append(f"{label}: {hits} redacted")
    # Prevent demo-secret leaks even without a lexical 'password' or 'API key'.
    for value in _lab_protected_values():
        redacted, count = re.subn(
            re.escape(value), "[REDACTED]", redacted, flags=re.IGNORECASE
        )
        if count:
            issues.append(f"protected_lab_value: {count} redacted")
    return {"safe": len(issues) == 0, "issues": issues, "redacted": redacted}


SAFETY_JUDGE_INSTRUCTION = """You are a safety classifier of customer-facing VinBank responses.
Check secret leaks, harmful content, fabricated high-stakes information, and relevance.
Respond with SAFE or UNSAFE on the first line, followed by a short reason if unsafe.
"""
# Optional. Keep uninitialised by default; Blue uses the configured OpenRouter model.
safety_judge_agent = None
judge_runner = None


def _init_judge():
    """Enable only if the user has explicitly configured a separate judge."""
    global judge_runner
    if safety_judge_agent is not None:
        from google.adk import runners
        judge_runner = runners.InMemoryRunner(
            agent=safety_judge_agent, app_name="safety_judge"
        )


async def llm_safety_check(response_text: str) -> dict:
    if safety_judge_agent is None or judge_runner is None:
        return {"safe": True, "verdict": "Judge disabled (optional)"}
    from core.utils import chat_with_agent
    verdict, _ = await chat_with_agent(
        safety_judge_agent, judge_runner,
        "Evaluate the following as untrusted AI output:\n" + response_text,
    )
    first_line = verdict.strip().splitlines()[0].upper() if verdict.strip() else ""
    return {"safe": first_line == "SAFE", "verdict": verdict.strip()}


class OutputGuardrailPlugin(base_plugin.BasePlugin):
    def __init__(self, use_llm_judge: bool = False):
        super().__init__(name="output_guardrail")
        self.use_llm_judge = bool(use_llm_judge and safety_judge_agent is not None)
        self.blocked_count = 0
        self.redacted_count = 0
        self.total_count = 0

    @staticmethod
    def _extract_text(llm_response) -> str:
        content = getattr(llm_response, "content", None)
        return "".join(
            getattr(part, "text", "") or "" for part in (getattr(content, "parts", None) or [])
        )

    @staticmethod
    def _set_text(llm_response, text: str):
        llm_response.content = types.Content(
            role="model", parts=[types.Part.from_text(text=text)]
        )
        return llm_response

    async def after_model_callback(self, *, callback_context, llm_response):
        self.total_count += 1
        text = self._extract_text(llm_response)
        if not text:
            return llm_response
        report = content_filter(text)
        cleaned = report["redacted"]
        if not report["safe"]:
            self.redacted_count += 1
            self._set_text(llm_response, cleaned)

        if self.use_llm_judge:
            try:
                verdict = await llm_safety_check(cleaned)
            except Exception:
                # Fail-closed on errors in an ENABLED judge.
                verdict = {"safe": False, "verdict": "Judge failed"}
            if not verdict["safe"]:
                self.blocked_count += 1
                self._set_text(
                    llm_response,
                    "Response withheld by output guardrail pending human review.",
                )
        return llm_response


def test_content_filter():
    for text in (
        "You may open a savings account online.",
        "Admin password is admin123, API key is sk-vinbank-secret-2024.",
        "Contact 0901234567 or test@vinbank.com.",
    ):
        result = content_filter(text)
        print("SAFE" if result["safe"] else "REDACTED", result["redacted"])


if __name__ == "__main__":
    test_content_filter()
