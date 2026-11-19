"""Checkpoint 3 — privacy-conscious, append-only-in-memory audit trail.

Lab audit logs must remain useful without copying banking PII/secrets verbatim.
"""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    return str(Path(__file__).resolve().parents[2] / "outputs" / "audit_log.json")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditLogPlugin:
    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, dict] = {}

    @staticmethod
    def _sanitize(text: str) -> str:
        from guardrails.output_guardrails import content_filter
        return content_filter(text or "")["redacted"][:1000]

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        rid = request_id or str(uuid.uuid4())
        if rid in self._open:
            raise ValueError(f"duplicate request_id: {rid}")
        self._open[rid] = {
            "request_id": rid,
            "user_id": str(user_id),
            "input": self._sanitize(text),
            "timestamp": utc_now_iso(),
            "started": time.perf_counter(),
        }
        return rid

    def record_output(
        self, *, user_id: str, text: str, blocked: bool = False,
        layer: str | None = None, request_id: str | None = None,
    ):
        rid = request_id or next(
            (k for k, v in reversed(list(self._open.items())) if v["user_id"] == str(user_id)),
            None,
        )
        data = self._open.pop(rid, None) if rid else None
        if data is None:
            # Out-of-band output remains auditable rather than raising.
            data = {
                "request_id": rid or str(uuid.uuid4()), "user_id": str(user_id),
                "input": "", "timestamp": utc_now_iso(), "started": time.perf_counter(),
            }
        elapsed_ms = max(0.0, (time.perf_counter() - data.pop("started")) * 1000)
        entry = {
            **data, "output": self._sanitize(text), "finished_at": utc_now_iso(),
            "blocked": bool(blocked), "layer": layer,
            "latency_ms": round(elapsed_ms, 3),
        }
        self.logs.append(entry)
        return entry

    def export_json(self, filepath: str | None = None):
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.logs, indent=2, ensure_ascii=False), encoding="utf-8")
        return path
