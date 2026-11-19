"""Checkpoint 3 — rate-limit, rejection-rate, judge-failure monitoring."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


def default_metrics_path() -> str:
    return str(Path(__file__).resolve().parents[2] / "outputs" / "metrics.json")


@dataclass
class Alert:
    metric: str
    value: float
    threshold: float
    message: str


@dataclass
class MonitoringAlert:
    block_rate_threshold: float = 0.5
    rate_limit_hit_threshold: int = 5
    judge_fail_rate_threshold: float = 0.3
    alerts: list[Alert] = field(default_factory=list)
    total_requests: int = 0
    blocked_requests: int = 0
    rate_limit_hits: int = 0
    judge_checks: int = 0
    judge_fails: int = 0

    def check_metrics(self) -> list[Alert]:
        block_rate = (
            self.blocked_requests / self.total_requests if self.total_requests else 0.0
        )
        judge_fail_rate = (
            self.judge_fails / self.judge_checks if self.judge_checks else 0.0
        )
        # Recompute instead of appending duplicates on each request.
        alerts = []
        if self.total_requests and block_rate > self.block_rate_threshold:
            alerts.append(Alert(
                "block_rate", block_rate, self.block_rate_threshold,
                "High block rate: investigate abuse or false positives",
            ))
        if self.rate_limit_hits > self.rate_limit_hit_threshold:
            alerts.append(Alert(
                "rate_limit_hits", float(self.rate_limit_hits),
                float(self.rate_limit_hit_threshold), "Repeated flood/rate-limit events",
            ))
        if self.judge_checks and judge_fail_rate > self.judge_fail_rate_threshold:
            alerts.append(Alert(
                "judge_fail_rate", judge_fail_rate, self.judge_fail_rate_threshold,
                "High judge disagreement/failure rate",
            ))
        self.alerts = alerts
        return alerts

    def snapshot(self) -> dict:
        return {
            "total_requests": self.total_requests,
            "blocked_requests": self.blocked_requests,
            "block_rate": (
                self.blocked_requests / self.total_requests if self.total_requests else 0.0
            ),
            "rate_limit_hits": self.rate_limit_hits,
            "judge_checks": self.judge_checks,
            "judge_fails": self.judge_fails,
            "judge_fail_rate": (
                self.judge_fails / self.judge_checks if self.judge_checks else 0.0
            ),
            "alerts": [
                {"metric": a.metric, "value": a.value, "threshold": a.threshold, "message": a.message}
                for a in self.alerts
            ],
        }

    def export_json(self, filepath: str | None = None):
        self.check_metrics()
        path = Path(filepath or default_metrics_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.snapshot(), indent=2, ensure_ascii=False), encoding="utf-8")
        return path
