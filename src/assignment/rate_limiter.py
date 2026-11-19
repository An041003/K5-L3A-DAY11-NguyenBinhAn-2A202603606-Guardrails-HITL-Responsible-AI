"""Checkpoint 3 — per-user sliding-window rate limiter (monotonic time)."""
from __future__ import annotations

from collections import defaultdict, deque
import time
from google.adk.plugins import base_plugin
from google.genai import types


class RateLimitPlugin(base_plugin.BasePlugin):
    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        if max_requests < 1 or window_seconds < 1:
            raise ValueError("max_requests/window_seconds must be positive")
        super().__init__(name="rate_limiter")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.user_windows: dict[str, deque[float]] = defaultdict(deque)
        self.blocked_count = 0
        self.total_count = 0

    @staticmethod
    def _block_response(message: str) -> types.Content:
        return types.Content(role="model", parts=[types.Part.from_text(text=message)])

    async def on_user_message_callback(self, *, invocation_context, user_message):
        self.total_count += 1
        user_id = str(getattr(invocation_context, "user_id", None) or "anonymous")
        now = time.monotonic()  # resists wall-clock jumps
        window = self.user_windows[user_id]
        while window and now - window[0] >= self.window_seconds:
            window.popleft()
        if len(window) >= self.max_requests:
            self.blocked_count += 1
            remaining = max(0.0, self.window_seconds - (now - window[0]))
            return self._block_response(
                f"Rate limit exceeded. Try again in {remaining:.0f}s."
            )
        window.append(now)
        return None
