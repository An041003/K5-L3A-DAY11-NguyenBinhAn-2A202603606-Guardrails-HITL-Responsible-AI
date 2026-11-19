"""Verify model selection reaches the runtime without calling external APIs."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))


def test_blue_runner_uses_required_model_despite_stale_env(monkeypatch):
    from core.openai_runtime import create_blue_pair

    monkeypatch.setenv("OPENROUTER_MODEL", "google/gemini-3.5-flash")
    monkeypatch.setenv("OPENROUTER_API_KEY", "offline-test-key")
    _, runner = create_blue_pair(
        name="blue_test", instruction="Banking only", app_name="blue_test"
    )
    assert runner.provider == "openrouter"
    assert runner.model == "liquid/lfm-3-1.7b:free"
    assert runner.client_kwargs["base_url"] == "https://openrouter.ai/api/v1"


def test_blue_starter_fallback(monkeypatch):
    from core.config import get_blue_model

    monkeypatch.delenv("OPENROUTER_MODEL", raising=False)
    assert get_blue_model() == "liquid/lfm-3-1.7b:free"
    monkeypatch.setenv("OPENROUTER_MODEL", " ")
    assert get_blue_model() == "liquid/lfm-3-1.7b:free"


def test_red_gpt4o_mini_selection(monkeypatch):
    from core.config import get_red_model_default, get_red_model_advance

    monkeypatch.setenv("RED_TEAM_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-4o-mini")
    assert get_red_model_default() == "gpt-4o-mini"
    assert get_red_model_advance() == "gpt-4o-mini"
