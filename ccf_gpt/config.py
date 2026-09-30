"""Central configuration store for ccf-gpt.

Config lives at ``~/.config/ccf-gpt/config.json`` (XDG-aware via platformdirs).
API keys can also come from environment variables so Kali users can
``export ANTHROPIC_API_KEY=...`` without persisting secrets to disk.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import platformdirs

APP_NAME = "ccf-gpt"
APP_AUTHOR = "cybercia"

DEFAULT_CONFIG: dict[str, Any] = {
    "model": "anthropic/claude-3-5-sonnet-20240620",
    "temperature": 0.2,
    "max_iterations": 12,
    "tool_timeout": 300,
    "max_output_chars": 12000,
    "auto_confirm_low_risk": True,
    "scope": [],  # e.g. ["192.168.1.0/24", "example.com", "10.10.10.50"]
    "api_keys": {},  # {"anthropic": "sk-ant-...", "openai": "...", "gemini": ...}
}


def config_dir() -> Path:
    d = Path(platformdirs.user_config_dir(APP_NAME, APP_AUTHOR))
    d.mkdir(parents=True, exist_ok=True)
    return d


def config_path() -> Path:
    return config_dir() / "config.json"


def db_path() -> Path:
    return config_dir() / "engagements.db"


def load_config() -> dict[str, Any]:
    """Load merged config (defaults <- file <- env overrides for model)."""
    cfg: dict[str, Any] = dict(DEFAULT_CONFIG)
    p = config_path()
    if p.exists():
        try:
            file_cfg = json.loads(p.read_text())
            if isinstance(file_cfg, dict):
                cfg.update(file_cfg)
        except (json.JSONDecodeError, OSError):
            pass
    # Env override for convenience
    env_model = os.getenv("CCF_GPT_MODEL")
    if env_model:
        cfg["model"] = env_model
    return cfg


def save_config(cfg: dict[str, Any]) -> Path:
    p = config_path()
    p.write_text(json.dumps(cfg, indent=2))
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    return p


def get_api_key(provider: str, cfg: dict[str, Any] | None = None) -> str | None:
    """Resolve API key: explicit config -> standard env vars."""
    cfg = cfg or load_config()
    stored = (cfg.get("api_keys") or {}).get(provider)
    if stored:
        return stored
    env_map = {
        "anthropic": ["ANTHROPIC_API_KEY"],
        "openai": ["OPENAI_API_KEY"],
        "gemini": ["GEMINI_API_KEY", "GOOGLE_API_KEY"],
        "ollama": [],  # local, no key needed
    }
    for var in env_map.get(provider, []):
        val = os.getenv(var)
        if val:
            return val
    return None


def provider_for_model(model: str) -> str:
    low = model.lower()
    if low.startswith("anthropic/"):
        return "anthropic"
    if low.startswith("openai/") or low.startswith("gpt-"):
        return "openai"
    if low.startswith("gemini/") or low.startswith("google/"):
        return "gemini"
    if low.startswith("ollama/"):
        return "ollama"
    return "unknown"
