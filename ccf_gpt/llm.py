"""Multi-provider LLM client on top of litellm.

Supports anthropic/*, openai/*, gemini/* (google), ollama/* via one
unified ``complete_with_tools`` call. Handles:
  * API-key injection from config/env,
  * unified tool-calling schemas (OpenAI style),
  * graceful degradation on rate limits / network drops with retries.
"""

from __future__ import annotations

import time
from typing import Any

from rich.console import Console

console = Console()

SYSTEM_BASE = """You are CCF-GPT, an autonomous Kali Linux penetration-testing and DFIR assistant operating a ReAct loop (Thought -> Tool Call -> Observation).

Rules:
1. You may ONLY act through the provided tools (run_nmap, run_gobuster, run_ffuf, run_nuclei, run_sqlmap, record_finding). Never invent shell commands or output.
2. Chain steps logically: port scan -> on open 80/443/8080 run directory fuzzing -> on findings run nuclei -> on injectable params consider sqlmap.
3. Prefer low-risk enumeration before intrusive tests. Justify sqlmap/nuclei use.
4. Every target/URL you pass to a tool MUST already be inside the engagement scope given in context. If no scope is set, ask the operator to set it instead of scanning.
5. Keep reasoning concise. When enumeration is complete, summarize: open ports, services/versions, web paths, vulnerabilities/CVEs, credentials, and concrete next steps.
6. NEVER claim authorization you don't have. Remind the operator to stay in scope.
7. If a tool observation shows an error (missing binary, timeout), explain the fix briefly and propose an alternative.
8. Use record_finding to persist durable facts (open ports, vulns, creds) so memory survives across turns.
"""


def _ensure_key(model: str, cfg: dict[str, Any]) -> None:
    """Inject provider API key into the environment for litellm if available."""
    import os

    from .config import get_api_key, provider_for_model

    provider = provider_for_model(model)
    key = get_api_key(provider, cfg)
    if not key:
        return
    mapping = {
        "anthropic": "ANTHROPIC_API_KEY",
        "openai": "OPENAI_API_KEY",
        "gemini": "GEMINI_API_KEY",
    }
    env_var = mapping.get(provider)
    if env_var and not os.getenv(env_var):
        os.environ[env_var] = key
        if provider == "gemini" and not os.getenv("GOOGLE_API_KEY"):
            os.environ["GOOGLE_API_KEY"] = key


def complete_with_tools(
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None,
    cfg: dict[str, Any],
    max_retries: int = 3,
) -> Any:
    """Call litellm.completion with retries on rate-limit / network errors.

    Returns the litellm response object (response.choices[0].message).
    Raises RuntimeError after exhausting retries.
    """
    import litellm

    model = cfg.get("model", "anthropic/claude-3-5-sonnet-20240620")
    _ensure_key(model, cfg)
    temperature = float(cfg.get("temperature", 0.2))

    # Gemini 3+ deprecates top-level sampling params (warns on every call);
    # move guidance into the system prompt instead by simply omitting it.
    omit_temperature = model.lower().startswith("gemini/gemini-3")

    last_err: Exception | None = None
    for attempt in range(1, max_retries + 1):
        try:
            kwargs: dict[str, Any] = {
                "model": model,
                "messages": messages,
            }
            if not omit_temperature:
                kwargs["temperature"] = temperature
            if tools:
                kwargs["tools"] = tools
                kwargs["tool_choice"] = "auto"
            return litellm.completion(**kwargs)
        except Exception as e:  # litellm exposes RateLimitError etc.; catch broadly + backoff
            last_err = e
            msg = str(e).lower()
            retryable = any(k in msg for k in (
                "rate limit", "429", "overloaded", "503", "timeout",
                "connection", "temporarily", "retry", "500", "502", "529",
            ))
            if attempt < max_retries and retryable:
                wait = 2 ** attempt
                console.print(f"[yellow]LLM transient error (attempt {attempt}/{max_retries}): {e}. Retrying in {wait}s…[/yellow]")
                time.sleep(wait)
                continue
            break
    raise RuntimeError(
        f"LLM call failed after {max_retries} attempt(s) with model '{model}': {last_err}\n"
        "Hints: check `ccf-gpt config show`, set a key via `ccf-gpt config set-key <provider>`, "
        "or switch model via `ccf-gpt config set-model ollama/llama3` for local inference."
    ) from last_err


def extract_tool_calls(message: Any) -> list[dict[str, Any]]:
    """Normalize litellm / OpenAI message tool calls to [{id, name, args}]."""
    calls: list[dict[str, Any]] = []
    raw_calls = getattr(message, "tool_calls", None) or []
    import json

    for tc in raw_calls:
        try:
            fn = tc.function
            name = fn.name
            args_raw = fn.arguments or "{}"
            args = json.loads(args_raw) if isinstance(args_raw, str) else dict(args_raw)
        except Exception:
            continue
        calls.append({"id": getattr(tc, "id", name), "name": name, "args": args})
    return calls


def message_text(message: Any) -> str:
    return (getattr(message, "content", None) or "").strip()
