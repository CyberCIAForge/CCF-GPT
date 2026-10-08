"""The ReAct loop engine: Thought -> Tool Call -> Observation -> Next Thought.

``run_goal`` takes a natural-language objective, loops over litellm
tool-calling turns, executes Kali tools via tools.py (after guardrail
checks), feeds parser-summarized observations back, persists state to
memory, and returns the final assistant summary.
"""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console
from rich.markdown import Markdown
from rich.status import Status

from . import parser as smart_parser
from .config import load_config
from .guardrails import ScopeLock, classify_risk, confirm_execution
from .llm import SYSTEM_BASE, complete_with_tools, extract_tool_calls, message_text
from .memory import EngagementMemory
from .methodology import PHASE_IDS, get_phase, playbook_text
from .tools import EXECUTORS, SPECS, TOOL_SCHEMAS

console = Console()

SET_PHASE_SCHEMA: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "set_phase",
        "description": "Advance the pentest-methodology tracker to the next phase when exit criteria are met. Local-only, no scan.",
        "parameters": {
            "type": "object",
            "properties": {
                "phase": {"type": "string", "description": f"One of: {', '.join(PHASE_IDS)}"},
            },
            "required": ["phase"],
        },
    },
}

ALL_SCHEMAS = TOOL_SCHEMAS + [SET_PHASE_SCHEMA]

# Which argument of each tool carries the scope-checked target ("" = none).
TARGET_ARG = {name: spec.target_arg for name, spec in SPECS.items()}
TARGET_ARG.update({"record_finding": "target", "set_phase": ""})

# Values for these args are secrets — masked in previews and logs.
SENSITIVE_KEYS = {"password", "pass", "hashes", "secret", "passwd", "pwd"}

MAX_TOOL_CALLS_PER_TURN = 3


def _preview_command(tool: str, args: dict[str, Any]) -> str:
    order = ["target", "url", "domain", "query", "ports", "wordlist", "extensions",
             "threads", "status_codes", "level", "risk", "severity", "templates", "data",
             "service_detection", "extra_args", "batch", "phase", "kind", "title"]
    shown = []
    for k in order:
        if k in args:
            v = "***" if k in SENSITIVE_KEYS else args[k]
            shown.append(f"{k}={v}")
    for k in sorted(set(args) - set(order)):
        v = "***" if k in SENSITIVE_KEYS else args[k]
        shown.append(f"{k}={str(v)[:80]}")
    return " ".join([tool] + shown)


def _auto_memorize(tool: str, args: dict[str, Any], summary: str, mem: EngagementMemory) -> None:
    """Opportunistically persist high-signal facts from tool observations."""
    try:
        target = str(args.get(TARGET_ARG.get(tool, ""), "") or "")
        if tool == "run_nmap":
            d = smart_parser.parse_nmap(summary)
            if target:
                mem.add_target(target)
            for p in d.get("open_ports", [])[:40]:
                mem.add_asset(target, "open-port", f"{p['port']}/{p['proto']}",
                              f"{p['service']} {p['detail']}".strip())
            for cve in d.get("cves", [])[:10]:
                mem.add_vulnerability(target, f"Possible {cve} (nmap script/banner)", "info", summary[:500], cve)
        elif tool == "run_masscan":
            import re as _re
            if target:
                mem.add_target(target)
            for m in _re.finditer(r"open\s+(tcp|udp)\s+(\d+)\s+(\S+)", summary) or []:
                mem.add_asset(target, "open-port", f"{m.group(2)}/{m.group(1)}", m.group(3)[:120])
        elif tool in ("run_gobuster", "run_ffuf", "run_feroxbuster"):
            d = smart_parser.parse_gobuster_ffuf(summary)
            for h in d.get("hits", [])[:30]:
                mem.add_asset(target, "web-path", h["path"], f"status={h['status']} size={h['size']}")
        elif tool == "run_nuclei":
            d = smart_parser.parse_nuclei(summary)
            for f in d.get("findings", [])[:30]:
                cves = smart_parser.CVE_RE.findall(f["line"])
                mem.add_vulnerability(target, f["line"][:200], f["severity"], f["line"], cves[0].upper() if cves else "")
        elif tool == "run_sqlmap":
            d = smart_parser.parse_sqlmap(summary)
            if d.get("injectable"):
                mem.add_vulnerability(target, "SQL injection (sqlmap confirmed/appears injectable)",
                                      "critical", summary[:1000])
        elif tool in ("run_amass", "run_sublist3r", "run_theharvester"):
            import re as _re2
            if target:
                mem.add_target(target, target_type="domain")
            for sub in sorted(set(_re2.findall(r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}", summary)))[:40]:
                mem.add_asset(target, "subdomain", sub)
        elif tool == "run_whatweb":
            if target:
                mem.add_asset(target, "tech-stack", summary.splitlines()[0][:200] if summary else "")
        elif tool in ("run_hydra",):
            import re as _re3
            if _re3.search(r"login:\s*\S+.*password:\s*\S+", summary, _re3.I) or "1 of 1 target successfully" in summary:
                mem.add_credential(target, notes=f"possible valid credential (see {tool} output)")
        # generic: harvest any CVE mentions from tools without their own CVE handling
        if tool not in ("run_nmap", "run_nuclei"):
            for cve in sorted(set(smart_parser.CVE_RE.findall(summary)))[:10]:
                mem.add_vulnerability(target or "(unknown)", f"Mentioned {cve.upper()} ({tool})",
                                      "info", summary[:500], cve.upper())
    except Exception:
        pass  # memorization must never break the loop


def run_goal(
    goal: str,
    cfg: dict[str, Any] | None = None,
    mem: EngagementMemory | None = None,
    verbose: bool = True,
) -> str:
    """Execute one autonomous ReAct engagement for ``goal``. Returns final text."""
    cfg = cfg or load_config()
    mem = mem or EngagementMemory()
    max_iterations = int(cfg.get("max_iterations", 12))
    tool_timeout = int(cfg.get("tool_timeout", 300))
    max_out = int(cfg.get("max_output_chars", 12000))
    auto_low = bool(cfg.get("auto_confirm_low_risk", True))
    scope = ScopeLock(cfg.get("scope", []))
    phase = mem.get_phase()
    system = (
        SYSTEM_BASE
        + f"\n\nEngagement state (memory):\n{mem.context_summary()}\n\nScope policy: {scope.explain()}\n"
          "If the user's goal names a target outside scope, refuse the scan and explain how to extend scope.\n\n"
        + playbook_text(phase)
    )
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system},
        {"role": "user", "content": goal},
    ]

    final_text = ""
    with Status("ccf-gpt thinking…", spinner="dots") as status:
        for iteration in range(1, max_iterations + 1):
            status.update(f"ccf-gpt thinking… (step {iteration}/{max_iterations})")
            try:
                response = complete_with_tools(messages, ALL_SCHEMAS, cfg)
            except RuntimeError as e:
                console.print(f"[red]{e}[/red]")
                return f"LLM error: {e}"

            msg = response.choices[0].message
            text = message_text(msg)
            tool_calls = extract_tool_calls(msg)

            # Append assistant turn (with tool_calls in API shape) to history
            asst: dict[str, Any] = {"role": "assistant", "content": text or None}
            raw_tc = getattr(msg, "tool_calls", None)
            if raw_tc:
                asst["tool_calls"] = [
                    {"id": tc.id, "type": "function",
                     "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                    for tc in raw_tc
                ]
            messages.append(asst)

            if text and verbose:
                console.print(Markdown(f"**Thought [{iteration}]:** {text}"))

            if not tool_calls:
                final_text = text or "(no output)"
                break

            for tc in tool_calls[:MAX_TOOL_CALLS_PER_TURN]:
                tool, args = tc["name"], tc.get("args", {})
                if verbose:
                    console.print(f"[cyan]→ action:[/cyan] [bold]{tool}[/bold] [dim]{json.dumps(args)[:300]}[/dim]")
                observation = _execute_tool(tool, args, cfg, mem, scope,
                                            tool_timeout, max_out, auto_low, status)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc["id"],
                    "content": observation[:max_out * 2],
                })
                if verbose:
                    console.print(f"[green]← observation ({tool}):[/green]\n[dim]{observation[:1500]}[/dim]\n")
            else:
                continue
            # (for loop exhausted without break — continue outer iteration)
        else:
            # hit max_iterations: ask for a closing summary
            messages.append({"role": "user",
                             "content": "Max steps reached. Write the final summary now: assets, vulns, creds, next steps. No more tool calls."})
            try:
                response = complete_with_tools(messages, None, cfg)
                final_text = message_text(response.choices[0].message) or final_text
            except Exception as e:
                final_text = final_text or f"(summary unavailable: {e})"

    if final_text and verbose:
        console.print(Markdown(f"## Result\n{final_text}"))
    return final_text or "(empty result)"


def _execute_tool(
    tool: str, args: dict[str, Any], cfg: dict[str, Any],
    mem: EngagementMemory, scope: ScopeLock, tool_timeout: int,
    max_out: int, auto_low: bool, status: Status | None = None,
) -> str:
    # --- record_finding is local-only (no subprocess, no scope gate) --------
    if tool == "record_finding":
        try:
            target = str(args.get("target", ""))
            kind = str(args.get("kind", "asset"))
            title = str(args.get("title", ""))
            detail = str(args.get("detail", ""))
            severity = str(args.get("severity", "info"))
            cve = str(args.get("cve", ""))
            if kind == "target":
                mem.add_target(target, notes=title)
            elif kind == "credential":
                mem.add_credential(target, notes=f"{title} {detail}".strip())
            elif kind == "vulnerability":
                mem.add_vulnerability(target, title, severity, detail, cve)
            else:
                mem.add_asset(target, "note", title, detail)
            return f"recorded {kind} for {target}: {title}"
        except Exception as e:
            return f"record_finding failed: {e}"

    # --- set_phase is local-only (methodology tracker, no subprocess) --------
    if tool == "set_phase":
        try:
            phase = str(args.get("phase", "")).strip().lower()
            if phase not in PHASE_IDS:
                return f"Unknown phase '{phase}'. Valid: {', '.join(PHASE_IDS)}"
            mem.set_phase(phase)
            info = get_phase(phase)
            return (f"Methodology phase → {phase}: {info['name']}. Goal: {info['goal']} "
                    f"Preferred tools: {', '.join(info['tools'])}")
        except Exception as e:
            return f"set_phase failed: {e}"

    executor = EXECUTORS.get(tool)
    if executor is None:
        return f"Unknown tool '{tool}'. Available: {sorted(list(EXECUTORS) + ['record_finding', 'set_phase'])}"

    # --- scope gate ----------------------------------------------------------
    target_key = TARGET_ARG.get(tool, "")
    target_val = str(args.get(target_key, "") or "")
    if target_val and not scope.is_in_scope(target_val):
        mem.log_command(tool, _preview_command(tool, args), 1, "blocked: out of scope")
        return (
            f"REFUSED: target '{target_val}' is outside the authorized scope. {scope.explain()} "
            "Ask the operator to extend scope with `ccf-gpt config set-scope ...` before retrying."
        )

    # --- risk gate -----------------------------------------------------------
    preview = _preview_command(tool, args)
    risk = classify_risk(tool, preview)
    if status:
        status.stop()
    try:
        approved = confirm_execution(tool, preview, risk, auto_confirm_low)
    finally:
        if status:
            status.start()
    if not approved:
        mem.log_command(tool, preview, 1, f"denied by operator (risk={risk})")
        return f"Operator denied execution of {tool} (risk={risk}). Propose an alternative or ask for approval."

    # --- execute -------------------------------------------------------------
    if status:
        status.update(f"running {tool}… (timeout {tool_timeout}s)")
        status.stop()
    try:
        call_args = dict(args)
        # sqlmap/nuclei get longer default budgets; honour cfg timeout otherwise
        if tool in ("run_sqlmap", "run_nuclei") and "timeout" not in call_args:
            call_args["timeout"] = max(tool_timeout, 600)
        elif "timeout" not in call_args:
            call_args["timeout"] = tool_timeout
        # filter to executor-accepted kwargs (registry executors take **kwargs)
        import inspect

        sig = inspect.signature(executor)
        accepts_all = any(p.kind == inspect.Parameter.VAR_KEYWORD
                          for p in sig.parameters.values())
        if not accepts_all:
            call_args = {k: v for k, v in call_args.items() if k in sig.parameters}
        result = executor(**call_args)  # type: ignore[arg-type]
    except TypeError as e:
        return f"Invalid arguments for {tool}: {e}. Schema: {next((s for s in TOOL_SCHEMAS if s['function']['name']==tool), {})}"
    finally:
        if status:
            status.start()

    if result.error and result.returncode == 127:
        mem.log_command(tool, result.public_cmd, result.returncode, result.error)
        return f"Tool error: {result.error}"
    combined = result.combined() or result.error or "(no output)"
    summary = smart_parser.summarize(tool, combined, budget=max_out // 2 if max_out > 4000 else max_out)
    mem.log_command(tool, result.public_cmd, result.returncode, summary[:1500])
    _auto_memorize(tool, args, combined, mem)
    tail = f"\n[exit={result.returncode}]" + (f" [tool-error] {result.error}" if result.error else "")
    return summary + tail
