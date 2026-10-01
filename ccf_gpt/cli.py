"""Entrypoint & REPL: single-shot, chat mode, and config management."""

from __future__ import annotations

from typing import List, Optional

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table

from . import __version__
from .agent import run_goal
from .config import config_path, get_api_key, load_config, save_config
from .memory import EngagementMemory

console = Console()
app = typer.Typer(
    name="ccf-gpt",
    help="CyberCIA Forge GPT — autonomous Kali pentesting assistant (ReAct loop).",
    no_args_is_help=True,
)
config_app = typer.Typer(help="Manage model, API keys, scope, and runtime defaults.")
app.add_typer(config_app, name="config")


def _mask(v: str) -> str:
    if not v:
        return "(not set)"
    return (v[:4] + "…" + v[-3:]) if len(v) > 8 else "****"


# -- root callback (options only, NO positional args) ---------------------------
# NOTE: a root-level `prompt` argument was removed on purpose. Click parses
# group arguments before dispatching subcommands, so `ccf-gpt config ...`
# was misread as prompt="config" + unknown command. Single-shot runs go
# through `ccf-gpt run "<objective>"`.

@app.callback()
def main(
    version: bool = typer.Option(False, "--version", help="Show version and exit."),
) -> None:
    if version:
        console.print(f"ccf-gpt [bold]{__version__}[/bold]")
        raise typer.Exit()


@app.command()
def run(
    goal: str = typer.Argument(..., help="Objective to execute autonomously."),
    model: Optional[str] = typer.Option(None, "--model", "-m"),
    engagement: str = typer.Option("default", "--engagement", "-e"),
    max_iterations: Optional[int] = typer.Option(None, "--max-iterations"),
) -> None:
    """Single-shot autonomous run: ``ccf-gpt run \"enumerate …\"``."""
    cfg = load_config()
    if model:
        cfg["model"] = model
    if max_iterations:
        cfg["max_iterations"] = max_iterations
    mem = EngagementMemory(engagement=engagement)
    try:
        run_goal(goal, cfg=cfg, mem=mem)
    finally:
        mem.close()


# -- interactive REPL -------------------------------------------------------

@app.command()
def chat(
    engagement: str = typer.Option("default", "--engagement", "-e"),
    model: Optional[str] = typer.Option(None, "--model", "-m"),
) -> None:
    """Interactive REPL chat mode with persistent engagement memory."""
    cfg = load_config()
    if model:
        cfg["model"] = model
    mem = EngagementMemory(engagement=engagement)
    console.print(
        f"[bold green]ccf-gpt[/bold green] [dim]v{__version__} · model={cfg['model']} · engagement={engagement}[/dim]\n"
        "[dim]Type a pentest objective. Slash commands: /targets /vulns /assets /history /scope /model /engagement /help /exit[/dim]\n"
        f"[dim]Config: {config_path()}[/dim]"
    )
    try:
        while True:
            try:
                user = console.input("[bold cyan]ccf❯[/bold cyan] ").strip()
            except (EOFError, KeyboardInterrupt):
                console.print("\n[dim]Bye. Stay in scope.[/dim]")
                break
            if not user:
                continue
            if user.startswith("/"):
                if _handle_slash(user, mem, cfg):
                    break
                continue
            try:
                run_goal(user, cfg=cfg, mem=mem)
            except Exception as e:
                console.print(f"[red]Agent error: {e}[/red]")
    finally:
        mem.close()


def _handle_slash(user: str, mem: EngagementMemory, cfg: dict) -> bool:
    """Returns True if the REPL should exit."""
    parts = user.split()
    cmd, args = parts[0].lower(), parts[1:]
    if cmd in ("/exit", "/quit", "/q"):
        console.print("[dim]Bye. Stay in scope.[/dim]")
        return True
    if cmd == "/help":
        console.print(Markdown(
            "**/targets** — list targets · **/assets [t]** — discovered assets · "
            "**/vulns [t]** — vulnerabilities · **/history** — recent commands · "
            "**/scope** — show scope · **/model X** — switch model · "
            "**/engagement NAME** — switch engagement · **/exit** — quit"
        ))
    elif cmd == "/targets":
        rows = mem.get_targets()
        _print_rows("Targets", ["value", "target_type", "notes"], rows)
    elif cmd == "/assets":
        rows = mem.get_assets(args[0] if args else None)
        _print_rows("Assets", ["target", "kind", "value", "detail"], rows[-50:])
    elif cmd in ("/vulns", "/vuln"):
        rows = mem.get_vulnerabilities(args[0] if args else None)
        _print_rows("Vulnerabilities", ["target", "severity", "title", "cve"], rows[-50:])
    elif cmd == "/history":
        rows = mem.get_command_history(15)
        _print_rows("Command history", ["tool", "command", "exit_code"], rows)
    elif cmd == "/scope":
        console.print(f"Scope: [bold]{cfg.get('scope') or '(empty — scans blocked)'}[/bold]")
    elif cmd == "/model" and args:
        cfg["model"] = args[0]
        save_config(cfg)
        console.print(f"Model → [bold]{args[0]}[/bold] (saved)")
    elif cmd == "/engagement" and args:
        mem.use_engagement(args[0])
        console.print(f"Engagement → [bold]{args[0]}[/bold]")
    else:
        console.print(f"[yellow]Unknown command {cmd}. Try /help[/yellow]")
    return False


def _print_rows(title: str, cols: list[str], rows: list[dict]) -> None:
    if not rows:
        console.print(f"[dim]{title}: (none)[/dim]")
        return
    t = Table(title=title, show_lines=False)
    for c in cols:
        t.add_column(c, overflow="fold", max_width=60)
    for r in rows:
        t.add_row(*[str(r.get(c, ""))[:120] for c in cols])
    console.print(t)


# -- state inspection -------------------------------------------------------

@app.command()
def targets(engagement: str = typer.Option("default", "--engagement", "-e")) -> None:
    mem = EngagementMemory(engagement=engagement)
    try:
        _print_rows(f"Targets ({engagement})", ["value", "target_type", "notes"], mem.get_targets())
    finally:
        mem.close()


@app.command()
def findings(
    target: Optional[str] = typer.Option(None, "--target", "-t"),
    engagement: str = typer.Option("default", "--engagement", "-e"),
) -> None:
    mem = EngagementMemory(engagement=engagement)
    try:
        _print_rows(f"Vulnerabilities ({engagement})",
                    ["target", "severity", "title", "cve"], mem.get_vulnerabilities(target))
        _print_rows(f"Assets ({engagement})",
                    ["target", "kind", "value", "detail"], mem.get_assets(target)[-50:])
    finally:
        mem.close()


# -- config subcommands -----------------------------------------------------

@config_app.command("show")
def config_show() -> None:
    cfg = load_config()
    t = Table(title="ccf-gpt configuration", show_header=False)
    t.add_column("key", style="cyan")
    t.add_column("value", overflow="fold")
    t.add_row("file", str(config_path()))
    t.add_row("model", str(cfg.get("model")))
    t.add_row("temperature", str(cfg.get("temperature")))
    t.add_row("max_iterations", str(cfg.get("max_iterations")))
    t.add_row("tool_timeout", str(cfg.get("tool_timeout")))
    t.add_row("max_output_chars", str(cfg.get("max_output_chars")))
    t.add_row("auto_confirm_low_risk", str(cfg.get("auto_confirm_low_risk")))
    t.add_row("scope", ", ".join(cfg.get("scope", [])) or "(empty — scans blocked)")
    for p in ("anthropic", "openai", "gemini", "ollama"):
        stored = (cfg.get("api_keys") or {}).get(p, "")
        env_hit = bool(get_api_key(p, cfg)) and not stored
        t.add_row(f"key:{p}", _mask(stored) + (" (via env)" if env_hit and not stored else ""))
    console.print(t)


@config_app.command("set-model")
def config_set_model(model: str = typer.Argument(..., help="e.g. anthropic/claude-3-5-sonnet-20240620, openai/gpt-4o, gemini/gemini-1.5-pro, ollama/llama3")) -> None:
    cfg = load_config()
    cfg["model"] = model
    save_config(cfg)
    console.print(f"Model → [bold green]{model}[/bold green] [dim](saved to {config_path()})[/dim]")


@config_app.command("set-key")
def config_set_key(
    provider: str = typer.Argument(..., help="anthropic | openai | gemini"),
    key: Optional[str] = typer.Argument(None, help="API key (omit to be prompted securely)."),
) -> None:
    """Store a provider API key (file chmod 600). Ollama needs no key."""
    provider = provider.lower()
    if provider not in ("anthropic", "openai", "gemini"):
        console.print("[red]Provider must be one of: anthropic, openai, gemini (ollama needs no key).[/red]")
        raise typer.Exit(1)
    if not key:
        key = typer.prompt(f"Enter {provider} API key", hide_input=True)
    cfg = load_config()
    cfg.setdefault("api_keys", {})[provider] = key.strip()
    save_config(cfg)
    console.print(f"Saved [bold]{provider}[/bold] key [dim]({config_path()}, mode 600)[/dim]")


@config_app.command("set-scope")
def config_set_scope(scope: List[str] = typer.Argument(..., help="Allowed scope entries: CIDRs, IPs, domains. Replaces existing scope.")) -> None:
    cfg = load_config()
    cfg["scope"] = [s.strip() for s in scope if s.strip()]
    save_config(cfg)
    console.print(f"Scope → [bold green]{', '.join(cfg['scope'])}[/bold green]")


@config_app.command("add-scope")
def config_add_scope(scope: List[str] = typer.Argument(..., help="Scope entries to append.")) -> None:
    cfg = load_config()
    existing = list(cfg.get("scope", []))
    for s in scope:
        if s.strip() and s.strip() not in existing:
            existing.append(s.strip())
    cfg["scope"] = existing
    save_config(cfg)
    console.print(f"Scope → [bold green]{', '.join(existing) or '(empty)'}[/bold green]")


@config_app.command("clear-scope")
def config_clear_scope() -> None:
    cfg = load_config()
    cfg["scope"] = []
    save_config(cfg)
    console.print("[yellow]Scope cleared — network tool runs are now blocked until re-set.[/yellow]")


@config_app.command("set-timeout")
def config_set_timeout(seconds: int = typer.Argument(..., help="Per-tool timeout 30-3600.")) -> None:
    cfg = load_config()
    cfg["tool_timeout"] = max(30, min(int(seconds), 3600))
    save_config(cfg)
    console.print(f"tool_timeout → [bold]{cfg['tool_timeout']}s[/bold]")


@config_app.command("set-max-iterations")
def config_set_max_iterations(n: int = typer.Argument(..., help="ReAct step budget 1-50.")) -> None:
    cfg = load_config()
    cfg["max_iterations"] = max(1, min(int(n), 50))
    save_config(cfg)
    console.print(f"max_iterations → [bold]{cfg['max_iterations']}[/bold]")


if __name__ == "__main__":
    app()
