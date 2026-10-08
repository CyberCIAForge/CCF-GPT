"""Scope & safety guardrails: scope lock + human-in-the-loop confirmation.

Two layers:
1. ScopeLock — every tool target (IP / domain / URL) must fall inside the
   operator-defined scope (CIDRs, IPs, domains). Otherwise execution is refused.
2. Risk gate — LOW risk tools auto-run; MEDIUM/HIGH tools render the exact
   command in a rich Panel and require explicit ``[y/N]`` confirmation.
"""

from __future__ import annotations

import ipaddress
import re
import urllib.parse
from dataclasses import dataclass, field

from rich.console import Console
from rich.panel import Panel

console = Console()

# tool -> default risk tier (mirrors ToolSpec.risk in tools.py)
TOOL_RISK: dict[str, str] = {
    "run_nmap": "medium",
    "run_gobuster": "low",
    "run_ffuf": "low",
    "run_nuclei": "medium",
    "run_sqlmap": "high",
    "run_masscan": "medium",
    "run_nikto": "medium",
    "run_whatweb": "low",
    "run_wafw00f": "low",
    "run_dig": "low",
    "run_whois": "low",
    "run_theharvester": "low",
    "run_amass": "low",
    "run_sublist3r": "low",
    "run_enum4linux": "medium",
    "run_smbmap": "medium",
    "run_snmpwalk": "medium",
    "run_ldapsearch": "medium",
    "run_searchsploit": "low",
    "run_hydra": "high",       # brute-force: lockout risk
    "run_john": "low",         # offline cracking
    "run_feroxbuster": "low",
    "run_msfvenom": "high",    # payload generation
    "run_lynis": "low",
    "run_netexec": "medium",
    "run_tcpdump": "medium",
    "run_msfconsole": "high",  # scripted exploits/scanners
    "run_bettercap": "high",   # MITM / active network attacks
    "record_finding": "low",
    "set_phase": "low",
}

# Argument patterns that escalate a tool to HIGH risk regardless of default.
HIGH_RISK_ARG_PATTERNS = [
    r"--risk\s*[23]", r"--level\s*[4-5]", r"--os-shell", r"--os-pwn",
    r"--eval", r";", r"\|\|", r"\$\(", r"`", r"--script\s+\S*vuln",
    r"-A\b", r"--script\s", r"-O\b",
]

BLOCKED_PATTERNS = [
    r"\brm\s+-rf\s+/", r"\bmkfs\b", r"\bdd\s+if=", r":\(\)\s*\{",
    r"\bshutdown\b", r"\breboot\b", r"\bhalt\b",
]


@dataclass
class ScopeLock:
    """Validate targets against an allow-list scope."""

    scope: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.scope = [s.strip().lower() for s in (self.scope or []) if s.strip()]

    @property
    def locked(self) -> bool:
        return len(self.scope) > 0

    @staticmethod
    def _hostname_of(target: str) -> str:
        t = target.strip()
        if "://" not in t and not re.match(r"^[\w.%-]+@[\w.%-]+:", t):
            # bare host[:port][/path] — prepend // so urlparse finds hostname
            parsed = urllib.parse.urlparse(f"//{t}")
        else:
            parsed = urllib.parse.urlparse(t if "://" in t else f"http://{t}")
        return (parsed.hostname or t.split("/")[0].split(":")[0]).lower().strip(".")

    def is_in_scope(self, target: str) -> bool:
        """Empty scope => deny by default for network tools (fail-closed)."""
        if not target or not target.strip():
            return False
        if not self.locked:
            return False
        host = self._hostname_of(target)
        # Direct string match first (fast path)
        if host in self.scope:
            return True
        # Try IP / CIDR matching
        try:
            ip = ipaddress.ip_address(host)
            for entry in self.scope:
                try:
                    if "/" in entry:
                        if ip in ipaddress.ip_network(entry, strict=False):
                            return True
                    elif ip == ipaddress.ip_address(entry):
                        return True
                except ValueError:
                    continue
            return False
        except ValueError:
            pass  # not an IP — fall through to domain matching
        # Domain matching: exact or subdomain of a scope domain
        for entry in self.scope:
            e = entry.strip().lower()
            if "/" in e:
                continue
            if host == e or host.endswith("." + e):
                return True
        return False

    def explain(self) -> str:
        if not self.locked:
            return "No scope configured — all network tool runs are blocked. Use `ccf-gpt config set-scope <cidr|ip|domain> [...]`."
        return "Allowed scope: " + ", ".join(self.scope)


def classify_risk(tool: str, command_preview: str = "") -> str:
    """Return low|medium|high for a tool invocation."""
    base = TOOL_RISK.get(tool, "medium")
    cmd = command_preview or ""
    for pat in BLOCKED_PATTERNS:
        if re.search(pat, cmd):
            return "blocked"
    for pat in HIGH_RISK_ARG_PATTERNS:
        if re.search(pat, cmd):
            return "high"
    return base


def confirm_execution(tool: str, command: list[str] | str, risk: str, auto_confirm_low: bool = True) -> bool:
    """Render the exact command and ask for explicit confirmation.

    Returns True iff the operator approved. LOW risk auto-passes when
    ``auto_confirm_low`` is enabled; everything else requires typing y/yes.
    """
    cmd_str = " ".join(command) if isinstance(command, list) else command
    if risk == "blocked":
        console.print(
            Panel(
                f"[bold red]BLOCKED[/bold red] — command matches a destructive pattern and will not run.\n[dim]{cmd_str}[/dim]",
                title=f"[red]ccf-gpt guardrail · {tool}",
                border_style="red",
            )
        )
        return False
    if risk == "low" and auto_confirm_low:
        return True
    style = {"low": "green", "medium": "yellow", "high": "red"}.get(risk, "yellow")
    console.print(
        Panel(
            f"[bold]{cmd_str}[/bold]\n\nRisk tier: [bold {style}]{risk.upper()}[/bold {style}] · tool: [cyan]{tool}[/cyan]\n"
            "Review flags carefully. Only run against systems you are authorized to test.",
            title=f"[{style}]Confirm execution? [y/N]",
            border_style=style,
        )
    )
    try:
        answer = console.input("  Approve and run? [[bold green]y[/]/[red]N[/]]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        console.print("[dim]Denied (no confirmation).[/dim]")
        return False
    approved = answer in ("y", "yes")
    if not approved:
        console.print("[dim]Skipped by operator.[/dim]")
    return approved
