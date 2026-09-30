"""Kali tool registry — structured schemas + safe subprocess execution.

Each tool exposes:
  * an OpenAI-compatible function schema (TOOL_SCHEMAS) for litellm,
  * a python executor ``exec_<name>`` with timeouts, binary checks,
    scope validation and guardrail confirmation handled by the caller.

Never use shell=True. All commands are built as argv lists.
Missing binaries produce a clean, actionable error (apt install hint).
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Any

INSTALL_HINTS = {
    "nmap": "sudo apt install -y nmap",
    "gobuster": "sudo apt install -y gobuster",
    "ffuf": "sudo apt install -y ffuf",
    "sqlmap": "sudo apt install -y sqlmap",
    "nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest  # or: sudo apt install -y nuclei",
}

TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "run_nmap",
            "description": "Port scan + service/version detection with nmap. Use for host discovery and open-port enumeration. Target must be in scope.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "IP, CIDR, or hostname in scope (e.g. 192.168.1.50)"},
                    "ports": {"type": "string", "description": "Port spec, e.g. '80,443' or '1-1000' or 'top-1000'. Default top-1000 fast scan."},
                    "service_detection": {"type": "boolean", "description": "Add -sV for version detection. Default true."},
                    "extra_args": {"type": "string", "description": "Extra safe nmap flags, e.g. '-sC -Pn -T4'. Aggressive flags (-A, -O, --script) trigger HIGH-risk confirmation."},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_gobuster",
            "description": "Web directory/file fuzzing with gobuster dir mode. Use after finding open HTTP ports.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Base URL in scope, e.g. http://192.168.1.50/"},
                    "wordlist": {"type": "string", "description": "Wordlist path. Default /usr/share/wordlists/dirb/common.txt"},
                    "extensions": {"type": "string", "description": "Comma extensions, e.g. 'php,html,txt'"},
                    "threads": {"type": "integer", "description": "Threads 1-100. Default 30."},
                    "extra_args": {"type": "string", "description": "Extra gobuster flags (no shell metachars)."},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_ffuf",
            "description": "Fast web fuzzer (ffuf). Alternative to gobuster for directories, vhosts, and parameters.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "FUZZ URL, e.g. http://192.168.1.50/FUZZ"},
                    "wordlist": {"type": "string", "description": "Wordlist path."},
                    "status_codes": {"type": "string", "description": "Match codes, e.g. '200,301,302,403'. Default '200,204,301,302,307,401,403'"},
                    "threads": {"type": "integer", "description": "Threads. Default 40."},
                    "extra_args": {"type": "string", "description": "Extra ffuf flags."},
                },
                "required": ["url", "wordlist"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_sqlmap",
            "description": "Automated SQL injection testing with sqlmap. HIGH RISK — always requires confirmation and in-scope URL.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Target URL with parameters in scope, e.g. http://host/page?id=1"},
                    "data": {"type": "string", "description": "POST data string if needed."},
                    "level": {"type": "integer", "description": "1-5. Default 1. Higher = more intrusive."},
                    "risk": {"type": "integer", "description": "1-3. Default 1."},
                    "batch": {"type": "boolean", "description": "Non-interactive batch mode. Default true."},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_nuclei",
            "description": "Vulnerability template scanning with nuclei against an in-scope target/URL.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "URL, IP or hostname in scope."},
                    "severity": {"type": "string", "description": "Filter e.g. 'critical,high,medium'. Default all."},
                    "templates": {"type": "string", "description": "Template path or tag filter."},
                    "extra_args": {"type": "string", "description": "Extra nuclei flags."},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "record_finding",
            "description": "Record a finding directly to engagement memory without running a tool (ports, creds, vulns, assets). Use to persist anything the operator confirms or you infer from output.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Affected host/URL."},
                    "kind": {"type": "string", "description": "One of: asset, vulnerability, credential, target."},
                    "title": {"type": "string", "description": "Short title, e.g. 'Open port 80/http' or 'SQLi in id param'."},
                    "detail": {"type": "string", "description": "Longer detail/evidence."},
                    "severity": {"type": "string", "description": "info|low|medium|high|critical (for vulnerabilities)."},
                    "cve": {"type": "string", "description": "CVE id if known."},
                },
                "required": ["target", "kind", "title"],
            },
        },
    },
]


@dataclass
class ToolResult:
    tool: str
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    truncated: bool = False
    error: str = ""

    @property
    def cmd_str(self) -> str:
        return " ".join(self.command)

    def combined(self) -> str:
        parts = [self.stdout or ""]
        if self.stderr:
            parts.append(f"\n[stderr]\n{self.stderr}")
        return "\n".join(p for p in parts if p).strip()


def _require_binary(name: str) -> str | None:
    """Return error string if binary missing, else None."""
    if shutil.which(name) is None:
        hint = INSTALL_HINTS.get(name, f"sudo apt install -y {name}")
        return f"Binary '{name}' not found on PATH. Install it: {hint}"
    return None


def _run(argv: list[str], timeout: int) -> ToolResult:
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout,
        )
        return ToolResult(
            tool=argv[0], command=argv, returncode=proc.returncode,
            stdout=proc.stdout or "", stderr=proc.stderr or "",
        )
    except subprocess.TimeoutExpired as e:
        partial = ""
        if e.stdout:
            partial += e.stdout.decode() if isinstance(e.stdout, bytes) else str(e.stdout)
        if e.stderr:
            partial += "\n" + (e.stderr.decode() if isinstance(e.stderr, bytes) else str(e.stderr))
        return ToolResult(tool=argv[0], command=argv, returncode=124,
                          stdout=partial, stderr="",
                          error=f"Timed out after {timeout}s (partial output kept).")
    except FileNotFoundError:
        return ToolResult(tool=argv[0], command=argv, returncode=127,
                          stdout="", stderr="",
                          error=f"Binary '{argv[0]}' not found. {INSTALL_HINTS.get(argv[0], '')}")
    except Exception as e:  # network drops, perms, etc.
        return ToolResult(tool=argv[0], command=argv, returncode=1,
                          stdout="", stderr="", error=f"Execution failed: {e}")


def _safe_extra(extra: str) -> list[str]:
    """Split extra args on whitespace, rejecting shell metacharacters."""
    if not extra or not extra.strip():
        return []
    forbidden = [";", "&&", "||", "|", "`", "$(", ">", "<", "\n"]
    if any(f in extra for f in forbidden):
        raise ValueError(f"Rejected unsafe extra_args (shell metacharacters): {extra!r}")
    return extra.split()


# -- executors ----------------------------------------------------------

def exec_run_nmap(target: str, ports: str = "", service_detection: bool = True,
                  extra_args: str = "", timeout: int = 300) -> ToolResult:
    missing = _require_binary("nmap")
    if missing:
        return ToolResult("run_nmap", ["nmap", target], 127, "", "", error=missing)
    argv = ["nmap", "-T4", "--open"]
    if service_detection:
        argv.append("-sV")
    if ports:
        argv += ["-p", ports]
    else:
        argv += ["--top-ports", "1000"]
    try:
        argv += _safe_extra(extra_args)
    except ValueError as e:
        return ToolResult("run_nmap", argv, 2, "", "", error=str(e))
    argv.append(target)
    return _run(argv, timeout)


def exec_run_gobuster(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                      extensions: str = "", threads: int = 30,
                      extra_args: str = "", timeout: int = 300) -> ToolResult:
    missing = _require_binary("gobuster")
    if missing:
        return ToolResult("run_gobuster", ["gobuster", url], 127, "", "", error=missing)
    threads = max(1, min(int(threads or 30), 100))
    argv = ["gobuster", "dir", "-u", url, "-w", wordlist, "-t", str(threads),
            "--no-error", "-q"]
    if extensions:
        argv += ["-x", extensions]
    try:
        argv += _safe_extra(extra_args)
    except ValueError as e:
        return ToolResult("run_gobuster", argv, 2, "", "", error=str(e))
    return _run(argv, timeout)


def exec_run_ffuf(url: str, wordlist: str, status_codes: str = "200,204,301,302,307,401,403",
                  threads: int = 40, extra_args: str = "", timeout: int = 300) -> ToolResult:
    missing = _require_binary("ffuf")
    if missing:
        return ToolResult("run_ffuf", ["ffuf"], 127, "", "", error=missing)
    threads = max(1, min(int(threads or 40), 200))
    argv = ["ffuf", "-u", url, "-w", wordlist, "-t", str(threads),
            "-mc", status_codes, "-noninteractive"]
    try:
        argv += _safe_extra(extra_args)
    except ValueError as e:
        return ToolResult("run_ffuf", argv, 2, "", "", error=str(e))
    return _run(argv, timeout)


def exec_run_sqlmap(url: str, data: str = "", level: int = 1, risk: int = 1,
                    batch: bool = True, timeout: int = 600) -> ToolResult:
    missing = _require_binary("sqlmap")
    if missing:
        return ToolResult("run_sqlmap", ["sqlmap"], 127, "", "", error=missing)
    level = max(1, min(int(level or 1), 5))
    risk = max(1, min(int(risk or 1), 3))
    argv = ["sqlmap", "-u", url, f"--level={level}", f"--risk={risk}"]
    if batch:
        argv.append("--batch")
    if data:
        argv += ["--data", data]
    return _run(argv, timeout)


def exec_run_nuclei(target: str, severity: str = "", templates: str = "",
                    extra_args: str = "", timeout: int = 600) -> ToolResult:
    missing = _require_binary("nuclei")
    if missing:
        return ToolResult("run_nuclei", ["nuclei"], 127, "", "", error=missing)
    argv = ["nuclei", "-u", target, "-silent", "-nc"]
    if severity:
        argv += ["-severity", severity]
    if templates:
        argv += ["-t", templates]
    try:
        argv += _safe_extra(extra_args)
    except ValueError as e:
        return ToolResult("run_nuclei", argv, 2, "", "", error=str(e))
    return _run(argv, timeout)


EXECUTORS = {
    "run_nmap": exec_run_nmap,
    "run_gobuster": exec_run_gobuster,
    "run_ffuf": exec_run_ffuf,
    "run_sqlmap": exec_run_sqlmap,
    "run_nuclei": exec_run_nuclei,
}
