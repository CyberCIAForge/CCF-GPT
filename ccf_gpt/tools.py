"""Kali tool registry — structured schemas + safe subprocess execution.

Data-driven: every tool is a ToolSpec (schema + risk + argv builder).
The agent gets OpenAI-compatible function schemas; execution is always
argv lists (never shell=True) with timeouts, binary checks and redaction
of secrets (passwords/hashes never hit logs or console).

Add a tool = append one ToolSpec. No other code changes needed.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Callable

INSTALL_HINTS = {
    "nmap": "sudo apt install -y nmap",
    "gobuster": "sudo apt install -y gobuster",
    "ffuf": "sudo apt install -y ffuf",
    "sqlmap": "sudo apt install -y sqlmap",
    "nuclei": "sudo apt install -y nuclei",
    "masscan": "sudo apt install -y masscan",
    "nikto": "sudo apt install -y nikto",
    "whatweb": "sudo apt install -y whatweb",
    "wafw00f": "sudo apt install -y wafw00f",
    "dig": "sudo apt install -y dnsutils",
    "whois": "sudo apt install -y whois",
    "theHarvester": "sudo apt install -y theharvester",
    "amass": "sudo apt install -y amass",
    "sublist3r": "sudo apt install -y sublist3r",
    "enum4linux": "sudo apt install -y enum4linux",
    "smbmap": "sudo apt install -y smbmap",
    "snmpwalk": "sudo apt install -y snmp",
    "ldapsearch": "sudo apt install -y ldap-utils",
    "searchsploit": "sudo apt install -y exploitdb",
    "hydra": "sudo apt install -y hydra",
    "john": "sudo apt install -y john",
    "feroxbuster": "sudo apt install -y feroxbuster",
    "msfvenom": "sudo apt install -y metasploit-framework",
    "lynis": "sudo apt install -y lynis",
    "netexec": "sudo apt install -y netexec",
    "crackmapexec": "sudo apt install -y crackmapexec",
    "tcpdump": "sudo apt install -y tcpdump",
    "msfconsole": "sudo apt install -y metasploit-framework",
    "bettercap": "sudo apt install -y bettercap",
}


@dataclass
class ToolResult:
    tool: str
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    truncated: bool = False
    error: str = ""
    redacted: str = ""  # safe-for-log display; falls back to cmd_str

    @property
    def cmd_str(self) -> str:
        return " ".join(self.command)

    @property
    def public_cmd(self) -> str:
        return self.redacted or self.cmd_str

    def combined(self) -> str:
        parts = [self.stdout or ""]
        if self.stderr:
            parts.append(f"\n[stderr]\n{self.stderr}")
        return "\n".join(p for p in parts if p).strip()


@dataclass
class ToolSpec:
    """One Kali tool: schema for the LLM + safe argv builder."""

    name: str                      # run_nmap — also the function name
    binary: str                    # primary binary (may be overridden per-spec)
    binaries: tuple = ()           # alternatives tried in order (e.g. netexec/crackmapexec)
    description: str = ""
    risk: str = "medium"           # low|medium|high
    target_arg: str = ""           # param holding the scope-checked target ("": none)
    timeout: int = 300
    properties: dict = field(default_factory=dict)
    required: list = field(default_factory=list)
    build: Callable[[dict], list[str]] = lambda a: []  # validated argv
    redact: tuple = ()             # flags whose NEXT argv value is secret


# -- shared validation helpers --------------------------------------------

def _bounded_int(v: Any, default: int, lo: int, hi: int) -> int:
    try:
        v = int(v)
    except (TypeError, ValueError):
        return default
    return max(lo, min(v, hi))


def _safe_extra(extra: str) -> list[str]:
    if not extra or not str(extra).strip():
        return []
    forbidden = [";", "&&", "||", "|", "`", "$(", ">", "<", "\n"]
    if any(f in str(extra) for f in forbidden):
        raise ValueError(f"Rejected unsafe extra_args (shell metacharacters): {extra!r}")
    return str(extra).split()


def _host(v: Any, what: str = "host") -> str:
    v = str(v or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,253}", v):
        raise ValueError(f"Invalid {what}: {v!r}")
    return v


def _wordlist(v: Any, default: str = "/usr/share/wordlists/dirb/common.txt") -> str:
    v = str(v or default).strip()
    if not re.fullmatch(r"[/\w.\-]{1,300}", v) or ".." in v:
        raise ValueError(f"Rejected wordlist path: {v!r}")
    return v


def _require_root(tool: str) -> None:
    if os.geteuid() != 0:
        raise PermissionError(f"{tool} needs root — re-run ccf-gpt with sudo for this tool.")


def _resolve_binary(spec: ToolSpec) -> str:
    for b in (spec.binary, *spec.binaries):
        if shutil.which(b):
            return b
    hint = INSTALL_HINTS.get(spec.binary, f"sudo apt install -y {spec.binary}")
    raise FileNotFoundError(f"Binary '{spec.binary}' not found on PATH. Install it: {hint}")


def _run(spec: ToolSpec, argv: list[str], timeout: int) -> ToolResult:
    # compute redacted display for secrets (-p password etc.)
    pub = list(argv)
    for i, tok in enumerate(pub[:-1]):
        if tok in spec.redact and i + 1 < len(pub):
            pub[i + 1] = "***"
    redacted = " ".join(pub) if pub != argv else ""
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return ToolResult(spec.name, argv, proc.returncode,
                          proc.stdout or "", proc.stderr or "", redacted=redacted)
    except subprocess.TimeoutExpired as e:
        partial = ""
        if e.stdout:
            partial += e.stdout.decode() if isinstance(e.stdout, bytes) else str(e.stdout)
        if e.stderr:
            partial += "\n" + (e.stderr.decode() if isinstance(e.stderr, bytes) else str(e.stderr))
        return ToolResult(spec.name, argv, 124, partial, "",
                          error=f"Timed out after {timeout}s (partial output kept).",
                          redacted=redacted)
    except Exception as e:
        return ToolResult(spec.name, argv, 1, "", "",
                          error=f"Execution failed: {e}", redacted=redacted)


def _executor(spec: ToolSpec) -> Callable[..., ToolResult]:
    def run(**kwargs: Any) -> ToolResult:
        missing = [k for k in spec.required if not str(kwargs.get(k) or "").strip()]
        if missing:
            return ToolResult(spec.name, [spec.binary], 2, "", "",
                              error=f"Missing required arguments: {', '.join(missing)}")
        timeout = _bounded_int(kwargs.get("timeout"), spec.timeout, 10, 3600)
        try:
            argv = spec.build(dict(kwargs))
        except PermissionError as e:
            return ToolResult(spec.name, [spec.binary], 1, "", "", error=str(e))
        except FileNotFoundError as e:
            return ToolResult(spec.name, [spec.binary], 127, "", "", error=str(e))
        except ValueError as e:
            return ToolResult(spec.name, [spec.binary], 2, "", "", error=str(e))
        return _run(spec, argv, timeout)
    run.__name__ = spec.name
    return run


# -- argv builders (one per tool; all inputs validated) ---------------------

def _b_nmap(a: dict) -> list[str]:
    argv = [_resolve_binary(SPECS["run_nmap"]), "-T4", "--open"]
    if a.get("service_detection", True):
        argv.append("-sV")
    ports = str(a.get("ports") or "").strip()
    if ports:
        if not re.fullmatch(r"[\d,\- ]{1,100}", ports):
            raise ValueError(f"Bad ports spec: {ports!r}")
        argv += ["-p", ports]
    else:
        argv += ["--top-ports", "1000"]
    argv += _safe_extra(a.get("extra_args", ""))
    argv.append(_host(a.get("target"), "target"))
    return argv


def _b_gobuster(a: dict) -> list[str]:
    th = _bounded_int(a.get("threads", 30), 30, 1, 100)
    argv = [_resolve_binary(SPECS["run_gobuster"]), "dir", "-u", str(a.get("url")).strip(),
            "-w", _wordlist(a.get("wordlist")), "-t", str(th), "--no-error", "-q"]
    if a.get("extensions"):
        ext = str(a["extensions"]).strip()
        if not re.fullmatch(r"[A-Za-z0-9,]{1,60}", ext):
            raise ValueError(f"Bad extensions: {ext!r}")
        argv += ["-x", ext]
    argv += _safe_extra(a.get("extra_args", ""))
    return argv


def _b_ffuf(a: dict) -> list[str]:
    th = _bounded_int(a.get("threads", 40), 40, 1, 200)
    codes = str(a.get("status_codes") or "200,204,301,302,307,401,403")
    if not re.fullmatch(r"[\d, ]{1,60}", codes):
        raise ValueError(f"Bad status codes: {codes!r}")
    argv = [_resolve_binary(SPECS["run_ffuf"]), "-u", str(a.get("url")).strip(),
            "-w", _wordlist(a.get("wordlist", "")), "-t", str(th),
            "-mc", codes, "-noninteractive"]
    argv += _safe_extra(a.get("extra_args", ""))
    return argv


def _b_sqlmap(a: dict) -> list[str]:
    lv = _bounded_int(a.get("level", 1), 1, 1, 5)
    rk = _bounded_int(a.get("risk", 1), 1, 1, 3)
    argv = [_resolve_binary(SPECS["run_sqlmap"]), "-u", str(a.get("url")).strip(),
            f"--level={lv}", f"--risk={rk}"]
    if a.get("batch", True):
        argv.append("--batch")
    if a.get("data"):
        argv += ["--data", str(a["data"])[:2000]]
    return argv


def _b_nuclei(a: dict) -> list[str]:
    argv = [_resolve_binary(SPECS["run_nuclei"]), "-u", str(a.get("target") or a.get("url")).strip(),
            "-silent", "-nc"]
    if a.get("severity"):
        sev = str(a["severity"]).strip()
        if not re.fullmatch(r"[a-z, ]{1,40}", sev):
            raise ValueError(f"Bad severity: {sev!r}")
        argv += ["-severity", sev]
    if a.get("templates"):
        argv += ["-t", str(a["templates"]).strip()[:200]]
    argv += _safe_extra(a.get("extra_args", ""))
    return argv


def _b_masscan(a: dict) -> list[str]:
    _require_root("masscan")
    ports = str(a.get("ports") or "80,443,8080")
    if not re.fullmatch(r"[\d,\-UT: ]{1,100}", ports):
        raise ValueError(f"Bad ports: {ports!r}")
    rate = _bounded_int(a.get("rate", 1000), 1000, 100, 100000)
    argv = [_resolve_binary(SPECS["run_masscan"]), str(a.get("target")).strip(),
            "-p", ports, "--rate", str(rate), "--open", "--wait", "2"]
    argv += _safe_extra(a.get("extra_args", ""))
    return argv


def _b_nikto(a: dict) -> list[str]:
    argv = [_resolve_binary(SPECS["run_nikto"]), "-h", str(a.get("url")).strip(), "-ask", "no"]
    if a.get("tuning"):
        t = str(a["tuning"]).strip()
        if not re.fullmatch(r"[0-9a-zA-Zx ]{1,20}", t):
            raise ValueError(f"Bad tuning: {t!r}")
        argv += ["-Tuning", t]
    argv += _safe_extra(a.get("extra_args", ""))
    return argv


def _b_whatweb(a: dict) -> list[str]:
    aggr = _bounded_int(a.get("aggression", 1), 1, 1, 4)
    argv = [_resolve_binary(SPECS["run_whatweb"]), "-a", str(aggr), str(a.get("target")).strip()]
    argv += _safe_extra(a.get("extra_args", ""))
    return argv


def _b_wafw00f(a: dict) -> list[str]:
    return [_resolve_binary(SPECS["run_wafw00f"]), str(a.get("target")).strip()]


def _b_dig(a: dict) -> list[str]:
    qtype = str(a.get("query_type") or "A").upper()
    if qtype not in {"A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT", "AXFR", "ANY"}:
        raise ValueError(f"Bad query type: {qtype!r}")
    argv = [_resolve_binary(SPECS["run_dig"]), str(a.get("target")).strip(), qtype]
    if a.get("dns_server"):
        argv.append("@" + _host(a["dns_server"], "dns server"))
    return argv


def _b_whois(a: dict) -> list[str]:
    return [_resolve_binary(SPECS["run_whois"]), str(a.get("target")).strip()]


def _b_theharvester(a: dict) -> list[str]:
    src = str(a.get("sources") or "crtsh")
    if not re.fullmatch(r"[a-zA-Z0-9_,\-]{1,80}", src):
        raise ValueError(f"Bad sources: {src!r}")
    lim = _bounded_int(a.get("limit", 100), 100, 10, 1000)
    return [_resolve_binary(SPECS["run_theharvester"]), "-d", str(a.get("domain")).strip(),
            "-b", src, "-l", str(lim)]


def _b_amass(a: dict) -> list[str]:
    argv = [_resolve_binary(SPECS["run_amass"]), "enum"]
    argv.append("-passive" if a.get("passive", True) else "-active")
    mins = _bounded_int(a.get("timeout_mins", 30), 30, 5, 120)
    argv += ["-timeout", str(mins), "-d", str(a.get("domain")).strip()]
    return argv


def _b_sublist3r(a: dict) -> list[str]:
    return [_resolve_binary(SPECS["run_sublist3r"]), "-d", str(a.get("domain")).strip(), "-t", "10"]


def _b_enum4linux(a: dict) -> list[str]:
    return [_resolve_binary(SPECS["run_enum4linux"]), "-a", str(a.get("target")).strip()]


def _b_smbmap(a: dict) -> list[str]:
    argv = [_resolve_binary(SPECS["run_smbmap"]), "-H", str(a.get("target")).strip()]
    if a.get("username"):
        argv += ["-u", str(a["username"])[:64]]
    if a.get("password"):
        argv += ["-p", str(a["password"])[:256]]
    return argv


def _b_snmpwalk(a: dict) -> list[str]:
    ver = str(a.get("version") or "2c")
    if ver not in {"1", "2c"}:
        raise ValueError("SNMP version must be 1 or 2c")
    comm = str(a.get("community") or "public")
    if not re.fullmatch(r"[\w\-]{1,64}", comm):
        raise ValueError("Bad community string")
    argv = [_resolve_binary(SPECS["run_snmpwalk"]), f"-v{ver}", "-c", comm,
            str(a.get("target")).strip()]
    if a.get("oid"):
        oid = str(a["oid"]).strip()
        if not re.fullmatch(r"[.\w]{1,64}", oid):
            raise ValueError(f"Bad OID: {oid!r}")
        argv.append(oid)
    return argv


def _b_ldapsearch(a: dict) -> list[str]:
    base = str(a.get("base_dn") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9=,._@\s\-]{1,200}", base):
        raise ValueError("Bad base DN")
    argv = [_resolve_binary(SPECS["run_ldapsearch"]), "-x", "-LLL",
            "-h", str(a.get("target")).strip(), "-b", base]
    if a.get("bind_dn"):
        argv += ["-D", str(a["bind_dn"])[:200]]
    if a.get("password"):
        argv += ["-w", str(a["password"])[:256]]
    return argv


def _b_searchsploit(a: dict) -> list[str]:
    q = str(a.get("query") or "").strip()
    if not re.fullmatch(r"[\w\s.\-+]{1,120}", q):
        raise ValueError(f"Bad query: {q!r}")
    argv = [_resolve_binary(SPECS["run_searchsploit"])]
    if a.get("title_only"):
        argv.append("-t")
    argv.append(q)
    return argv


_HYDRA_SVCS = {"ssh", "ftp", "smb", "rdp", "telnet", "mysql", "postgres"}


def _b_hydra(a: dict) -> list[str]:
    svc = str(a.get("service") or "").lower()
    if svc not in _HYDRA_SVCS:
        raise ValueError(f"Service must be one of {sorted(_HYDRA_SVCS)}")
    th = _bounded_int(a.get("threads", 4), 4, 1, 16)
    argv = [_resolve_binary(SPECS["run_hydra"]), "-l", str(a.get("login"))[:64],
            "-P", _wordlist(a.get("wordlist", "/usr/share/wordlists/rockyou.txt")),
            "-t", str(th), "-f"]
    if a.get("port"):
        argv += ["-s", str(_bounded_int(a["port"], 0, 1, 65535))]
    argv += [str(a.get("target")).strip(), svc]
    return argv


def _b_john(a: dict) -> list[str]:
    hf = str(a.get("hashfile") or "").strip()
    if not re.fullmatch(r"[/\w.\-]{1,300}", hf) or ".." in hf:
        raise ValueError(f"Bad hashfile path: {hf!r}")
    if not os.path.exists(hf):
        raise ValueError(f"Hashfile not found: {hf}")
    argv = [_resolve_binary(SPECS["run_john"])]
    if a.get("format"):
        fmt = str(a["format"]).strip()
        if not re.fullmatch(r"[A-Za-z0-9_\-]{1,40}", fmt):
            raise ValueError(f"Bad format: {fmt!r}")
        argv.append(f"--format={fmt}")
    if a.get("wordlist"):
        argv.append(f"--wordlist={_wordlist(a['wordlist'])}")
    argv.append(hf)
    return argv


def _b_feroxbuster(a: dict) -> list[str]:
    th = _bounded_int(a.get("threads", 30), 30, 1, 100)
    depth = _bounded_int(a.get("depth", 2), 2, 0, 4)
    argv = [_resolve_binary(SPECS["run_feroxbuster"]), "-u", str(a.get("url")).strip(),
            "-w", _wordlist(a.get("wordlist")), "-t", str(th), "-d", str(depth), "--silent"]
    argv += _safe_extra(a.get("extra_args", ""))
    return argv


_MSFVENOM_PAYLOADS = {
    "windows/meterpreter/reverse_tcp", "windows/x64/meterpreter/reverse_tcp",
    "windows/shell_reverse_tcp", "linux/x86/meterpreter/reverse_tcp",
    "linux/x64/meterpreter/reverse_tcp", "php/meterpreter/reverse_tcp",
    "python/meterpreter/reverse_tcp", "java/jsp_shell_reverse_tcp",
    "cmd/unix/reverse_netcat", "generic/shell_reverse_tcp",
}
_MSFVENOM_FMT = {"exe", "dll", "elf", "ps1", "py", "php", "asp", "aspx", "jsp", "war", "raw"}


def _b_msfvenom(a: dict) -> list[str]:
    pay = str(a.get("payload") or "")
    if pay not in _MSFVENOM_PAYLOADS:
        raise ValueError(f"Payload must be one of {sorted(_MSFVENOM_PAYLOADS)}")
    fmt = str(a.get("format") or "exe")
    if fmt not in _MSFVENOM_FMT:
        raise ValueError(f"Format must be one of {sorted(_MSFVENOM_FMT)}")
    lport = _bounded_int(a.get("lport", 4444), 4444, 1, 65535)
    out = str(a.get("outfile") or f"/tmp/ccf_msfvenom_{int(time.time())}.{fmt}")
    if not re.fullmatch(r"[/\w.\-]{1,200}", out) or ".." in out:
        raise ValueError(f"Bad outfile: {out!r}")
    return [_resolve_binary(SPECS["run_msfvenom"]), "-p", pay,
            f"LHOST={_host(a.get('lhost'), 'lhost')}", f"LPORT={lport}",
            "-f", fmt, "-o", out]


def _b_lynis(a: dict) -> list[str]:
    argv = [_resolve_binary(SPECS["run_lynis"]), "audit", "system"]
    argv += _safe_extra(a.get("extra_args", ""))
    return argv


_NETEXEC_PROTO = {"smb", "ssh", "winrm", "ldap", "mssql", "ftp"}


def _b_netexec(a: dict) -> list[str]:
    proto = str(a.get("protocol") or "smb").lower()
    if proto not in _NETEXEC_PROTO:
        raise ValueError(f"Protocol must be one of {sorted(_NETEXEC_PROTO)}")
    spec = SPECS["run_netexec"]
    binary = next((b for b in (spec.binary, *spec.binaries) if shutil.which(b)), None)
    if not binary:
        raise FileNotFoundError("Neither 'netexec' nor 'crackmapexec' found. sudo apt install -y netexec")
    argv = [binary, proto, str(a.get("target")).strip()]
    if a.get("username"):
        argv += ["-u", str(a["username"])[:64]]
    if a.get("hashes"):
        h = str(a["hashes"]).strip()
        if not re.fullmatch(r"[0-9a-fA-F:]{32,65}", h):
            raise ValueError("Bad NTLM hash format")
        argv += ["-H", h]
    elif a.get("password"):
        argv += ["-p", str(a["password"])[:256]]
    return argv


def _b_tcpdump(a: dict) -> list[str]:
    _require_root("tcpdump")
    iface = str(a.get("interface") or "any")
    if not re.fullmatch(r"[a-zA-Z0-9._\-]{1,16}", iface):
        raise ValueError(f"Bad interface: {iface!r}")
    count = _bounded_int(a.get("count", 20), 20, 1, 1000)
    argv = [_resolve_binary(SPECS["run_tcpdump"]), "-i", iface, "-c", str(count), "-nn"]
    if a.get("filter"):
        f = str(a["filter"])
        if not re.fullmatch(r"[A-Za-z0-9_.:\s=()/\-]{0,200}", f) or any(
                s in f for s in (";", "&", "|", "`", "$", ">", "<", "\n")):
            raise ValueError(f"Rejected capture filter: {f!r}")
        argv.append(f)
    return argv


def _b_msfconsole(a: dict) -> list[str]:
    """Scripted msfconsole: use <module>; set opts; [check;] run; exit. One argv element, no shell."""
    mod = str(a.get("module") or "").strip().lower()
    if not re.fullmatch(r"(exploit|auxiliary)/[a-z0-9_/]{1,120}", mod):
        raise ValueError("module must look like exploit/... or auxiliary/... (post/payload-only use is blocked)")
    target = _host(a.get("target"), "target")
    opts = a.get("options") or {}
    if not isinstance(opts, dict):
        raise ValueError("options must be a mapping like {RHOSTS: ..., THREADS: ...}")
    cmds = [f"use {mod}"]
    seen = set()
    for k, v in opts.items():
        k2 = str(k).upper()
        if not re.fullmatch(r"[A-Z_][A-Z0-9_]{0,29}", k2):
            raise ValueError(f"Bad option name: {k!r}")
        v2 = str(v)
        if not re.fullmatch(r"[\w.\-/:]{1,200}", v2):
            raise ValueError(f"Rejected option value for {k2} (allowed: letters/digits . - / : _)")
        cmds.append(f"set {k2} {v2}")
        seen.add(k2)
    # Pro default: point the module at the in-scope target unless told otherwise.
    if "RHOSTS" not in seen:
        cmds.append(f"set RHOSTS {target}")
    if "RHOST" not in seen:
        cmds.append(f"set RHOST {target}")
    payload = str(a.get("payload") or "").strip().lower()
    if payload:
        if not re.fullmatch(r"[a-z0-9_/]{1,120}", payload) or "/" not in payload:
            raise ValueError(f"Bad payload: {payload!r}")
        cmds.append(f"set PAYLOAD {payload}")
    if mod.startswith("exploit/") and a.get("check_first", True):
        cmds.append("check")
    cmds += ["run", "exit"]
    return [_resolve_binary(SPECS["run_msfconsole"]), "-q", "-x", "; ".join(cmds)]


_BETTERCAP_WHITELIST = {
    "net.probe", "net.show", "net.recon", "net.sniff", "arp.spoof", "dns.spoof",
    "http.proxy", "https.proxy", "ticker", "events.show", "events.stream",
    "wifi.recon", "caplets", "set", "sleep", "quit", "q", "exit", "help",
}


def _b_bettercap(a: dict) -> list[str]:
    _require_root("bettercap")
    iface = str(a.get("interface") or "eth0")
    if not re.fullmatch(r"[a-zA-Z0-9._\-]{1,16}", iface):
        raise ValueError(f"Bad interface: {iface!r}")
    raw = str(a.get("commands") or "").strip()
    if not raw:
        raise ValueError("commands is required, e.g. 'net.probe on; net.show'")
    if any(s in raw for s in ("`", "$(", "&&", "||", "|", ">", "<", "\n", "\r")):
        raise ValueError("Rejected metacharacters in bettercap script")
    stmts = [s.strip() for s in raw.split(";") if s.strip()]
    if not stmts:
        raise ValueError("Empty bettercap script")
    cleaned: list[str] = []
    for s in stmts:
        head = s.split()[0].lower()
        if head not in _BETTERCAP_WHITELIST:
            raise ValueError(f"Blocked bettercap command: {head!r} (allowlist: {sorted(_BETTERCAP_WHITELIST)})")
        m = re.fullmatch(r"sleep\s+(\d+)", s, re.IGNORECASE)
        if m and int(m.group(1)) > 300:
            raise ValueError("sleep capped at 300s per script")
        cleaned.append(s)
    if cleaned[-1].lower() not in ("quit", "q", "exit"):
        cleaned.append("q")
    return [_resolve_binary(SPECS["run_bettercap"]), "-iface", iface,
            "-eval", "; ".join(cleaned)]


# -- the registry -----------------------------------------------------------

def _props(**kw: dict) -> dict:
    return kw


SPECS: dict[str, ToolSpec] = {}

_SPECS = [
    ToolSpec("run_nmap", "nmap", description="Port scan + service/version detection. First step for almost any host.", risk="medium", target_arg="target", timeout=300,
             properties=_props(target={"type": "string", "description": "IP/CIDR/hostname in scope"},
                               ports={"type": "string", "description": "'80,443' or '1-1000'. Default: top-1000"},
                               service_detection={"type": "boolean", "description": "Add -sV. Default true"},
                               extra_args={"type": "string", "description": "Extra flags; -A/-O/--script escalate to HIGH"}),
             required=["target"], build=_b_nmap),
    ToolSpec("run_gobuster", "gobuster", description="Web directory/file fuzzing (dir mode). Use on open HTTP ports.", risk="low", target_arg="url", timeout=300,
             properties=_props(url={"type": "string", "description": "Base URL in scope"},
                               wordlist={"type": "string", "description": "Default /usr/share/wordlists/dirb/common.txt"},
                               extensions={"type": "string", "description": "'php,html,txt'"},
                               threads={"type": "integer", "description": "1-100, default 30"},
                               extra_args={"type": "string"}),
             required=["url"], build=_b_gobuster),
    ToolSpec("run_ffuf", "ffuf", description="Fast web fuzzer for dirs, vhosts, parameters.", risk="low", target_arg="url", timeout=300,
             properties=_props(url={"type": "string", "description": "FUZZ URL, e.g. http://host/FUZZ"},
                               wordlist={"type": "string"}, status_codes={"type": "string", "description": "Default 200,204,301,302,307,401,403"},
                               threads={"type": "integer", "description": "Default 40"}, extra_args={"type": "string"}),
             required=["url", "wordlist"], build=_b_ffuf),
    ToolSpec("run_sqlmap", "sqlmap", description="Automated SQL injection testing. HIGH RISK — intrusive.", risk="high", target_arg="url", timeout=600,
             properties=_props(url={"type": "string", "description": "URL with params in scope"},
                               data={"type": "string", "description": "POST data if needed"},
                               level={"type": "integer", "description": "1-5, default 1"},
                               risk={"type": "integer", "description": "1-3, default 1"},
                               batch={"type": "boolean", "description": "Default true"}),
             required=["url"], build=_b_sqlmap),
    ToolSpec("run_nuclei", "nuclei", description="Vulnerability template scanning against a target.", risk="medium", target_arg="target", timeout=600,
             properties=_props(target={"type": "string", "description": "URL/IP/host in scope"},
                               severity={"type": "string", "description": "'critical,high,medium'"},
                               templates={"type": "string", "description": "Template path or filter"},
                               extra_args={"type": "string"}),
             required=["target"], build=_b_nuclei),
    ToolSpec("run_masscan", "masscan", description="Very fast large-scale port scanner (needs root). Recon at scale.", risk="medium", target_arg="target", timeout=300,
             properties=_props(target={"type": "string"}, ports={"type": "string", "description": "Default 80,443,8080"},
                               rate={"type": "integer", "description": "Packets/sec 100-100000, default 1000"}, extra_args={"type": "string"}),
             required=["target"], build=_b_masscan),
    ToolSpec("run_nikto", "nikto", description="Web server vulnerability scanner (outdated software, misconfigs).", risk="medium", target_arg="url", timeout=900,
             properties=_props(url={"type": "string"}, tuning={"type": "string", "description": "Tuning codes, e.g. 'x'. Default all"}, extra_args={"type": "string"}),
             required=["url"], build=_b_nikto),
    ToolSpec("run_whatweb", "whatweb", description="Web technology fingerprinting (CMS, servers, versions).", risk="low", target_arg="target", timeout=300,
             properties=_props(target={"type": "string"}, aggression={"type": "integer", "description": "1-4, default 1"}, extra_args={"type": "string"}),
             required=["target"], build=_b_whatweb),
    ToolSpec("run_wafw00f", "wafw00f", description="Detect web application firewalls in front of a target.", risk="low", target_arg="target", timeout=120,
             properties=_props(target={"type": "string", "description": "URL or host in scope"}), required=["target"], build=_b_wafw00f),
    ToolSpec("run_dig", "dig", description="DNS enumeration (A/MX/TXT/NS/AXFR...). Passive-ish recon.", risk="low", target_arg="target", timeout=60,
             properties=_props(target={"type": "string", "description": "Domain in scope"},
                               query_type={"type": "string", "description": "Default A"}, dns_server={"type": "string", "description": "Custom resolver @IP"}),
             required=["target"], build=_b_dig),
    ToolSpec("run_whois", "whois", description="Domain/IP registration intel (registrar, contacts, nameservers).", risk="low", target_arg="target", timeout=60,
             properties=_props(target={"type": "string"}), required=["target"], build=_b_whois),
    ToolSpec("run_theharvester", "theHarvester", description="OSINT: emails, subdomains, hosts via public sources.", risk="low", target_arg="domain", timeout=600,
             properties=_props(domain={"type": "string", "description": "Domain in scope"},
                               sources={"type": "string", "description": "e.g. crtsh, all. Default crtsh"},
                               limit={"type": "integer", "description": "Default 100"}),
             required=["domain"], build=_b_theharvester),
    ToolSpec("run_amass", "amass", description="Subdomain enumeration (passive by default; active on request).", risk="low", target_arg="domain", timeout=900,
             properties=_props(domain={"type": "string"}, passive={"type": "boolean", "description": "Default true"},
                               timeout_mins={"type": "integer", "description": "5-120, default 30"}),
             required=["domain"], build=_b_amass),
    ToolSpec("run_sublist3r", "sublist3r", description="Fast subdomain enumeration via search engines.", risk="low", target_arg="domain", timeout=600,
             properties=_props(domain={"type": "string"}), required=["domain"], build=_b_sublist3r),
    ToolSpec("run_enum4linux", "enum4linux", description="SMB/Windows enumeration (users, shares, policies).", risk="medium", target_arg="target", timeout=600,
             properties=_props(target={"type": "string"}), required=["target"], build=_b_enum4linux),
    ToolSpec("run_smbmap", "smbmap", description="SMB share enumeration (anonymous or with creds).", risk="medium", target_arg="target", timeout=300,
             properties=_props(target={"type": "string"}, username={"type": "string"}, password={"type": "string", "description": "Masked in logs"}),
             required=["target"], build=_b_smbmap, redact=("-p",)),
    ToolSpec("run_snmpwalk", "snmpwalk", description="SNMP enumeration (community strings, system info).", risk="medium", target_arg="target", timeout=300,
             properties=_props(target={"type": "string"}, community={"type": "string", "description": "Default public"},
                               version={"type": "string", "description": "1 or 2c"}, oid={"type": "string"}),
             required=["target"], build=_b_snmpwalk),
    ToolSpec("run_ldapsearch", "ldapsearch", description="LDAP directory enumeration (users, groups).", risk="medium", target_arg="target", timeout=300,
             properties=_props(target={"type": "string"}, base_dn={"type": "string", "description": "e.g. dc=corp,dc=local"},
                               bind_dn={"type": "string"}, password={"type": "string", "description": "Masked in logs"}),
             required=["target", "base_dn"], build=_b_ldapsearch, redact=("-w",)),
    ToolSpec("run_searchsploit", "searchsploit", description="Offline Exploit-DB lookup for a product/version. No network.", risk="low", target_arg="", timeout=60,
             properties=_props(query={"type": "string", "description": "e.g. 'apache 2.4.49'"},
                               title_only={"type": "boolean", "description": "Match titles only"}),
             required=["query"], build=_b_searchsploit),
    ToolSpec("run_hydra", "hydra", description="Online password brute-force (ssh/ftp/smb/rdp/...). HIGH RISK — lockout danger, always confirms.", risk="high", target_arg="target", timeout=900,
             properties=_props(target={"type": "string"}, service={"type": "string", "description": "ssh|ftp|smb|rdp|telnet|mysql|postgres"},
                               login={"type": "string", "description": "Username to test"},
                               wordlist={"type": "string", "description": "Default rockyou.txt"},
                               threads={"type": "integer", "description": "1-16, default 4 (gentle)"}, port={"type": "integer"}),
             required=["target", "service", "login"], build=_b_hydra),
    ToolSpec("run_john", "john the Ripper", description="Offline password hash cracking. No network.", risk="low", target_arg="", timeout=900,
             properties=_props(hashfile={"type": "string", "description": "Path to hash file on this machine"},
                               wordlist={"type": "string"}, format={"type": "string", "description": "e.g. Raw-MD5"}),
             required=["hashfile"], build=_b_john),
    ToolSpec("run_feroxbuster", "feroxbuster", description="Fast recursive content discovery (gobuster alternative).", risk="low", target_arg="url", timeout=300,
             properties=_props(url={"type": "string"}, wordlist={"type": "string"},
                               threads={"type": "integer", "description": "Default 30"}, depth={"type": "integer", "description": "0-4, default 2"},
                               extra_args={"type": "string"}),
             required=["url"], build=_b_feroxbuster),
    ToolSpec("run_msfvenom", "msfvenom", description="Payload generation for exploitation stage. HIGH RISK — always confirms.", risk="high", target_arg="", timeout=300,
             properties=_props(payload={"type": "string", "description": "Whitelisted payloads only"},
                               lhost={"type": "string", "description": "Callback host (your machine)"}, lport={"type": "integer", "description": "Default 4444"},
                               format={"type": "string", "description": "exe|elf|ps1|py|php|..."}, outfile={"type": "string"}),
             required=["payload", "lhost"], build=_b_msfvenom),
    ToolSpec("run_lynis", "lynis", description="Local host security auditing (this machine). No network.", risk="low", target_arg="", timeout=900,
             properties=_props(extra_args={"type": "string"}), required=[], build=_b_lynis),
    ToolSpec("run_netexec", "netexec", description="Network service auth testing (smb/ssh/winrm/ldap...). NetExec/CrackMapExec.", risk="medium", target_arg="target", timeout=600,
             properties=_props(target={"type": "string"}, protocol={"type": "string", "description": "Default smb"},
                               username={"type": "string"}, password={"type": "string", "description": "Masked in logs"},
                               hashes={"type": "string", "description": "NTLM hash, masked in logs"}),
             required=["target"], build=_b_netexec, redact=("-p", "-H")),
    ToolSpec("run_tcpdump", "tcpdump", description="Bounded packet capture for traffic analysis (needs root).", risk="medium", target_arg="", timeout=300,
             properties=_props(interface={"type": "string", "description": "Default any"},
                               count={"type": "integer", "description": "Packets 1-1000, default 20"},
                               filter={"type": "string", "description": "BPF filter, strictly validated"}),
             required=[], build=_b_tcpdump),
    ToolSpec("run_msfconsole", "msfconsole", description="Scripted Metasploit: run scanner/exploit modules non-interactively (use/set/check/run). HIGH RISK — always confirms. RHOSTS auto-pointed at your in-scope target.", risk="high", target_arg="target", timeout=900,
             properties=_props(target={"type": "string", "description": "In-scope target; auto-set as RHOSTS/RHOST unless overridden"},
                               module={"type": "string", "description": "e.g. auxiliary/scanner/smb/smb_version or exploit/windows/smb/ms17_010_eternalblue"},
                               options={"type": "object", "description": "Module options, e.g. {\"THREADS\": \"10\"}. Values: letters/digits . - / : _ only"},
                               payload={"type": "string", "description": "Optional, e.g. windows/x64/meterpreter/reverse_tcp"},
                               check_first={"type": "boolean", "description": "Run 'check' before exploits. Default true"}),
             required=["target", "module"], build=_b_msfconsole),
    ToolSpec("run_bettercap", "bettercap", description="MITM/network-attack framework in batch mode (net.probe/arp.spoof/dns.spoof/sniff...). HIGH RISK, needs root — always confirms. Only use against in-scope networks you own.", risk="high", target_arg="", timeout=600,
             properties=_props(interface={"type": "string", "description": "e.g. eth0, wlan0"},
                               commands={"type": "string", "description": "Semicolon script, e.g. 'net.probe on; net.show'. Allowlisted commands only; auto-quits at end"}),
             required=["interface", "commands"], build=_b_bettercap),
]

for _s in _SPECS:
    SPECS[_s.name] = _s
del _s, _SPECS

EXECUTORS: dict[str, Callable[..., ToolResult]] = {name: _executor(spec) for name, spec in SPECS.items()}


def _schema_for(spec: ToolSpec) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": spec.name,
            "description": spec.description + " Target must be in scope." if spec.target_arg else spec.description,
            "parameters": {
                "type": "object",
                "properties": spec.properties,
                "required": spec.required,
            },
        },
    }


TOOL_SCHEMAS: list[dict[str, Any]] = [_schema_for(s) for s in SPECS.values()] + [
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
