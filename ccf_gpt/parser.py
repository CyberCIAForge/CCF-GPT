"""Smart output normalizer — keep signal, drop noise.

Kali tools dump ANSI colors, progress bars, and pages of boilerplate that
would blow up the LLM context window. This module:
  1. strips ANSI codes / carriage-return progress bars,
  2. truncates to a caller-controlled budget,
  3. extracts high-signal facts (ports, services, HTTP hits, CVEs)
     via per-tool parsers, returning a compact observation string.
"""

from __future__ import annotations

import re

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|\x1b\([AB0]")
CR_PROGRESS_RE = re.compile(r"[^\n]*\r(?!\n)")
SPINNER_RE = re.compile(r"[|/\\-]\s*\d+%|\[\s*[#=.\-\s]*\]\s*\d*%?")
NMAP_PORT_RE = re.compile(
    r"^(\d+)/(tcp|udp)\s+(\S+)\s+(\S+)(?:\s+(.*))?$", re.MULTILINE
)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
HTTP_HIT_RE = re.compile(
    r"(?P<path>/\S*?)\s+\(Status:\s*(?P<status>\d{3})\).*?\[Size:\s*(?P<size>\d+)[^\]]*\]",
    re.IGNORECASE,
)
GOBUSTER_SIMPLE_RE = re.compile(r"^(?P<path>/\S+)\s+\(Status:\s*(?P<status>\d{3})\)", re.MULTILINE)
VERSION_RE = re.compile(
    r"(Apache|nginx|OpenSSH|vsftpd|Postfix|MySQL|Microsoft-IIS|Samba|ProFTPD)[/\s][\d.a-zA-Z_-]+",
    re.IGNORECASE,
)


def strip_noise(text: str) -> str:
    """Remove ANSI codes, CR progress lines, spinner artefacts, blank runs."""
    if not text:
        return ""
    text = ANSI_RE.sub("", text)
    # Keep only the segment after the last \r on each CR-progress line
    lines: list[str] = []
    for line in text.splitlines():
        if "\r" in line:
            line = line.split("\r")[-1]
        line = SPINNER_RE.sub("", line).rstrip()
        lines.append(line)
    # Collapse 3+ blank lines and drop trailing whitespace
    out = "\n".join(lines)
    out = re.sub(r"\n{3,}", "\n\n", out)
    # Drop common boilerplate banners
    drop_substrings = [
        "Starting Nmap",
        "Nmap scan report for",
    ]
    # (keep Nmap report header out of drop list — handled by structured parser)
    _ = drop_substrings
    return out.strip()


def truncate(text: str, budget: int = 12000, head: int = 8000, tail: int = 4000) -> str:
    if len(text) <= budget:
        return text
    omitted = len(text) - head - tail
    return text[:head] + f"\n\n... [truncated {omitted} chars] ...\n\n" + text[-tail:]


def clean_output(text: str, budget: int = 12000) -> str:
    return truncate(strip_noise(text), budget)


# -- per-tool structured extractors -------------------------------------

def parse_nmap(text: str) -> dict:
    clean = strip_noise(text)
    ports: list[dict] = []
    for m in NMAP_PORT_RE.finditer(clean):
        port, proto, state, service, extra = m.groups()
        if state.lower() != "open":
            continue
        ports.append({
            "port": int(port), "proto": proto, "service": service,
            "detail": (extra or "").strip()[:200],
        })
    os_matches = re.findall(r"(?i)OS details?:\s*(.+)", clean)
    cves = sorted({c.upper() for c in CVE_RE.findall(clean)})
    versions = sorted({m.group(0) for m in VERSION_RE.finditer(clean)})[:10]
    host_up = bool(re.search(r"Host is up", clean))
    return {"open_ports": ports, "os": [o.strip() for o in os_matches][:3],
            "cves": cves, "versions": versions, "host_up": host_up}


def parse_gobuster_ffuf(text: str) -> dict:
    clean = strip_noise(text)
    hits: list[dict] = []
    for m in HTTP_HIT_RE.finditer(clean):
        hits.append({"path": m.group("path"), "status": int(m.group("status")), "size": m.group("size")})
    if not hits:
        for m in GOBUSTER_SIMPLE_RE.finditer(clean):
            hits.append({"path": m.group("path"), "status": int(m.group("status")), "size": "?"})
    # de-dup, prefer interesting statuses
    seen: dict[tuple, dict] = {}
    for h in hits:
        seen[(h["path"], h["status"])] = h
    ordered = sorted(seen.values(), key=lambda h: (h["status"] not in (200, 301, 302, 401, 403), h["path"]))
    return {"hits": ordered[:100], "count": len(ordered)}


def parse_nuclei(text: str) -> dict:
    clean = strip_noise(text)
    findings: list[dict] = []
    for line in clean.splitlines():
        if "[" in line and ("http" in line.lower() or "critical" in line.lower()
                             or "high" in line.lower() or "medium" in line.lower()):
            sev = "info"
            for s in ("critical", "high", "medium", "low", "info"):
                if f"[{s}]" in line.lower():
                    sev = s
                    break
            findings.append({"severity": sev, "line": line.strip()[:300]})
    cves = sorted({c.upper() for c in CVE_RE.findall(clean)})
    return {"findings": findings[:100], "count": len(findings), "cves": cves}


def parse_sqlmap(text: str) -> dict:
    clean = strip_noise(text)
    out: dict = {
        "injectable": bool(re.search(r"(parameter .* (is|appears).*injectable|is .* injectable|vulnerable)", clean, re.IGNORECASE)),
        "dbms": None, "databases": [], "tables": [],
    }
    m = re.search(r"back-end DBMS:\s*(.+)", clean, re.IGNORECASE)
    if m:
        out["dbms"] = m.group(1).strip()[:120]
    m2 = re.search(r"available databases\s*\[\d+\][^\n]*\n((?:\[\*\].*\n?)+)", clean, re.IGNORECASE)
    if m2:
        out["databases"] = re.findall(r"\[\*\]\s*(\S+)", m2.group(1))[:20]
    return out


SIGNAL_KEYWORDS = re.compile(
    r"(vulnerab|exploit|weak|default (cred|pass)|anonymous (login|access)|"
    r"critical|remote code|privilege|bypass|pwned|cracked|FOUND|SUCCESS)",
    re.IGNORECASE,
)


def extract_signals(text: str, limit: int = 25) -> list[str]:
    """Generic high-signal lines for tools without a dedicated parser."""
    clean = strip_noise(text)
    out: list[str] = []
    cves = sorted({c.upper() for c in CVE_RE.findall(clean)})
    if cves:
        out.append("CVEs: " + ", ".join(cves[:10]))
    for line in clean.splitlines():
        line = line.strip()
        if len(line) < 8 or len(line) > 300:
            continue
        if SIGNAL_KEYWORDS.search(line) and line not in out:
            out.append(line)
        if len(out) >= limit:
            break
    return out


def summarize(tool: str, raw: str, budget: int = 6000) -> str:
    """Build the compact observation string fed back to the LLM + memory."""
    clean = clean_output(raw, budget=budget * 2)
    header = ""
    try:
        if tool == "run_nmap":
            d = parse_nmap(clean)
            lines = [f"open={len(d['open_ports'])} host_up={d['host_up']}"]
            for p in d["open_ports"][:40]:
                lines.append(f"  {p['port']}/{p['proto']} {p['service']} {p['detail']}")
            if d["os"]:
                lines.append("OS: " + "; ".join(d["os"]))
            if d["versions"]:
                lines.append("Versions: " + ", ".join(d["versions"]))
            if d["cves"]:
                lines.append("CVEs: " + ", ".join(d["cves"][:15]))
            header = "\n".join(lines)
        elif tool in ("run_gobuster", "run_ffuf", "run_feroxbuster"):
            d = parse_gobuster_ffuf(clean)
            lines = [f"paths_found={d['count']}"]
            for h in d["hits"][:50]:
                lines.append(f"  [{h['status']}] {h['path']} (size={h['size']})")
            header = "\n".join(lines)
        elif tool == "run_nuclei":
            d = parse_nuclei(clean)
            lines = [f"findings={d['count']}"]
            for f in d["findings"][:40]:
                lines.append(f"  [{f['severity']}] {f['line']}")
            if d["cves"]:
                lines.append("CVEs: " + ", ".join(d["cves"][:15]))
            header = "\n".join(lines)
        elif tool == "run_sqlmap":
            d = parse_sqlmap(clean)
            header = f"injectable={d['injectable']} dbms={d['dbms']} databases={d['databases']}"
        else:
            sig = extract_signals(clean)
            header = "signals:\n" + "\n".join(f"  {s}" for s in sig) if sig else ""
    except Exception:
        header = ""
    body = truncate(clean, budget)
    if header:
        return f"--- structured summary ({tool}) ---\n{header}\n\n--- raw (cleaned, truncated) ---\n{body}"
    return body
