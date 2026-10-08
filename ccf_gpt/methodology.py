"""Ethical-hacking methodology engine (PTES-inspired, condensed for agents).

The ReAct loop consults this playbook: each phase declares its goal,
rules of engagement, preferred tools, and exit criteria. The agent tracks
the current phase in engagement memory (see ``set_phase`` tool) and the
playbook text is injected into its system prompt.
"""

from __future__ import annotations

PHASES: list[dict] = [
    {
        "id": "recon",
        "name": "Passive Reconnaissance",
        "goal": "Learn everything about the target without touching it aggressively.",
        "rules": [
            "Prefer passive sources (DNS, WHOIS, OSINT, search engines).",
            "No brute-forcing, no exploitation, no payload generation.",
        ],
        "tools": ["run_whois", "run_dig", "run_sublist3r", "run_amass", "run_theharvester"],
        "exit": "Have: domains, subdomains, emails, IPs, technologies. Then set_phase(scan).",
    },
    {
        "id": "scan",
        "name": "Scanning & Discovery",
        "goal": "Find live hosts, open ports, services and versions.",
        "rules": [
            "Stay inside scope; fast SYN scans before deep ones.",
            "masscan/tcpdump need root and explicit confirmation.",
        ],
        "tools": ["run_nmap", "run_masscan", "run_whatweb", "run_wafw00f"],
        "exit": "Have: live hosts + open ports + service versions. Then set_phase(enumerate).",
    },
    {
        "id": "enumerate",
        "name": "Enumeration",
        "goal": "Squeeze every open service for users, shares, paths and banners.",
        "rules": [
            "Enumerate before attacking: web dirs, SMB, SNMP, LDAP, DNS zone data.",
            "Record every asset with record_finding so nothing is lost.",
        ],
        "tools": ["run_gobuster", "run_ffuf", "run_feroxbuster", "run_enum4linux",
                  "run_smbmap", "run_snmpwalk", "run_ldapsearch", "run_nikto"],
        "exit": "Have: web paths, shares/users where available, service details. Then set_phase(vuln).",
    },
    {
        "id": "vuln",
        "name": "Vulnerability Analysis",
        "goal": "Map findings to known vulnerabilities (no exploitation yet).",
        "rules": [
            "Correlate versions with CVEs via nuclei + searchsploit.",
            "Rank by severity and exploitability; report uncertain items as-is.",
        ],
        "tools": ["run_nuclei", "run_searchsploit"],
        "exit": "Have: ranked vuln list with CVEs where possible. Then set_phase(exploit) only if authorized.",
    },
    {
        "id": "exploit",
        "name": "Exploitation (Authorized Only)",
        "goal": "Prove impact on explicitly-authorized targets, minimally and reversibly.",
        "rules": [
            "HIGH-RISK tools always need operator confirmation — propose, never assume.",
            "Prefer the least intrusive proof (e.g. sqlmap --risk=1 before higher).",
            "Stop immediately on unexpected impact; record everything.",
        ],
        "tools": ["run_sqlmap", "run_hydra", "run_msfvenom", "run_msfconsole",
                  "run_bettercap", "run_netexec", "run_john"],
        "exit": "Have: confirmed findings with evidence, or documented failure. Then set_phase(post).",
    },
    {
        "id": "post",
        "name": "Post-Exploitation Notes",
        "goal": "Document access obtained and business impact; minimal footprint.",
        "rules": [
            "No persistence mechanisms, no lateral movement beyond scope.",
            "Credentials found go to memory as credentials, secrets masked.",
        ],
        "tools": ["record_finding"],
        "exit": "Impact documented. Then set_phase(report).",
    },
    {
        "id": "report",
        "name": "Reporting",
        "goal": "Summarize: scope, assets, vulnerabilities (severity + CVE), evidence, remediation next steps.",
        "rules": [
            "Lead with critical/high findings; include exact reproduction where safe.",
            "End with prioritized remediation and retest suggestions.",
        ],
        "tools": ["record_finding"],
        "exit": "Final summary delivered to the operator.",
    },
]

PHASE_IDS = [p["id"] for p in PHASES]


def get_phase(pid: str) -> dict:
    for p in PHASES:
        if p["id"] == pid:
            return p
    return PHASES[0]


def playbook_text(current: str = "recon") -> str:
    lines = ["PENETRATION-TEST METHODOLOGY (follow in order, track with set_phase):"]
    for p in PHASES:
        mark = ">> CURRENT" if p["id"] == current else ""
        lines.append(
            f"- {p['id']}: {p['name']} {mark}\n"
            f"  goal: {p['goal']}\n"
            f"  rules: {' '.join(p['rules'])}\n"
            f"  tools: {', '.join(p['tools'])}\n"
            f"  done when: {p['exit']}"
        )
    return "\n".join(lines)
