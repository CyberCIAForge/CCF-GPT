# ccf-gpt — CyberCIA Forge GPT

Autonomous **ReAct (Thought → Tool → Observation)** pentesting & DFIR assistant for Kali Linux.
Unlike single-command guessers (shell-gpt), `ccf-gpt` chains native Kali tools, parses massive
outputs into compact signal, remembers engagement state in SQLite, and enforces scope +
human-in-the-loop guardrails.

## Features

| Capability | How |
|---|---|
| ReAct loop | `agent.py`: Thought → Tool Call → Observation, up to N steps, auto-chains (nmap → gobuster/ffuf → nuclei → sqlmap) |
| Kali tools | `tools.py`: `run_nmap`, `run_gobuster`, `run_ffuf`, `run_sqlmap`, `run_nuclei` (+ `record_finding`) via safe `subprocess` (no `shell=True`), timeouts, missing-binary hints |
| Smart parser | `parser.py`: strips ANSI/progress bars, truncates to budget, extracts ports, services, paths, CVEs |
| Memory | `memory.py`: `~/.config/ccf-gpt/engagements.db` — targets, assets, creds, vulns, command audit log |
| Guardrails | `guardrails.py`: fail-closed scope lock (CIDR/IP/domain) + risk-tier `[y/N]` confirmation, destructive-pattern blocks |
| Multi-LLM | `llm.py` over `litellm`: `anthropic/*`, `openai/*`, `gemini/*`, `ollama/*` with retries |
| Zero-fuss setup | `ccf-gpt setup`: paste any key → provider auto-detected, verified live, matching model set |

## Install (Kali Linux)

```bash
sudo apt update && sudo apt install -y python3 python3-pip pipx git \
  nmap gobuster ffuf sqlmap nuclei dirb wordlists
# nuclei optional via apt or: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

git clone https://github.com/CyberCIAForge/CCF-GPT.git
cd CCF-GPT
pipx install -e . && pipx ensurepath
```

> Use `pipx` (or a venv), **not** `pip install --break-system-packages` — `litellm`
> pulls newer shared libraries that conflict with Kali's pre-installed tools
> (Faraday, mitmproxy, theHarvester…). Isolated install avoids that entirely.

Verify:

```bash
ccf-gpt --help
ccf-gpt config show
python -m pytest -q
```

## Quickstart

```bash
# 1. One-command setup — paste any key, the rest is automatic
ccf-gpt setup
# Detects provider from the key (sk-ant- / sk- / sk-proj- / AIza...),
# verifies it live, saves it (mode 600), picks a matching model.
# Rejected keys are refused with the provider's reason. No key?
# use local Ollama instead: ccf-gpt config set-model ollama/llama3

# 2. Chat immediately (Q&A needs no scope), or authorize scan targets:
ccf-gpt config set-scope 192.168.1.0/24 example.com
# ccf-gpt config add-scope 10.10.10.50    # append without replacing
# ccf-gpt config clear-scope              # re-lock (scans blocked again)
# one-off scope for a single run, never saved:
ccf-gpt run --scope 127.0.0.1 "Scan 127.0.0.1 for open ports"

# 3a. Single-shot autonomous run (bare prompt works like shell-gpt)
ccf-gpt "Scan 192.168.1.50 for open web ports, then fuzz directories if HTTP is open"
# equivalent explicit form: ccf-gpt run "Scan ..."
ccf-gpt run --engagement client-acme --model openai/gpt-4o "Enumerate 10.10.10.50"

# 3b. Interactive REPL (persistent memory per engagement)
ccf-gpt chat
ccf-gpt chat --engagement client-acme --scope 10.10.10.0/24

# 4. Review what the agent remembers
ccf-gpt targets
ccf-gpt findings --target 192.168.1.50
```

REPL slash commands: `/targets` `/assets [t]` `/vulns [t]` `/history` `/scope`
`/model X` `/engagement NAME` `/help` `/exit`

## Why scope?

`ccf-gpt` is an *autonomous* agent that executes network scans on its own —
pointing that at the wrong IP is potentially illegal. So scope is
**fail-closed**: chatting, Q&A, and reasoning work with no scope at all, but the
moment a tool targets a host, it must be inside your authorized scope or the run
is refused with the exact command to authorize it. Authorize once with
`config set-scope`, or per run with `--scope` (never saved).

## ReAct loop in action

```
You: Scan 192.168.1.50 for open web ports
Thought [1]: 192.168.1.50 is in scope; start with fast nmap top-1000 + -sV.
→ action: run_nmap {target: 192.168.1.50}
Confirm execution? [y/N]: y            # medium risk → explicit confirm
← observation: open=2 … 80/tcp http … 22/tcp ssh …
Thought [2]: HTTP open → fuzz with gobuster.
→ action: run_gobuster {url: http://192.168.1.50/}
← observation: paths_found=3 … [301] /admin …
Thought [3]: record findings, run nuclei on the app root.
→ action: run_nuclei {target: http://192.168.1.50/} …
## Result … open ports, paths, CVEs, next steps
```

Low-risk `run_gobuster`/`run_ffuf` auto-run; `run_nmap`/`run_nuclei` confirm;
`run_sqlmap` is always HIGH risk and always confirms. Destructive patterns
(`rm -rf /`, `;`, `||`, backticks…) are blocked outright.

## Command reference

| Command | Purpose |
|---|---|
| `ccf-gpt setup [KEY]` | Paste-a-key setup: detect → verify live → save → set model |
| `ccf-gpt run "goal" [-m MODEL] [-e ENG] [--max-iterations N] [-s SCOPE...]` | Single-shot autonomous engagement |
| `ccf-gpt chat [-e ENG] [-m MODEL] [-s SCOPE...]` | Interactive REPL with persistent memory |
| `ccf-gpt targets [-e ENG]` | List remembered targets |
| `ccf-gpt findings [-t TARGET] [-e ENG]` | Show vulns + assets |
| `ccf-gpt config show` | Full config, keys masked |
| `ccf-gpt config set-key [PROVIDER\|KEY] [KEY]` | Store key; raw key auto-detects + verifies; bad keys refused |
| `ccf-gpt config set-model MODEL` | e.g. `openai/gpt-4o`, `anthropic/claude-3-5-sonnet-20240620`, `gemini/gemini-3.8-flash`, `ollama/llama3` |
| `ccf-gpt config set-scope ...` / `add-scope ...` / `clear-scope` | Manage authorized targets |
| `ccf-gpt config set-timeout SEC` / `set-max-iterations N` | Runtime tuning (30–3600s, 1–50 steps) |

## Configuration

File: `~/.config/ccf-gpt/config.json` (mode 600). DB: `~/.config/ccf-gpt/engagements.db`.
Env overrides (no file write): `CCF_GPT_MODEL`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`,
`GEMINI_API_KEY`/`GOOGLE_API_KEY`. Defaults: temperature `0.2`, `max_iterations` 12,
`tool_timeout` 300s, `max_output_chars` 12000, low-risk tools auto-approved.

Light/small models work (`ollama/llama3.1:8b`, `openai/gpt-4o-mini`,
`gemini/gemini-3.8-flash`) — expect weaker tool-call discipline than full-size
models; keep goals simple and step budgets small.

## Project layout

```
pyproject.toml  README.md  LICENSE  .gitignore
ccf_gpt/
  __init__.py  __main__.py  cli.py  config.py  llm.py  agent.py
  tools.py  parser.py  memory.py  guardrails.py
tests/test_ccf.py
```

## Safety & legal

Authorized testing only. The scope lock is fail-closed and high-risk tools
require explicit confirmation, but **you** are responsible for authorization.
Never test systems you don't own or have written permission to assess.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `REFUSED: target … outside scope` | `ccf-gpt config set-scope <target>` or one-off `--scope <target>` |
| `Incorrect API key` / key rejected at setup | Key is wrong/revoked — generate a fresh one, re-run `ccf-gpt setup` |
| `Binary 'nmap' not found` | `sudo apt install -y nmap` (hint printed inline) |
| pip dependency conflicts (faraday/theharvester/…) | You installed into system Python — uninstall and use `pipx`/venv instead |
| `LLM call failed … 429` | Retried automatically; then check key/model (`config show`), or use `ollama/llama3` locally |
| `Timed out after Ns` | `ccf-gpt config set-timeout 600`; partial output is kept and summarized |
| Ollama errors | `ollama pull llama3 && ollama serve`, then `set-model ollama/llama3` |

## License

MIT
