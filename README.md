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

## Install (Kali Linux)

```bash
sudo apt update && sudo apt install -y python3 python3-pip nmap gobuster ffuf sqlmap nuclei \
  dirb wordlists  # nuclei optional via apt or go install

git clone <this-repo> && cd ccf-gpt
pip install -e .            # or: pipx install -e . / uv pip install -e .
```

Verify:

```bash
ccf-gpt --help
ccf-gpt config show
python -m pytest -q
```

## Quickstart

```bash
# 1. Pick a model + key (or use local Ollama — no key needed)
ccf-gpt config set-model anthropic/claude-3-5-sonnet-20240620
ccf-gpt config set-key anthropic          # prompts securely; or export ANTHROPIC_API_KEY=…
# openai / gemini analogous; local: ccf-gpt config set-model ollama/llama3

# 2. Lock scope FIRST (fail-closed: scans are refused until scope is set)
ccf-gpt config set-scope 192.168.1.0/24 example.com
# ccf-gpt config add-scope 10.10.10.50   # append
# ccf-gpt config clear-scope             # re-lock

# 3a. Single-shot autonomous run
ccf-gpt run "Scan 192.168.1.50 for open web ports, then fuzz directories if HTTP is open"

# 3b. Interactive REPL (persistent memory per engagement)
ccf-gpt chat
ccf-gpt chat --engagement client-acme --model openai/gpt-4o

# 4. Review state
ccf-gpt targets
ccf-gpt findings --target 192.168.1.50
```

REPL slash commands: `/targets /assets [t] /vulns [t] /history /scope /model X /engagement NAME /help /exit`

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

## Configuration

File: `~/.config/ccf-gpt/config.json` (mode 600), DB: `~/.config/ccf-gpt/engagements.db`.
Env overrides: `CCF_GPT_MODEL`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`/`GOOGLE_API_KEY`.

```bash
ccf-gpt config show
ccf-gpt config set-model openai/gpt-4o
ccf-gpt config set-key openai
ccf-gpt config set-timeout 600
ccf-gpt config set-max-iterations 15
```

## Project layout

```
pyproject.toml
ccf_gpt/
  __init__.py  cli.py  config.py  llm.py  agent.py
  tools.py  parser.py  memory.py  guardrails.py  __main__.py
tests/test_ccf.py
```

## Safety & legal

Authorized testing only. The scope lock is fail-closed and high-risk tools
require explicit confirmation, but **you** are responsible for authorization.
Never test systems you don't own or have written permission to assess.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `REFUSED: target … outside scope` | `ccf-gpt config set-scope <your-target>` |
| `Binary 'nmap' not found` | `sudo apt install -y nmap` (hint printed inline) |
| `LLM call failed … 429` | waits + retries automatically; then check key/model (`config show`), or use `ollama/llama3` locally |
| `Timed out after Ns` | `ccf-gpt config set-timeout 600`; partial output is kept and summarized |
| Ollama errors | `ollama pull llama3 && ollama serve`, then `set-model ollama/llama3` |

## License

MIT
