# Security Policy

## Purpose

`ccf-gpt` is a **defensive security research tool**: an AI assistant that
orchestrates standard, open-source Kali Linux utilities (nmap, nuclei,
Metasploit in scripted mode, etc.) for **authorized penetration testing and
digital forensics**. It contains no malware, no zero-day exploits, and no
bundled payloads.

## Authorized use only

- Test **only** systems you own or have **explicit written permission** to assess
  (your lab, CTF/VulnHub boxes, contracted engagements with a signed scope).
- Unauthorized scanning, exploitation, or access attempts are illegal in most
  jurisdictions. The tool's fail-closed scope lock exists to help you stay
  inside authorization — it does not grant any.
- High-risk capabilities (exploitation, brute-force, payload generation,
  MITM tooling) require explicit per-run operator confirmation by design.

## Reporting vulnerabilities

If you find a security issue **in this project itself** (e.g. a guardrail
bypass, command-injection flaw, or secret leak), please report it privately:

- Open a **private security advisory** on the GitHub repo
  (Security tab → Advisories), or contact the maintainers directly.
- Do **not** open a public issue with exploit details.
- Please allow reasonable time for a fix before any public disclosure.

## What this project will never include

- Malware, ransomware, or credential stealers
- Zero-day exploits or weaponized payloads
- Features designed to evade attribution, persistence mechanisms, or
  functionality whose primary purpose is unauthorized access
