"""Smoke tests for parser, guardrails, memory (no network, no Kali binaries needed)."""
from ccf_gpt import parser as p
from ccf_gpt.guardrails import ScopeLock, classify_risk
from ccf_gpt.memory import EngagementMemory


def test_strip_ansi():
    assert p.strip_noise("\x1b[31mhello\x1b[0m") == "hello"


def test_parse_nmap():
    sample = "PORT   STATE SERVICE VERSION\n80/tcp open  http Apache httpd 2.4.49\n22/tcp open ssh OpenSSH 8.2"
    d = p.parse_nmap(sample)
    assert len(d["open_ports"]) == 2
    assert d["open_ports"][0]["port"] == 80


def test_parse_gobuster():
    sample = "/admin (Status: 301) [Size: 162]\n/index (Status: 200) [Size: 12]"
    d = p.parse_gobuster_ffuf(sample)
    assert d["count"] == 2


def test_scope_cidr():
    s = ScopeLock(["192.168.1.0/24"])
    assert s.is_in_scope("192.168.1.50")
    assert not s.is_in_scope("10.0.0.1")


def test_scope_domain():
    s = ScopeLock(["example.com"])
    assert s.is_in_scope("http://sub.example.com/path")
    assert not s.is_in_scope("evil.com")


def test_scope_empty_blocks():
    assert not ScopeLock([]).is_in_scope("192.168.1.1")


def test_risk_escalation():
    assert classify_risk("run_nmap", "run_nmap -A target=1.1.1.1") == "high"
    assert classify_risk("run_sqlmap", "run_sqlmap url=x") == "high"


def test_memory(tmp_path):
    m = EngagementMemory(path=tmp_path / "t.db", engagement="test")
    m.add_target("192.168.1.50")
    m.add_asset("192.168.1.50", "open-port", "80/tcp", "http")
    m.add_vulnerability("192.168.1.50", "SQLi", "critical", "detail", "CVE-2023-1234")
    assert len(m.get_targets()) == 1
    assert len(m.get_vulnerabilities()) == 1
    m.close()


def test_detect_provider():
    from ccf_gpt.config import detect_provider
    assert detect_provider("sk-ant-abc123") == "anthropic"
    assert detect_provider("sk-proj-abc123") == "openai"
    assert detect_provider("sk-abc123") == "openai"
    assert detect_provider("AIzaSyAbC123") == "gemini"
    assert detect_provider("garbage-key") is None
    assert detect_provider("") is None


def test_verify_key_rejects_empty():
    from ccf_gpt.config import verify_key
    ok, _ = verify_key("openai", "")
    assert ok is False
