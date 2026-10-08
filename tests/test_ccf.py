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
    assert detect_provider("AQ.Ab8RN6Jxyz") == "gemini"
    assert detect_provider("garbage-key") is None
    assert detect_provider("") is None


def test_verify_key_rejects_empty():
    from ccf_gpt.config import verify_key
    ok, _ = verify_key("openai", "")
    assert ok is False


def test_registry_integrity():
    import re
    from ccf_gpt.tools import EXECUTORS, SPECS, TOOL_SCHEMAS
    assert len(SPECS) >= 20, f"expected a full arsenal, got {len(SPECS)}"
    for name, spec in SPECS.items():
        assert spec.name == name
        assert spec.description, name
        assert spec.risk in ("low", "medium", "high"), name
        assert set(spec.required) <= set(spec.properties), name
        assert name in EXECUTORS, name
    names = [s["function"]["name"] for s in TOOL_SCHEMAS]
    assert "record_finding" in names
    for name in SPECS:
        assert name in names, name


def test_builders_reject_shell_metachars():
    from ccf_gpt.tools import SPECS
    bad = {"extra_args": "; rm -rf /", "filter": "port 80; evil", "ports": "80 || 1"}
    for name, spec in SPECS.items():
        args = {k: "x" for k in spec.required}
        args.update({"target": "127.0.0.1", "url": "http://127.0.0.1/",
                     "domain": "example.com", "query": "apache",
                     "hashfile": "/tmp/x", "payload": "generic/shell_reverse_tcp",
                     "lhost": "127.0.0.1", "base_dn": "dc=x"})
        args.update(bad)
        try:
            argv = spec.build(args)
        except (ValueError, PermissionError, FileNotFoundError):
            continue  # validation/root errors are the safe outcome
        joined = " ".join(argv)
        assert ";" not in joined and "`" not in joined and "$(" not in joined, (name, joined)


def test_methodology_phases_reference_real_tools():
    from ccf_gpt.methodology import PHASES, PHASE_IDS, playbook_text
    from ccf_gpt.tools import SPECS
    assert PHASE_IDS[0] == "recon" and PHASE_IDS[-1] == "report"
    for p in PHASES:
        for tool in p["tools"]:
            assert tool in SPECS or tool in ("record_finding",), (p["id"], tool)
    assert "recon" in playbook_text("scan")


def test_phase_memory(tmp_path):
    from ccf_gpt.memory import EngagementMemory
    m = EngagementMemory(path=tmp_path / "p.db", engagement="ph")
    assert m.get_phase() == "recon"
    m.set_phase("scan")
    assert m.get_phase() == "scan"
    assert "scan" in m.context_summary()
    m.close()


def test_msfconsole_pro_and_rejections():
    import shutil
    from ccf_gpt.tools import SPECS
    build = SPECS["run_msfconsole"].build
    if shutil.which("msfconsole"):
        argv = build({"target": "10.10.10.5", "module": "auxiliary/scanner/smb/smb_version",
                      "options": {"THREADS": "10"}})
        assert argv[:3] == ["msfconsole", "-q", "-x"]
        assert "set RHOSTS 10.10.10.5" in argv[3] and argv[3].endswith("run; exit")
        argv = build({"target": "10.10.10.5",
                      "module": "exploit/windows/smb/ms17_010_eternalblue"})
        assert "; check; " in argv[3]
    for bad in [{"target": "t", "module": "post/windows/gather"},
                {"target": "t", "module": "exploit/x; rm -rf /"},
                {"target": "t", "module": "auxiliary/x",
                 "options": {"RHOSTS": "1.1.1.1; evil"}},
                {"target": "t", "module": "auxiliary/x", "payload": "x; rm"}]:
        try:
            build(bad)
        except (ValueError, PermissionError, FileNotFoundError):
            continue
        raise AssertionError(f"msfconsole accepted: {bad}")


def test_bettercap_allowlist():
    import shutil
    from ccf_gpt.tools import SPECS
    build = SPECS["run_bettercap"].build
    if shutil.which("bettercap"):
        argv = build({"interface": "eth0", "commands": "net.probe on; net.show"})
        assert argv[:4] == ["bettercap", "-iface", "eth0", "-eval"]
        assert argv[4].endswith("; q")
    for bad in [{"interface": "eth0", "commands": "exec rm -rf /"},
                {"interface": "eth0; evil", "commands": "net.show"},
                {"interface": "eth0", "commands": "net.show; sleep 9999"},
                {"interface": "eth0", "commands": "net.show | tee /tmp/x"}]:
        try:
            build(bad)
        except (ValueError, PermissionError, FileNotFoundError):
            continue
        raise AssertionError(f"bettercap accepted: {bad}")
