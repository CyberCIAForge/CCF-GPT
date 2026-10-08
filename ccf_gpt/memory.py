"""SQLite engagement state tracker.

Persists targets, discovered assets, credentials, vulnerabilities and a
full command audit log to ``~/.config/ccf-gpt/engagements.db`` so the
agent (and the operator) remembers state across REPL turns and runs.

Schema
------
engagements(id, name, scope, created_at)
targets(id, engagement_id, value, target_type, notes, created_at)
assets(id, engagement_id, target, kind, value, detail, created_at)
credentials(id, engagement_id, target, username, secret, service, notes, created_at)
vulnerabilities(id, engagement_id, target, severity, title, detail, cve, created_at)
command_log(id, engagement_id, tool, command, exit_code, summary, created_at)
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any

from .config import db_path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS engagements(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL,
  scope TEXT DEFAULT '',
  created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS targets(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  engagement_id INTEGER NOT NULL,
  value TEXT NOT NULL,
  target_type TEXT DEFAULT 'host',
  notes TEXT DEFAULT '',
  created_at REAL NOT NULL,
  UNIQUE(engagement_id, value)
);
CREATE TABLE IF NOT EXISTS assets(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  engagement_id INTEGER NOT NULL,
  target TEXT NOT NULL,
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  detail TEXT DEFAULT '',
  created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS credentials(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  engagement_id INTEGER NOT NULL,
  target TEXT NOT NULL,
  username TEXT DEFAULT '',
  secret TEXT DEFAULT '',
  service TEXT DEFAULT '',
  notes TEXT DEFAULT '',
  created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS vulnerabilities(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  engagement_id INTEGER NOT NULL,
  target TEXT NOT NULL,
  severity TEXT DEFAULT 'info',
  title TEXT NOT NULL,
  detail TEXT DEFAULT '',
  cve TEXT DEFAULT '',
  created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS command_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  engagement_id INTEGER NOT NULL,
  tool TEXT NOT NULL,
  command TEXT NOT NULL,
  exit_code INTEGER DEFAULT 0,
  summary TEXT DEFAULT '',
  created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS state(
  engagement_id INTEGER PRIMARY KEY,
  phase TEXT DEFAULT 'recon'
);
"""


class EngagementMemory:
    """Thin SQLite wrapper with one active engagement at a time."""

    def __init__(self, path: str | Path | None = None, engagement: str = "default") -> None:
        self.path = Path(path) if path else db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.engagement = engagement
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._engagement_id = self._ensure_engagement(engagement)

    # -- engagement -----------------------------------------------------
    def _ensure_engagement(self, name: str) -> int:
        now = time.time()
        self._conn.execute(
            "INSERT OR IGNORE INTO engagements(name, scope, created_at) VALUES(?,?,?)",
            (name, "", now),
        )
        self._conn.commit()
        row = self._conn.execute(
            "SELECT id FROM engagements WHERE name=?", (name,)
        ).fetchone()
        return int(row["id"])

    def use_engagement(self, name: str) -> None:
        self.engagement = name
        self._engagement_id = self._ensure_engagement(name)

    # -- methodology phase ------------------------------------------------
    def get_phase(self) -> str:
        row = self._conn.execute(
            "SELECT phase FROM state WHERE engagement_id=?", (self._engagement_id,)
        ).fetchone()
        if row and row["phase"]:
            return str(row["phase"])
        self.set_phase("recon")
        return "recon"

    def set_phase(self, phase: str) -> None:
        self._conn.execute(
            "INSERT INTO state(engagement_id, phase) VALUES(?,?)"
            " ON CONFLICT(engagement_id) DO UPDATE SET phase=excluded.phase",
            (self._engagement_id, phase),
        )
        self._conn.commit()

    def list_engagements(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT name, scope, datetime(created_at,'unixepoch') AS created FROM engagements ORDER BY id"
        ).fetchall()
        return [dict(r) for r in rows]

    # -- writes ---------------------------------------------------------
    def add_target(self, value: str, target_type: str = "host", notes: str = "") -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO targets(engagement_id, value, target_type, notes, created_at)"
            " VALUES(?,?,?,?,?)",
            (self._engagement_id, value.strip(), target_type, notes, time.time()),
        )
        self._conn.commit()

    def add_asset(self, target: str, kind: str, value: str, detail: str = "") -> None:
        self._conn.execute(
            "INSERT INTO assets(engagement_id, target, kind, value, detail, created_at)"
            " VALUES(?,?,?,?,?,?)",
            (self._engagement_id, target, kind, value, detail[:2000], time.time()),
        )
        self._conn.commit()

    def add_credential(
        self, target: str, username: str = "", secret: str = "",
        service: str = "", notes: str = "",
    ) -> None:
        self._conn.execute(
            "INSERT INTO credentials(engagement_id, target, username, secret, service, notes, created_at)"
            " VALUES(?,?,?,?,?,?,?)",
            (self._engagement_id, target, username, secret, service, notes, time.time()),
        )
        self._conn.commit()

    def add_vulnerability(
        self, target: str, title: str, severity: str = "info",
        detail: str = "", cve: str = "",
    ) -> None:
        self._conn.execute(
            "INSERT INTO vulnerabilities(engagement_id, target, severity, title, detail, cve, created_at)"
            " VALUES(?,?,?,?,?,?,?)",
            (self._engagement_id, target, severity, title, detail[:4000], cve, time.time()),
        )
        self._conn.commit()

    def log_command(self, tool: str, command: str, exit_code: int = 0, summary: str = "") -> None:
        self._conn.execute(
            "INSERT INTO command_log(engagement_id, tool, command, exit_code, summary, created_at)"
            " VALUES(?,?,?,?,?,?)",
            (self._engagement_id, tool, command, exit_code, summary[:4000], time.time()),
        )
        self._conn.commit()

    # -- reads ----------------------------------------------------------
    def _rows(self, sql: str, args: tuple = ()) -> list[dict[str, Any]]:
        return [dict(r) for r in self._conn.execute(sql, args).fetchall()]

    def get_targets(self) -> list[dict[str, Any]]:
        return self._rows(
            "SELECT value, target_type, notes FROM targets WHERE engagement_id=? ORDER BY id",
            (self._engagement_id,),
        )

    def get_assets(self, target: str | None = None) -> list[dict[str, Any]]:
        if target:
            return self._rows(
                "SELECT target, kind, value, detail FROM assets WHERE engagement_id=? AND target=? ORDER BY id",
                (self._engagement_id, target),
            )
        return self._rows(
            "SELECT target, kind, value, detail FROM assets WHERE engagement_id=? ORDER BY id",
            (self._engagement_id,),
        )

    def get_vulnerabilities(self, target: str | None = None) -> list[dict[str, Any]]:
        if target:
            return self._rows(
                "SELECT target, severity, title, detail, cve FROM vulnerabilities"
                " WHERE engagement_id=? AND target=? ORDER BY id",
                (self._engagement_id, target),
            )
        return self._rows(
            "SELECT target, severity, title, detail, cve FROM vulnerabilities"
            " WHERE engagement_id=? ORDER BY id",
            (self._engagement_id,),
        )

    def get_credentials(self) -> list[dict[str, Any]]:
        return self._rows(
            "SELECT target, username, service, notes FROM credentials WHERE engagement_id=? ORDER BY id",
            (self._engagement_id,),
        )

    def get_command_history(self, limit: int = 20) -> list[dict[str, Any]]:
        return self._rows(
            "SELECT tool, command, exit_code, summary FROM command_log"
            " WHERE engagement_id=? ORDER BY id DESC LIMIT ?",
            (self._engagement_id, limit),
        )

    def context_summary(self) -> str:
        """Compact state block injected into the agent system prompt."""
        targets = self.get_targets()
        assets = self.get_assets()
        vulns = self.get_vulnerabilities()
        lines = [f"Engagement: {self.engagement} (methodology phase: {self.get_phase()})"]
        lines.append("Targets: " + (", ".join(t["value"] for t in targets) or "(none yet)"))
        if assets:
            lines.append("Known assets:")
            for a in assets[-30:]:
                lines.append(f"  - [{a['target']}] {a['kind']}: {a['value']} {a['detail'][:120]}")
        if vulns:
            lines.append("Known vulnerabilities:")
            for v in vulns[-30:]:
                cve = f" ({v['cve']})" if v["cve"] else ""
                lines.append(f"  - [{v['target']}] [{v['severity']}] {v['title']}{cve}")
        hist = self.get_command_history(8)
        if hist:
            lines.append("Recent commands:")
            for h in reversed(hist):
                lines.append(f"  $ ({h['tool']} rc={h['exit_code']}) {h['command'][:160]}")
        return "\n".join(lines)

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass
