#!/usr/bin/env python3
"""Seed the SQLite database used by the PGO docker-compose stack."""

from __future__ import annotations

import os
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

DEFAULT_ROWS = 5000


def seed(db_path: Path, rows: int = DEFAULT_ROWS) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS users")
    cur.execute(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    now = datetime.now(timezone.utc)
    data = [
        (
            n,
            f"User {n}",
            (now - timedelta(minutes=n)).strftime("%Y-%m-%d %H:%M:%S"),
        )
        for n in range(1, rows + 1)
    ]
    cur.executemany(
        "INSERT INTO users (id, name, created_at) VALUES (?, ?, ?)",
        data,
    )
    conn.commit()
    count = cur.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    conn.close()
    # Distroless easyrest-server runs as uid 65532 and needs WAL sidecars.
    os.chmod(db_path.parent, 0o777)
    os.chmod(db_path, 0o666)
    print(f"Seeded {count} rows into {db_path}")


def main() -> None:
    script_dir = Path(__file__).resolve().parent
    db_path = script_dir / "data" / "sqlite" / "pgo.db"
    rows = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_ROWS
    seed(db_path, rows)


if __name__ == "__main__":
    main()
