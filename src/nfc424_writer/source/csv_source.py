"""Sorgente batch da CSV esportato dal portale ShopRFID.

Formato CSV atteso (colonne come prodotte da Slice 20 "bulk export"):

    short_code, secret_key, label, url_template, plain_url

All'esecuzione il tool appende colonne di stato: `uid`, `programmed_at`,
`status`, `error` — così rilanciandolo ignora le righe già fatte e non
riprogramma tag.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .base import BatchSource, TagJob

STATUS_COLUMNS = ["uid", "programmed_at", "status", "error"]


class CsvSource(BatchSource):
    def __init__(self, path: Path | str):
        self.path = Path(path)
        if not self.path.exists():
            raise FileNotFoundError(f"CSV non trovato: {self.path}")
        self._rows: list[dict[str, str]] = []
        self._fieldnames: list[str] = []
        self._load()

    def _load(self) -> None:
        with self.path.open(newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            self._fieldnames = list(reader.fieldnames or [])
            self._rows = [dict(r) for r in reader]
        # Assicura che le colonne di stato esistano
        added = False
        for col in STATUS_COLUMNS:
            if col not in self._fieldnames:
                self._fieldnames.append(col)
                added = True
        if added:
            for r in self._rows:
                for col in STATUS_COLUMNS:
                    r.setdefault(col, "")

    def _save(self) -> None:
        with self.path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self._fieldnames)
            writer.writeheader()
            writer.writerows(self._rows)

    def iter_jobs(self) -> Iterator[TagJob]:
        """Yielda solo i job non ancora completati con successo."""
        for row in self._rows:
            if (row.get("status") or "").lower() == "ok":
                continue  # già fatto
            yield TagJob(
                short_code=row["short_code"],
                secret_key_hex=row["secret_key"],
                label=row.get("label", ""),
                url_template=row["url_template"],
                plain_url=row.get("plain_url", ""),
            )

    def _find_row(self, job: TagJob) -> dict[str, str] | None:
        for r in self._rows:
            if r.get("short_code") == job.short_code:
                return r
        return None

    def mark_done(self, job: TagJob, uid_hex: str, status: str = "ok") -> None:
        row = self._find_row(job)
        if row is None:
            return
        row["uid"] = uid_hex
        row["programmed_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        row["status"] = status
        row["error"] = ""
        self._save()

    def mark_error(self, job: TagJob, error: str) -> None:
        row = self._find_row(job)
        if row is None:
            return
        row["status"] = "error"
        row["error"] = error[:500]  # evita header CSV mostruosi
        self._save()
