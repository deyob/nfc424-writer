"""Interfaccia comune per sorgenti di batch."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, Protocol


@dataclass
class TagJob:
    """Un singolo tag da programmare."""

    short_code: str
    secret_key_hex: str  # 32 caratteri hex = 16 byte AES
    label: str
    url_template: str  # con placeholder {UID_COUNTER} e {CMAC}
    plain_url: str  # fallback senza SDM

    def secret_key_bytes(self) -> bytes:
        return bytes.fromhex(self.secret_key_hex)


class BatchSource(Protocol):
    """Sorgente iterabile di TagJob."""

    def iter_jobs(self) -> Iterator[TagJob]: ...

    def mark_done(self, job: TagJob, uid_hex: str, status: str = "ok") -> None:
        """Marca il job come completato (persistenza opzionale)."""

    def mark_error(self, job: TagJob, error: str) -> None:
        """Marca il job come fallito."""
