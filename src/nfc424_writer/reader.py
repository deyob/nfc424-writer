"""Wrapper PCSC per ACR1552U (e compatibili ACR122U, lettori CCID).

pyscard è cross-platform: funziona su macOS (pcscd nativo),
Linux (pcsc-lite + libccid), Windows (servizio Smart Card).

Niente driver vendor-specific necessari per ACR1552U su macOS moderno
(Big Sur +): il CCID driver integrato basta.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from smartcard.CardMonitoring import CardMonitor, CardObserver
from smartcard.CardRequest import CardRequest
from smartcard.CardType import AnyCardType
from smartcard.Exceptions import CardRequestTimeoutException, NoCardException
from smartcard.System import readers
from smartcard.util import toHexString


class ReaderError(RuntimeError):
    """Errore generico lato lettore / PCSC."""


@dataclass
class TagInfo:
    """Dati basilari del tag sul reader (pre-autenticazione)."""

    atr: str
    uid: bytes  # tipicamente 7 byte per NTAG 424 (manufacturer-specific)


class Reader:
    """Connessione PCSC a un lettore. Usa context manager per cleanup."""

    def __init__(self, name_substr: str | None = None, timeout: float = 10.0):
        """Seleziona il primo reader il cui nome contiene `name_substr`
        (case-insensitive). Se None, prende il primo disponibile.

        `timeout` si applica all'attesa di un tag nel metodo `wait_for_tag`.
        """
        self.name_substr = name_substr
        self.timeout = timeout
        self.connection = None
        self.reader_name: str | None = None

    def list_readers(self) -> list[str]:
        """Ritorna i nomi di tutti i lettori collegati."""
        return [str(r) for r in readers()]

    def connect(self) -> None:
        """Cerca il lettore e apre una connessione PCSC (senza ancora tag)."""
        rlist = readers()
        if not rlist:
            raise ReaderError(
                "Nessun lettore PCSC trovato. Verifica:\n"
                "  - lettore collegato e riconosciuto dal SO\n"
                "  - su macOS pcscd parte automaticamente\n"
                "  - su Linux: `sudo apt install pcscd libccid` + `sudo systemctl start pcscd`"
            )
        selected = None
        if self.name_substr:
            for r in rlist:
                if self.name_substr.lower() in str(r).lower():
                    selected = r
                    break
            if selected is None:
                raise ReaderError(
                    f"Lettore con nome contenente '{self.name_substr}' non trovato.\n"
                    f"Lettori disponibili: {[str(r) for r in rlist]}"
                )
        else:
            selected = rlist[0]
        self.reader_name = str(selected)

    def wait_for_tag(self) -> TagInfo:
        """Attende un tag sul reader (fino a `self.timeout` secondi)."""
        if self.reader_name is None:
            self.connect()
        cardtype = AnyCardType()
        try:
            cardrequest = CardRequest(
                timeout=self.timeout, cardType=cardtype, readers=readers()
            )
            cardservice = cardrequest.waitforcard()
        except CardRequestTimeoutException as e:
            raise ReaderError("Timeout: nessun tag presentato sul lettore") from e

        cardservice.connection.connect()
        self.connection = cardservice.connection
        atr = toHexString(self.connection.getATR())

        # Get UID via PC/SC escape: APDU FF CA 00 00 00 (Get Data, UID)
        uid_resp, sw1, sw2 = self.connection.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
        if (sw1, sw2) != (0x90, 0x00):
            raise ReaderError(
                f"Impossibile leggere UID: SW={sw1:02X}{sw2:02X}. "
                f"Il tag potrebbe non essere un NTAG/MIFARE."
            )
        return TagInfo(atr=atr, uid=bytes(uid_resp))

    def transmit(self, apdu: bytes | list[int]) -> tuple[bytes, int, int]:
        """Invia un APDU raw, ritorna (data, sw1, sw2)."""
        if self.connection is None:
            raise ReaderError("Nessuna connessione attiva. Chiama wait_for_tag prima.")
        apdu_list = list(apdu) if isinstance(apdu, (bytes, bytearray)) else list(apdu)
        resp, sw1, sw2 = self.connection.transmit(apdu_list)
        return bytes(resp), sw1, sw2

    def disconnect(self) -> None:
        if self.connection is not None:
            try:
                self.connection.disconnect()
            except Exception:
                pass
            self.connection = None

    # Context manager per uso pulito
    def __enter__(self) -> "Reader":
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.disconnect()

    # ---- Utility per batch -------------------------------------------------

    def wait_for_tag_removed(self, poll_interval: float = 0.3) -> None:
        """Attende che il tag venga rimosso dal lettore (utile tra un tag e
        il successivo nel batch). Polling su getATR; esce quando la
        connessione torna errore."""
        if self.connection is None:
            return
        while True:
            try:
                self.connection.getATR()
            except Exception:
                self.connection = None
                return
            time.sleep(poll_interval)


# Observer opzionale per debug — stampa inserimenti/estrazioni in tempo reale
class LoggingObserver(CardObserver):
    """Debug: stampa su console ogni connect/disconnect."""

    def update(self, observable, actions):  # noqa: D401, ARG002
        added, removed = actions
        for card in added:
            print(f"[reader] tag inserito, ATR={toHexString(card.atr)}")
        for card in removed:
            print(f"[reader] tag rimosso, ATR={toHexString(card.atr)}")


def start_logging_observer() -> tuple[CardMonitor, LoggingObserver]:
    monitor = CardMonitor()
    obs = LoggingObserver()
    monitor.addObserver(obs)
    return monitor, obs
