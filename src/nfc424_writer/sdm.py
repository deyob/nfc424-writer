"""Secure Dynamic Messaging (SDM) — configurazione NTAG 424 DNA.

A scan, il chip sostituisce placeholder nel URL con:
  - **PICCData mirror** (cryptogram AES-128 di UID + ReadCounter)
    Rappresentato come 32 caratteri hex nell'URL.
  - **SDMMAC mirror** (CMAC troncato a 8 byte = 16 hex)

Il backend verifica la firma e decifra PICCData per ottenere UID e counter.
Per fare tutto questo NXP chiede di:

  1. Scrivere un NDEF in cui i due placeholder sono presenti come stringhe
     di ZERI della lunghezza giusta (non servono byte magici, solo occupare
     lo spazio).
  2. Calcolare gli offset di quei placeholder nel file NDEF (byte 0 = primo
     byte del file, incluso il prefisso NLEN del 424 che è 2 byte big-endian
     per compatibilità Type 4 Tag).
  3. Chiamare ChangeFileSettings sul file 02 con un payload che indica
     quegli offset al chip.

Il placeholder del CSV è `{UID_COUNTER}` per PICCData e `{CMAC}` per SDMMAC.
Li sostituiamo qui prima di scrivere l'NDEF.
"""

from __future__ import annotations

from dataclasses import dataclass

# Lunghezze dei placeholder nel URL finale (come caratteri ASCII)
PICCDATA_HEX_LEN = 32  # 16 byte cryptogram = 32 hex chars
SDMMAC_HEX_LEN = 16  # 8 byte CMAC troncato = 16 hex chars

PLACEHOLDER_UID_COUNTER = "{UID_COUNTER}"
PLACEHOLDER_CMAC = "{CMAC}"


@dataclass
class SdmMirrors:
    """Offset dei mirror nel payload del file NDEF (byte, non character).

    Il chip riempie quei range a scan. Gli offset sono relativi al file
    NDEF completo come lo scrive il nostro WriteData (cioè: NLEN + TLV +
    URL NDEF record). L'URL stesso parte dopo il record header.
    """

    picc_data_offset: int  # dove iniziano i 32 char del PICCData hex
    sdmmac_offset: int  # dove iniziano i 16 char del CMAC hex
    sdmmac_input_offset: int  # da dove il chip calcola il MAC (tipicamente = picc_data_offset)
    sdmmac_input_end: int  # fino a dove (byte prima di sdmmac_offset)


def build_ndef_for_url(url_with_placeholders: str) -> tuple[bytes, SdmMirrors]:
    """Costruisce il file NDEF da scrivere sul chip e calcola gli offset
    dei mirror.

    Sostituisce i placeholder nel `url_with_placeholders` con stringhe di
    zeri della lunghezza corretta, wrappa in un record NDEF URI, e ritorna
    il buffer finale + gli offset.

    Il formato file NDEF su NTAG 424 DNA (Type 4 Tag v2.0):
        NLEN   : 2 byte big-endian = lunghezza del messaggio NDEF che segue
        NDEF   : record type URI (header fisso + URL)

    Record NDEF URI (TNF=0x01 "Well Known", Type='U'):
        [Header byte: MB=1 ME=1 CF=0 SR=1 IL=0 TNF=001] = 0xD1
        [Type length = 1]
        [Payload length = len(prefix_code + url_bytes)]
        [Type: 'U' = 0x55]
        [URI identifier code: 0x00 = no prefix, dopo codice segue URL completo]
        [URL bytes]
    """
    if PLACEHOLDER_UID_COUNTER not in url_with_placeholders:
        raise ValueError(f"URL non contiene {PLACEHOLDER_UID_COUNTER}")
    if PLACEHOLDER_CMAC not in url_with_placeholders:
        raise ValueError(f"URL non contiene {PLACEHOLDER_CMAC}")

    # Sostituisce i placeholder con zeri della giusta lunghezza
    url_final = url_with_placeholders.replace(
        PLACEHOLDER_UID_COUNTER, "0" * PICCDATA_HEX_LEN
    ).replace(PLACEHOLDER_CMAC, "0" * SDMMAC_HEX_LEN)
    url_bytes = url_final.encode("ascii")

    # URI identifier code 0x00 = nessun prefisso (URL completo segue)
    uri_payload = bytes([0x00]) + url_bytes
    record = (
        bytes(
            [
                0xD1,  # MB=1 ME=1 SR=1 TNF=0x01 (Well Known)
                0x01,  # Type length
                len(uri_payload),  # Payload length (short record, 1 byte)
                0x55,  # Type 'U'
            ]
        )
        + uri_payload
    )

    # Wrapping Type 4 Tag: NLEN (2 byte BE) + record
    nlen = len(record).to_bytes(2, "big")
    file_bytes = nlen + record

    # Calcolo offset dei mirror nel buffer finale
    # Cerco la posizione dei "0" * 32 e "0" * 16 nel file_bytes
    zero_picc = b"0" * PICCDATA_HEX_LEN
    zero_cmac = b"0" * SDMMAC_HEX_LEN

    idx_picc = file_bytes.find(zero_picc)
    if idx_picc < 0:
        raise RuntimeError("Impossibile trovare placeholder PICCData nel buffer")
    # CMAC può ovviamente comparire dentro al PICCData zero-filled; cerco
    # DOPO il PICCData per sicurezza.
    search_start = idx_picc + PICCDATA_HEX_LEN
    idx_cmac = file_bytes.find(zero_cmac, search_start)
    if idx_cmac < 0:
        raise RuntimeError("Impossibile trovare placeholder CMAC nel buffer")

    mirrors = SdmMirrors(
        picc_data_offset=idx_picc,
        sdmmac_offset=idx_cmac,
        # Il MAC input è la porzione dell'URL tra fine PICCData e inizio CMAC
        # (range di byte su cui il chip calcola il CMAC — include eventuali
        # parametri query tra i due mirror). Per URL semplice come il nostro
        # il range è vuoto e il chip firma "nulla" producendo solo un CMAC
        # del contesto (TI, counter, key). Lasciamo input = picc_data_end.
        sdmmac_input_offset=idx_picc + PICCDATA_HEX_LEN,
        sdmmac_input_end=idx_cmac,
    )
    return file_bytes, mirrors


# ---------------------------------------------------------------------------
# Payload per ChangeFileSettings con SDM abilitato
# ---------------------------------------------------------------------------
#
# Struttura del payload (NTAG 424 DNA AN12196 §7.5.1.8):
#
#   FileOption         1 byte   -> 0x40 (SDM abilitato, plain mode)
#   AccessRights       2 byte   -> 0xE0 0xEE: RW=E Change=0, Read=E Write=E
#                                (per file NDEF free access)
#   SDMOptions         1 byte   -> UID, ReadCtr, ASCIIEncoding, ReadCtrLim...
#   SDMAccessRights    2 byte   -> FileRead=0xF (plain), MetaRead=0xE (any),
#                                  CtrRet=0xF (no), SDMCtrRet=0xE (any)
#   UIDOffset          3 byte   -> (opzionale, solo se SDMOptions bit UID=1)
#   SDMReadCtrOffset   3 byte   -> (opzionale)
#   PICCDataOffset     3 byte   -> posizione del mirror PICCData nel file
#   SDMMACInputOffset  3 byte   -> inizio input del MAC
#   SDMMACOffset       3 byte   -> posizione del mirror SDMMAC
#   SDMENCOffset       3 byte   -> (opzionale, encrypted file data mirror)
#   SDMENCLength       3 byte   -> (opzionale)
#   SDMReadCtrLimit    3 byte   -> (opzionale)
#
# Per il nostro MVP usiamo PICCData + SDMMAC, senza encrypted data mirror,
# senza read counter limit. UID + Counter vanno dentro PICCData cifrato, quindi
# non esponiamo UID in chiaro.


def build_sdm_file_settings(mirrors: SdmMirrors) -> bytes:
    """Crea il blob di ChangeFileSettings per il file NDEF con SDM abilitato.

    Configurazione usata:
      - FileOption = 0x40        : Plain communication + SDM enabled
      - AccessRights = 0xE0EE    : Read=E, Write=E, ReadWrite=E, Change=0
                                   (E = "free" access, 0 = key 0 per changes)
      - SDMOptions = 0xC1        : UID mirror=0, Counter mirror=0, ASCII=1,
                                   EncFileData=0, ReadCtrLimit=0,
                                   VCUID=0
                                   (0xC1 = bit7=1 Encoding ASCII,
                                    bit6=1 SDMEnabled, bit0=1 ReadCtr enabled
                                    in PICCData encryption)
      - SDMAccessRights = 0xF121 :
          nibble bassi (0x21)    : FileRead key=2, CtrRet key=1
          nibble alti  (0xF1)    : MetaRead=F(plain),
                                   (MetaRead=0xE significa "ANY key" per
                                    calcolo PICCData cryptogram)
        NOTE: 0xF121 è un esempio; in produzione verificare
        secondo AN12196 Table 22.

    Mirrors offset sono codificati little-endian a 3 byte ciascuno.
    """
    file_option = 0x40
    access_rights = bytes([0xE0, 0xEE])
    sdm_options = 0xC1
    sdm_access_rights = bytes([0x21, 0xF1])  # little-endian di 0xF121

    def _off3(n: int) -> bytes:
        return int(n).to_bytes(3, "little")

    payload = (
        bytes([file_option])
        + access_rights
        + bytes([sdm_options])
        + sdm_access_rights
        + _off3(mirrors.picc_data_offset)
        + _off3(mirrors.sdmmac_input_offset)
        + _off3(mirrors.sdmmac_offset)
    )
    return payload
