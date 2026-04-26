"""Wrapper dei comandi NTAG 424 DNA (ISO 7816-4 APDU wrapping).

Riferimento: NXP AN12196 "NTAG 424 DNA — Application Note". I codici
comando sono DESFire-compatible (NTAG 424 espone una sottoapplicazione
NDEF DESFire-like con AID D2760000850101).

Struttura APDU "native wrapped":
  CLA=0x90 INS=<cmd> P1=0x00 P2=0x00 Lc=<n> <data> Le=0x00

I comandi qui implementati sono il minimo necessario per:
  1. Autenticarsi con AppKey0 (master) o AppKey2 (SDM)
  2. Cambiare le chiavi (ChangeKey)
  3. Configurare il file NDEF (02) per SDM (ChangeFileSettings)
  4. Scrivere l'NDEF con URL SUN template (WriteData)

Per operazioni più avanzate (Originality Signature, read counter, ecc.)
estendere questa classe.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field

from .crypto import (
    BLOCK_SIZE,
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    aes_cmac,
    derive_session_keys,
    rotate_left,
    truncate_cmac,
)
from .reader import Reader, ReaderError


# ---------------------------------------------------------------------------
# AID e costanti applicative
# ---------------------------------------------------------------------------

# AID della sottoapplicazione NDEF su NTAG 424 DNA
NDEF_AID = bytes.fromhex("D2760000850101")

# File ID dentro la NDEF application
FILE_CC = 0x01  # Capability Container (read-only)
FILE_NDEF = 0x02  # NDEF message — qui scriviamo l'URL
FILE_PROP = 0x03  # Proprietary file (usato da SDM per PICCData + CMAC mirror)

# Key numbers (NTAG 424 ha 5 chiavi: 0..4)
KEY_APP0 = 0x00  # master di applicazione — Change*Key, ChangeFileSettings
KEY_APP1 = 0x01
KEY_APP2 = 0x02  # tipicamente usata per SDM (CMAC generation)
KEY_APP3 = 0x03
KEY_APP4 = 0x04

# Chiavi di default dal factory NXP: 16 byte a zero per tutte e 5
FACTORY_KEY = bytes(16)

# APDU istruzioni (native-wrapped CLA=0x90)
INS_ISO_SELECT_FILE = 0xA4  # ISO 7816 SELECT (CLA=0x00 per questo)
INS_AUTH_EV2_FIRST = 0x71
INS_AUTH_EV2_NON_FIRST = 0x77
INS_ADDITIONAL_FRAME = 0xAF
INS_CHANGE_KEY = 0xC4
INS_GET_FILE_SETTINGS = 0xF5
INS_CHANGE_FILE_SETTINGS = 0x5F
INS_WRITE_DATA = 0x8D
INS_READ_DATA = 0xAD
INS_GET_UID = 0x51
INS_GET_VERSION = 0x60


# ---------------------------------------------------------------------------
# Eccezioni
# ---------------------------------------------------------------------------


class NtagError(RuntimeError):
    """Errore dal tag NTAG 424 (SW diverso da 9100/9000)."""

    def __init__(self, message: str, sw1: int | None = None, sw2: int | None = None):
        super().__init__(message)
        self.sw1 = sw1
        self.sw2 = sw2


# ---------------------------------------------------------------------------
# Sessione autenticata
# ---------------------------------------------------------------------------


@dataclass
class AuthSession:
    """Stato dopo AuthenticateEV2First: chiavi di sessione + contatore
    comandi. Serve a firmare/crittografare tutti i comandi successivi."""

    k_enc: bytes
    k_mac: bytes
    ti: bytes  # Transaction Identifier (4 byte)
    cmd_counter: int = 0  # incrementato a ogni comando autenticato
    key_no: int = 0

    def next_iv_for_cmd(self, cmd_ins: int) -> bytes:
        """IV per cifratura dati di un comando autenticato:
        IV = AES-ECB(K_SesAuthENC, 0xA55A || TI || CmdCtr || 0x0000)
        """
        from .crypto import aes_ecb_encrypt

        plain = (
            bytes([0xA5, 0x5A])
            + self.ti
            + self.cmd_counter.to_bytes(2, "little")
            + b"\x00\x00"
        )
        assert len(plain) == 16
        return aes_ecb_encrypt(self.k_enc, plain)

    def mac_input(self, cmd_ins: int, header: bytes, data: bytes) -> bytes:
        """Input per calcolo CMAC di un comando:
        CmdCtr || TI || Cmd || CmdHeader || CmdData
        """
        return (
            self.cmd_counter.to_bytes(2, "little")
            + self.ti
            + bytes([cmd_ins])
            + header
            + data
        )


# ---------------------------------------------------------------------------
# Client NTAG 424
# ---------------------------------------------------------------------------


class Ntag424:
    """Client ad alto livello per NTAG 424 DNA, sopra Reader."""

    def __init__(self, reader: Reader):
        self.reader = reader
        self.session: AuthSession | None = None

    # ---- APDU helpers ------------------------------------------------------

    def _native_apdu(self, ins: int, data: bytes = b"", le: int = 0x00) -> bytes:
        """Comando nativo NTAG (DESFire style) wrappato in ISO 7816:
        CLA=0x90 INS=ins P1=00 P2=00 Lc=len(data) <data> Le
        Le=0x00 significa "qualsiasi lunghezza" in ISO 7816 short.
        """
        apdu = bytes([0x90, ins, 0x00, 0x00, len(data)]) + data + bytes([le])
        resp, sw1, sw2 = self.reader.transmit(apdu)
        # NTAG risponde SW=91XX per comandi nativi (91 00 = ok).
        # Se SW=9000 il reader/driver ha già mappato → anche accettabile.
        return self._handle_response(resp, sw1, sw2, ins)

    def _iso_apdu(self, cla: int, ins: int, p1: int, p2: int, data: bytes) -> bytes:
        apdu = bytes([cla, ins, p1, p2, len(data)]) + data + bytes([0x00])
        resp, sw1, sw2 = self.reader.transmit(apdu)
        return self._handle_response(resp, sw1, sw2, ins)

    def _handle_response(self, resp: bytes, sw1: int, sw2: int, ins: int) -> bytes:
        # SW 91 00 = OK (DESFire-style), 90 00 = OK (ISO style),
        # 91 AF = More data (additional frame), tutto il resto errore.
        if (sw1, sw2) == (0x91, 0x00) or (sw1, sw2) == (0x90, 0x00):
            return resp
        if (sw1, sw2) == (0x91, 0xAF):
            # Additional frame: chi chiama lo gestisce
            return resp + bytes([0xAF])
        raise NtagError(
            f"Tag error on INS=0x{ins:02X}: SW={sw1:02X}{sw2:02X}",
            sw1=sw1,
            sw2=sw2,
        )

    # ---- Selezione applicazione -------------------------------------------

    def select_ndef_application(self) -> None:
        """SELECT ISO dell'applicazione NDEF (AID D2760000850101)."""
        self._iso_apdu(0x00, INS_ISO_SELECT_FILE, 0x04, 0x00, NDEF_AID)

    # ---- GetVersion / GetUID ----------------------------------------------

    def get_version(self) -> bytes:
        """Raccoglie i 3 frame di GetVersion (HW, SW, UID production info)."""
        frames = []
        resp = self._native_apdu(INS_GET_VERSION)
        frames.append(resp[:-1] if resp.endswith(b"\xaf") else resp)
        while resp.endswith(b"\xaf"):
            resp = self._native_apdu(INS_ADDITIONAL_FRAME)
            frames.append(resp[:-1] if resp.endswith(b"\xaf") else resp)
        return b"".join(frames)

    # ---- AuthenticateEV2First ---------------------------------------------

    def authenticate_ev2_first(self, key_no: int, key: bytes) -> AuthSession:
        """Protocollo di autenticazione mutua AES, lato PCD.

        Steps (AN12196 §6.6):
          1. PCD → PICC: Auth(keyNo) [+ LenCap=0x00 + PCDcap2=vuoto]
          2. PICC → PCD: E(RndB)
          3. PCD decrypt → RndB, genera RndA random, invia
             E(RndA || RndB<<8) (IV accumula lo stato precedente)
          4. PICC → PCD: E(TI || RndA<<8 || PDcap2 || PCDcap2)
          5. PCD decrypt, verifica RndA corrisponde, salva TI
          6. Deriva K_SesAuthENC e K_SesAuthMAC da RndA||RndB
        """
        if len(key) != 16:
            raise ValueError("key deve essere 16 byte (AES-128)")

        # Step 1+2: PCD invia AuthEV2First(keyNo, LenCap, PCDcap2). Per uso
        # base PCDcap2 è vuoto (LenCap=0x00), il payload è [keyNo, LenCap].
        # PICC risponde con E(RndB) (16 byte) + 0xAF.
        cmd_data = bytes([key_no, 0x00])
        resp = self._native_apdu(INS_AUTH_EV2_FIRST, cmd_data)
        if not resp.endswith(b"\xaf"):
            raise NtagError("AuthEV2First: atteso 91AF dopo primo frame")
        e_rnd_b = resp[:-1]
        if len(e_rnd_b) != 16:
            raise NtagError(f"E(RndB) lunghezza inattesa: {len(e_rnd_b)}")

        # Step 3: decrypt RndB (IV=0), genero RndA, preparo
        # E(RndA || rotl(RndB)), IV = E(RndB).
        iv0 = bytes(16)
        rnd_b = aes_cbc_decrypt(key, iv0, e_rnd_b)
        rnd_a = secrets.token_bytes(16)
        rnd_b_rot = rotate_left(rnd_b, 1)
        plain = rnd_a + rnd_b_rot
        e_payload = aes_cbc_encrypt(key, e_rnd_b, plain)

        # Step 4: invio Additional Frame con il payload. Risposta: E(TI ||
        # rotl(RndA) || PDcap2 || PCDcap2) = 32 byte, poi 9100.
        resp2 = self._native_apdu(INS_ADDITIONAL_FRAME, e_payload)
        if len(resp2) != 32:
            raise NtagError(f"AuthEV2First step2: lunghezza risposta {len(resp2)}")

        # IV per decrypt = ultimi 16 byte del payload cifrato appena inviato
        iv2 = e_payload[-16:]
        plain2 = aes_cbc_decrypt(key, iv2, resp2)
        ti = plain2[0:4]
        rnd_a_rot_recv = plain2[4:20]
        # pd_cap2 = plain2[20:26]  # 6 byte
        # pcd_cap2 = plain2[26:32] # 6 byte
        if rnd_a_rot_recv != rotate_left(rnd_a, 1):
            raise NtagError(
                "AuthEV2First: RndA rotato ricevuto non corrisponde — auth fallita"
            )

        # Step 5: derivo chiavi di sessione
        k_enc, k_mac = derive_session_keys(key, rnd_a, rnd_b)
        self.session = AuthSession(
            k_enc=k_enc,
            k_mac=k_mac,
            ti=ti,
            cmd_counter=0,
            key_no=key_no,
        )
        return self.session

    # ---- Comandi autenticati (LRP/AES modalità "Full") --------------------

    def _apdu_full(self, ins: int, header: bytes = b"", plain_data: bytes = b"") -> bytes:
        """Invia un comando in modalità Full (Enc + MAC).

        Struttura:
          CmdHeader (plain)
          E = AES-CBC_IV=IVc( PaddedData )    (solo se plain_data non vuoto)
          CMAC_in = CmdCtr || TI || INS || CmdHeader || E
          CMAC = truncate_cmac( AES-CMAC(K_SesAuthMAC, CMAC_in) )

          APDU.data = CmdHeader || E || CMAC
          Le = 0x00
        """
        if self.session is None:
            raise NtagError("Serve autenticazione prima di _apdu_full")
        s = self.session

        # Padding ISO/IEC 9797-1 metodo 2: 0x80 seguito da zero fino al
        # prossimo multiplo di 16 byte. Se plain_data è vuoto, nessuna
        # cifratura.
        encrypted = b""
        if plain_data:
            pad_len = BLOCK_SIZE - (len(plain_data) % BLOCK_SIZE)
            padded = plain_data + b"\x80" + b"\x00" * (pad_len - 1)
            if len(padded) % BLOCK_SIZE != 0:
                padded += b"\x00" * (BLOCK_SIZE - (len(padded) % BLOCK_SIZE))
            iv = s.next_iv_for_cmd(ins)
            encrypted = aes_cbc_encrypt(s.k_enc, iv, padded)

        mac_in = s.mac_input(ins, header, encrypted)
        cmac_full = aes_cmac(s.k_mac, mac_in)
        cmac_short = truncate_cmac(cmac_full)

        data = header + encrypted + cmac_short
        resp = self._native_apdu(ins, data)
        s.cmd_counter += 1

        # La risposta di solito include CMAC di risposta in coda (8 byte).
        # Per semplicità qui non la verifichiamo (accettiamo risposta se
        # SW=9100). Per produzione estendere con verifica CMAC risposta.
        return resp

    # ---- ChangeKey --------------------------------------------------------

    def change_key(
        self,
        target_key_no: int,
        new_key: bytes,
        old_key: bytes = FACTORY_KEY,
        key_version: int = 0x01,
    ) -> None:
        """Cambia una chiave. Il chiamante deve essere autenticato con
        AppKey0 (master) tipicamente; per cambiare AppKey0 stesso la sessione
        deve essere aperta con AppKey0 corrente.

        Se target == current auth key: payload = NewKey(16) || KeyVer(1)
        Se target != current auth key: payload = (NewKey XOR OldKey)(16) ||
                                        CRC32(NewKey)(4) || KeyVer(1)
        """
        if self.session is None:
            raise NtagError("Auth richiesta per ChangeKey")
        if len(new_key) != 16 or len(old_key) != 16:
            raise ValueError("Chiavi devono essere 16 byte")

        s = self.session
        header = bytes([target_key_no])

        if target_key_no == s.key_no:
            plain = new_key + bytes([key_version])
        else:
            xored = bytes(a ^ b for a, b in zip(new_key, old_key))
            crc = _crc32_nxp(new_key)
            plain = xored + crc + bytes([key_version])

        self._apdu_full(INS_CHANGE_KEY, header=header, plain_data=plain)

    # ---- ChangeFileSettings (per abilitare SDM) ---------------------------

    def change_file_settings(self, file_no: int, settings_payload: bytes) -> None:
        """Applica nuove FileSettings al file `file_no`. `settings_payload`
        è il blob plain definito da NXP, vedi sdm.build_sdm_file_settings.
        """
        if self.session is None:
            raise NtagError("Auth richiesta per ChangeFileSettings")
        header = bytes([file_no])
        self._apdu_full(INS_CHANGE_FILE_SETTINGS, header=header, plain_data=settings_payload)

    # ---- WriteData (file NDEF non cifrato) --------------------------------

    def write_ndef(self, ndef_bytes: bytes) -> None:
        """Scrive il file NDEF (02) a partire da offset 0.

        Il file 02 su NTAG 424 factory ha access right "Free" per
        read/write, quindi NON serve auth per scriverlo la prima volta.
        Si può usare il comando WriteData in modalità Plain.

        Il file NDEF su NTAG 424 ha 256 byte di capacità; i primi 2 byte
        sono l'NLEN (length) big-endian, poi il TLV/record.
        """
        # WriteData header: FileNo(1) || Offset(3 LE) || Length(3 LE)
        file_no = FILE_NDEF
        offset = 0
        length = len(ndef_bytes)
        header = (
            bytes([file_no])
            + offset.to_bytes(3, "little")
            + length.to_bytes(3, "little")
        )
        # Plain mode: data non cifrato, no CMAC
        data = header + ndef_bytes
        self._native_apdu(INS_WRITE_DATA, data)


# ---------------------------------------------------------------------------
# CRC32 specifico NXP (Jam CRC, init 0xFFFFFFFF, poly 0xEDB88320, LE output)
# ---------------------------------------------------------------------------


def _crc32_nxp(data: bytes) -> bytes:
    """CRC32 "Jam" usato da NXP per ChangeKey (CRC32 del NewKey, little-endian)."""
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xEDB88320
            else:
                crc >>= 1
    return crc.to_bytes(4, "little")
