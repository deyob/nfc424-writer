"""Primitivi crittografici per NTAG 424 DNA.

NTAG 424 DNA usa AES-128 per tutto:
  - autenticazione mutua (AuthenticateEV2First)
  - derivazione chiavi di sessione (CMAC)
  - cifratura messaggi (AES-CBC con IV ricalcolato per comando)
  - firma messaggi (AES-CMAC troncata a 8 byte)

Riferimento: NXP AN12196 "NTAG 424 DNA and NTAG 424 DNA TagTamper features
and hints" e AN12196-OMA "Operational Security / Originality Signature".
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC

BLOCK_SIZE = 16  # AES-128


def aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-128-CBC senza padding. `data` deve essere multiplo di 16."""
    if len(key) != 16:
        raise ValueError(f"key must be 16 bytes, got {len(key)}")
    if len(iv) != 16:
        raise ValueError(f"iv must be 16 bytes, got {len(iv)}")
    if len(data) % BLOCK_SIZE != 0:
        raise ValueError(f"data must be multiple of {BLOCK_SIZE}, got {len(data)}")
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-128-CBC senza padding."""
    if len(key) != 16:
        raise ValueError(f"key must be 16 bytes, got {len(key)}")
    if len(iv) != 16:
        raise ValueError(f"iv must be 16 bytes, got {len(iv)}")
    if len(data) % BLOCK_SIZE != 0:
        raise ValueError(f"data must be multiple of {BLOCK_SIZE}, got {len(data)}")
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()


def aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    """AES-128-ECB, un singolo blocco da 16 byte."""
    if len(key) != 16:
        raise ValueError(f"key must be 16 bytes, got {len(key)}")
    if len(data) != BLOCK_SIZE:
        raise ValueError(f"ECB helper expects single block of {BLOCK_SIZE}, got {len(data)}")
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def aes_cmac(key: bytes, data: bytes) -> bytes:
    """AES-CMAC (NIST SP 800-38B) con chiave AES-128, ritorna 16 byte."""
    if len(key) != 16:
        raise ValueError(f"key must be 16 bytes, got {len(key)}")
    c = CMAC(algorithms.AES(key))
    c.update(data)
    return c.finalize()


def truncate_cmac(cmac_full: bytes) -> bytes:
    """Tronca CMAC NTAG 424 a 8 byte prendendo i byte dispari (1,3,5,...,15).

    NXP-specific: "Short CMAC" (sCMAC) usa i byte in posizione dispari del
    CMAC standard a 16 byte. Cfr. AN12196 §6.4.
    """
    if len(cmac_full) != 16:
        raise ValueError(f"cmac must be 16 bytes, got {len(cmac_full)}")
    return bytes(cmac_full[i] for i in range(1, 16, 2))


def rotate_left(data: bytes, n: int = 1) -> bytes:
    """Rotazione a sinistra di n byte (usata in EV2First)."""
    if not data:
        return data
    n = n % len(data)
    return data[n:] + data[:n]


def derive_session_keys(
    key: bytes, rnd_a: bytes, rnd_b: bytes
) -> tuple[bytes, bytes]:
    """Deriva K_SesAuthENC e K_SesAuthMAC da RndA + RndB.

    Vettori di derivazione SV1 e SV2 come da AN12196 §6.7.
    """
    if len(rnd_a) != 16 or len(rnd_b) != 16:
        raise ValueError("RndA and RndB must be 16 bytes each")

    # Parti comuni di SV1/SV2
    #   SV = h1 || h2 || 0x00 || 0x01 || 0x00 || 0x80 || <diversified>
    # diversified = RndA[15:14] || (RndA[13:8] xor RndB[15:10]) || RndB[9:0] || RndA[7:0]
    ra_15_14 = rnd_a[0:2]
    ra_13_8 = rnd_a[2:8]
    rb_15_10 = rnd_b[0:6]
    xor_mid = bytes(a ^ b for a, b in zip(ra_13_8, rb_15_10))
    rb_9_0 = rnd_b[6:16]
    ra_7_0 = rnd_a[8:16]

    diversified = ra_15_14 + xor_mid + rb_9_0 + ra_7_0
    assert len(diversified) == 2 + 6 + 10 + 8 == 26

    # SV lunghezza fissa 32: header 6 byte + diversified 26
    sv1 = bytes([0xA5, 0x5A, 0x00, 0x01, 0x00, 0x80]) + diversified
    sv2 = bytes([0x5A, 0xA5, 0x00, 0x01, 0x00, 0x80]) + diversified
    assert len(sv1) == 32

    k_enc = aes_cmac(key, sv1)
    k_mac = aes_cmac(key, sv2)
    return k_enc, k_mac
