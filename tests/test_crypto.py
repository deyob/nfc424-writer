"""Test vettori noti per crypto primitives."""

import pytest

from nfc424_writer.crypto import (
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    aes_cmac,
    aes_ecb_encrypt,
    derive_session_keys,
    rotate_left,
    truncate_cmac,
)


# Vettore NIST CMAC AES-128 (SP 800-38B, esempio D.1)
#   K = 2b7e1516 28aed2a6 abf71588 09cf4f3c
#   Mlen = 0 bit: T = bb1d6929 e9593728 7fa37d12 9b756746
#   Mlen = 128 bit (blocco singolo):
#     M = 6bc1bee2 2e409f96 e93d7e11 7393172a
#     T = 070a16b4 6b4d4144 f79bdd9d d04a287c
def test_aes_cmac_empty():
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    expected = bytes.fromhex("bb1d6929e95937287fa37d129b756746")
    assert aes_cmac(key, b"") == expected


def test_aes_cmac_one_block():
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    msg = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    expected = bytes.fromhex("070a16b46b4d4144f79bdd9dd04a287c")
    assert aes_cmac(key, msg) == expected


def test_truncate_cmac_takes_odd_indices():
    full = bytes(range(16))  # 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
    # Byte dispari: 01, 03, 05, 07, 09, 0b, 0d, 0f
    expected = bytes([1, 3, 5, 7, 9, 11, 13, 15])
    assert truncate_cmac(full) == expected


def test_rotate_left_1():
    assert rotate_left(b"\x01\x02\x03\x04", 1) == b"\x02\x03\x04\x01"


def test_rotate_left_2():
    assert rotate_left(b"\x01\x02\x03\x04", 2) == b"\x03\x04\x01\x02"


def test_aes_cbc_roundtrip():
    key = bytes(16)
    iv = bytes(16)
    pt = bytes(range(32))
    ct = aes_cbc_encrypt(key, iv, pt)
    assert aes_cbc_decrypt(key, iv, ct) == pt


def test_aes_ecb_single_block():
    # Vettore FIPS 197 B: K=000..0, PT=0, CT=66e94bd4ef8a2c3b884cfa59ca342b2e
    key = bytes(16)
    pt = bytes(16)
    expected = bytes.fromhex("66e94bd4ef8a2c3b884cfa59ca342b2e")
    assert aes_ecb_encrypt(key, pt) == expected


def test_derive_session_keys_lengths():
    key = bytes(16)
    rnd_a = bytes(range(16))
    rnd_b = bytes(range(16, 32))
    k_enc, k_mac = derive_session_keys(key, rnd_a, rnd_b)
    assert len(k_enc) == 16
    assert len(k_mac) == 16
    # Diverse tra loro (header SV1/SV2 differente)
    assert k_enc != k_mac


def test_key_validation():
    with pytest.raises(ValueError):
        aes_cmac(b"short", b"")
    with pytest.raises(ValueError):
        aes_cbc_encrypt(b"short", bytes(16), bytes(16))
