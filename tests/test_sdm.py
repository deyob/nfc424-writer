"""Test per la costruzione NDEF + calcolo offset mirror SDM."""

import pytest

from nfc424_writer.sdm import (
    PICCDATA_HEX_LEN,
    SDMMAC_HEX_LEN,
    build_ndef_for_url,
    build_sdm_file_settings,
)


URL_TEMPLATE = (
    "https://shoprfid.it/t/ABC123?picc_data={UID_COUNTER}&cmac={CMAC}"
)


def test_build_ndef_contains_zero_placeholders():
    ndef, mirrors = build_ndef_for_url(URL_TEMPLATE)
    # NDEF non deve contenere i placeholder letterali
    assert b"{UID_COUNTER}" not in ndef
    assert b"{CMAC}" not in ndef
    # Invece contiene 32 zeri per PICCData e 16 zeri per CMAC
    assert ndef.count(b"0" * PICCDATA_HEX_LEN) >= 1


def test_ndef_starts_with_nlen():
    ndef, _ = build_ndef_for_url(URL_TEMPLATE)
    # NLEN = len(record) come 2 byte BE. Record parte da offset 2.
    nlen = int.from_bytes(ndef[0:2], "big")
    assert nlen == len(ndef) - 2
    # Primo byte del record deve essere 0xD1 (MB|ME|SR|WellKnown)
    assert ndef[2] == 0xD1


def test_mirror_offsets_consistent():
    ndef, mirrors = build_ndef_for_url(URL_TEMPLATE)
    # A picc_data_offset devono esserci 32 '0' consecutivi
    assert (
        ndef[mirrors.picc_data_offset : mirrors.picc_data_offset + PICCDATA_HEX_LEN]
        == b"0" * PICCDATA_HEX_LEN
    )
    # A sdmmac_offset devono esserci 16 '0' consecutivi
    assert (
        ndef[mirrors.sdmmac_offset : mirrors.sdmmac_offset + SDMMAC_HEX_LEN]
        == b"0" * SDMMAC_HEX_LEN
    )
    # Ordine: PICCData prima di CMAC
    assert mirrors.picc_data_offset < mirrors.sdmmac_offset
    # Input del MAC parte dopo PICCData e finisce a CMAC
    assert mirrors.sdmmac_input_offset == mirrors.picc_data_offset + PICCDATA_HEX_LEN
    assert mirrors.sdmmac_input_end == mirrors.sdmmac_offset


def test_build_ndef_rejects_missing_placeholder():
    with pytest.raises(ValueError):
        build_ndef_for_url("https://example.com/")


def test_sdm_file_settings_length():
    _, mirrors = build_ndef_for_url(URL_TEMPLATE)
    payload = build_sdm_file_settings(mirrors)
    # FileOption(1) + AccessRights(2) + SDMOptions(1) + SDMAR(2) +
    # 3 offset × 3 byte = 15 byte totali
    assert len(payload) == 15


def test_sdm_file_settings_first_byte_is_sdm_enabled():
    _, mirrors = build_ndef_for_url(URL_TEMPLATE)
    payload = build_sdm_file_settings(mirrors)
    # bit 6 di FileOption = SDM enabled
    assert payload[0] & 0x40


def test_sdm_offset_encoding_little_endian():
    _, mirrors = build_ndef_for_url(URL_TEMPLATE)
    payload = build_sdm_file_settings(mirrors)
    # Offset PICCData a byte 6..8 del payload (dopo 4 byte header + 2 SDMAR)
    off_from_payload = int.from_bytes(payload[6:9], "little")
    assert off_from_payload == mirrors.picc_data_offset
