# -*- coding: utf-8 -*-
"""Режимы работы шифров Kazual: SIV-пакет, ECB, CTR, MAC и дополнение."""

from .padding import pkcs7_pad, pkcs7_unpad, PaddingError
from .mac import siv_mac, siv_mac_streaming, GornMacError, mac_domain_tag
from .ctr import ctr_xor, ctr_iv, counter_bytes_for_block, CtrError
from .siv import (SivOptions, SivPacket, SivResult, PacketField,
                  encrypt_siv, decrypt_siv, parse_packet, MacError,
                  PacketFormatError, PREFIX_BYTES, RANDOM_BYTES, V_BYTES,
                  MAGIC, default_prefix_text)
from .ecb import encrypt_ecb, decrypt_ecb, EcbResult

__all__ = [
    'pkcs7_pad', 'pkcs7_unpad', 'PaddingError',
    'siv_mac', 'siv_mac_streaming', 'GornMacError', 'mac_domain_tag',
    'ctr_xor', 'ctr_iv', 'counter_bytes_for_block', 'CtrError',
    'SivOptions', 'SivPacket', 'SivResult', 'PacketField',
    'encrypt_siv', 'decrypt_siv', 'parse_packet', 'MacError',
    'PacketFormatError', 'PREFIX_BYTES', 'RANDOM_BYTES', 'V_BYTES',
    'MAGIC', 'default_prefix_text',
    'encrypt_ecb', 'decrypt_ecb', 'EcbResult',
]
