# -*- coding: utf-8 -*-
"""Режимы работы шифров Kazual: контейнер v2, SIV (tree-MAC), ECB, CTR, PKCS#7."""

from .padding import pkcs7_pad, pkcs7_unpad, PaddingError
from .mac import (tree_mac, tree_leaf_digest, tree_root_hasher,
                  GornMacError, V_BYTES, DEFAULT_LEAF_SIZE)
from .ctr import ctr_xor, ctr_iv, counter_bytes_for_block, CtrError
from .siv import (SivOptions, SivResult, PacketField, MacError,
                  PacketFormatError, RANDOM_BYTES, MAGIC)
from .ecb import encrypt_ecb, decrypt_ecb, EcbResult
from .container import (ContainerInfo, build_header, parse_header,
                        is_container, MODE_SIV, MODE_ECB)
from .siv2 import encrypt_siv2, decrypt_siv2, encrypt_ecb2, decrypt_ecb2

__all__ = [
    'pkcs7_pad', 'pkcs7_unpad', 'PaddingError',
    'tree_mac', 'tree_leaf_digest', 'tree_root_hasher', 'GornMacError',
    'V_BYTES', 'DEFAULT_LEAF_SIZE',
    'ctr_xor', 'ctr_iv', 'counter_bytes_for_block', 'CtrError',
    'SivOptions', 'SivResult', 'PacketField', 'MacError',
    'PacketFormatError', 'RANDOM_BYTES', 'MAGIC',
    'encrypt_ecb', 'decrypt_ecb', 'EcbResult',
    'ContainerInfo', 'build_header', 'parse_header', 'is_container',
    'MODE_SIV', 'MODE_ECB',
    'encrypt_siv2', 'decrypt_siv2', 'encrypt_ecb2', 'decrypt_ecb2',
]
