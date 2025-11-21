"""
encrypted database server with deterministic ppe-style rows

this module models a simple encrypted database where:
- the server holds an encrypted row per user (one logical record)
- encryption is deterministic per attribute to support equality-style matches
- the client holds the key and can request encrypted rows by user id

note: this is an in-memory python model, not a real sql engine. it is
intended to capture the protocol shape for the rest of the system.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Any, Optional


@dataclass
class DeterministicCiphertext:
    """simple deterministic ciphertext wrapper"""

    raw: bytes


class EncryptedDatabaseServer:
    """server-side encrypted database over user rows

    the server stores, for each user_id, a mapping from attribute
    name to deterministic ciphertext. it cannot decrypt values; it
    only compares ciphertexts for equality and returns encrypted
    rows to the client.
    """

    def __init__(self, key: bytes) -> None:
        self._key = key
        self._rows: Dict[str, Dict[str, DeterministicCiphertext]] = {}

    def _deterministic_encrypt(self, plaintext: bytes) -> DeterministicCiphertext:
        import hashlib

        h = hashlib.blake2b(digest_size=len(plaintext))
        h.update(self._key)
        h.update(plaintext)
        keystream = h.digest()
        raw = bytes([p ^ k for p, k in zip(plaintext, keystream)])
        return DeterministicCiphertext(raw=raw)

    def load_plaintext_row(self, user_id: str, attributes: Dict[str, str]) -> None:
        """load a single plaintext row into the encrypted table

        attributes is a mapping from attribute name to string value.
        we encode values as utf-8 bytes and apply deterministic
        encryption per attribute.
        """

        enc_row: Dict[str, DeterministicCiphertext] = {}
        for name, value in attributes.items():
            enc_row[name] = self._deterministic_encrypt(value.encode("utf-8"))
        self._rows[str(user_id)] = enc_row

    def get_encrypted_row(self, user_id: str) -> Optional[Dict[str, DeterministicCiphertext]]:
        """return encrypted row for user_id, or none if missing"""

        return self._rows.get(str(user_id))

    def query_by_equality(self, attr_name: str, plaintext_value: str) -> Dict[str, Dict[str, DeterministicCiphertext]]:
        """return all rows where attr_name equals plaintext_value

        the client is expected to know the key and could compute the
        deterministic ciphertext; here we keep the api simple and let
        the server perform the encryption internally to match values.
        this is equivalent to a cryptdb-style where clause over an
        equality-preserving column.
        """

        target_ct = self._deterministic_encrypt(plaintext_value.encode("utf-8")).raw
        result: Dict[str, Dict[str, DeterministicCiphertext]] = {}
        for uid, row in self._rows.items():
            ct = row.get(attr_name)
            if ct is not None and ct.raw == target_ct:
                result[uid] = row
        return result
