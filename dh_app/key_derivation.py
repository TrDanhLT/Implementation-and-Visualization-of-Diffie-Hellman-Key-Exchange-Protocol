"""HKDF-SHA256 helpers for turning a raw DH value into key material."""

from typing import Any
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from dh_app.diffie_hellman import DiffieHellmanError, validate_integer


def derive_key(
    shared_secret: Any,
    salt: bytes = b"dh-educational-simulator",
    info: bytes = b"educational-dh-aes-key",
    byte_length: int = 32,
) -> bytes:
    """Derive key material with HKDF-SHA256 from a non-negative DH integer.

    The integer is encoded as unsigned big-endian bytes. Salt and info are explicit
    context inputs; callers must agree on them. This educational helper is not a
    complete authenticated key-exchange protocol.
    """
    secret_int = validate_integer(shared_secret, "shared_secret")
    if secret_int < 0:
        raise DiffieHellmanError("shared_secret must be a non-negative integer.")

    length_int = validate_integer(byte_length, "byte_length")
    if not (1 <= length_int <= 255 * hashes.SHA256().digest_size):
        raise DiffieHellmanError("byte_length must be between 1 and 8160 bytes.")
    if not isinstance(salt, bytes) or not isinstance(info, bytes):
        raise DiffieHellmanError("salt and info must be bytes.")

    secret_bytes = max(1, (secret_int.bit_length() + 7) // 8)
    ikm = secret_int.to_bytes(secret_bytes, "big")
    return HKDF(
        algorithm=hashes.SHA256(), length=length_int, salt=salt, info=info
    ).derive(ikm)


def derive_hex_key(
    shared_secret: Any,
    salt: str = "dh-educational-simulator",
    byte_length: int = 32,
) -> str:
    """Compatibility/UI helper returning HKDF-SHA256 output as hexadecimal."""
    if not isinstance(salt, str):
        raise DiffieHellmanError("salt must be a string.")
    return derive_key(
        shared_secret, salt=salt.encode("utf-8"), byte_length=byte_length
    ).hex()
