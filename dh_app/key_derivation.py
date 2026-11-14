"""Educational key derivation helper showing how a raw DH integer becomes a symmetric key."""

import hashlib
from typing import Any

from dh_app.diffie_hellman import DiffieHellmanError, validate_integer


def derive_hex_key(
    shared_secret: Any,
    salt: str = "dh-educational-simulator",
    byte_length: int = 32,
) -> str:
    """Derive a fixed-length hexadecimal symmetric key from a shared secret using SHA-256.

    In practical protocols, raw Diffie-Hellman integers are never used directly as
    block-cipher keys; instead they are passed through a Key Derivation Function (KDF).
    """
    secret_int = validate_integer(shared_secret, "shared_secret")
    if secret_int < 0:
        raise DiffieHellmanError("shared_secret must be a non-negative integer.")

    length_int = validate_integer(byte_length, "byte_length")
    if not (1 <= length_int <= 32):
        raise DiffieHellmanError("byte_length must be between 1 and 32 bytes.")

    payload = f"{salt}:{secret_int}".encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()
    return digest[: length_int * 2]
