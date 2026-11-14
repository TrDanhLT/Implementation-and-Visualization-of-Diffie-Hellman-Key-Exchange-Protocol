"""Mathematical core and validation logic for the Diffie-Hellman Key Exchange Protocol.

Mathematical Overview:
1. Public parameters:
   - A prime modulus p >= 5.
   - A generator (primitive root modulo p) g in {2, ..., p - 2} whose multiplicative
     order modulo p is p - 1.
2. Private keys:
   - Alice selects secret integer a in [2, p - 2].
   - Bob selects secret integer b in [2, p - 2].
3. Public keys:
   - Alice computes A = g^a mod p.
   - Bob computes B = g^b mod p.
4. Shared secret:
   - Alice computes S_A = B^a mod p = (g^b)^a mod p = g^(ab) mod p.
   - Bob computes S_B = A^b mod p = (g^a)^b mod p = g^(ab) mod p.
   - By modular exponentiation properties, S_A == S_B.

Educational Disclaimer:
The small primes supported by this interactive simulator are strictly for classroom
and self-study visualization. Production systems require standardized safe primes
(at least 2048-3072 bits) or elliptic-curve groups (e.g., X25519) combined with
explicit authentication (such as TLS certificates or digital signatures).
"""

from dataclasses import dataclass
import secrets
from typing import Any, List, Set, Tuple, TypedDict


class DiffieHellmanError(ValueError):
    """Raised when Diffie-Hellman parameters, keys, or group properties are invalid."""


class ExchangeResult(TypedDict):
    """Structured result dictionary returned by calculate_exchange."""

    p: int
    g: int
    a: int
    b: int
    A: int
    B: int
    alice_secret: int
    bob_secret: int
    shared_secret: int


@dataclass(frozen=True)
class ModularStep:
    """Represents a single bit-processing step in right-to-left square-and-multiply."""

    step_index: int
    bit: int
    base_before: int
    result_before: int
    multiplied: bool
    result_after: int
    base_after: int
    explanation: str


def validate_integer(value: Any, name: str) -> int:
    """Ensure value is a true Python int and explicitly reject booleans or other types."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise DiffieHellmanError(
            f"{name} must be an integer (got {type(value).__name__})."
        )
    return value


def is_prime(n: Any) -> bool:
    """Return True if n is a prime integer >= 2; return False for non-primes or invalid types."""
    if isinstance(n, bool) or not isinstance(n, int):
        return False
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False

    divisor = 5
    while divisor * divisor <= n:
        if n % divisor == 0 or n % (divisor + 2) == 0:
            return False
        divisor += 6
    return True


def prime_factors(n: int) -> Set[int]:
    """Return the set of distinct prime factors of integer n >= 2."""
    n = validate_integer(n, "n")
    if n < 2:
        raise DiffieHellmanError("n must be an integer >= 2 to factorize.")

    factors: Set[int] = set()
    divisor = 2
    while divisor * divisor <= n:
        if n % divisor == 0:
            factors.add(divisor)
            while n % divisor == 0:
                n //= divisor
        divisor += 1
    if n > 1:
        factors.add(n)
    return factors


def is_generator(g: Any, p: Any) -> bool:
    """Check whether g is a primitive root (generator) modulo prime p.

    A number g in {2, ..., p - 1} is a primitive root modulo prime p if and only if
    g^((p - 1) / q) != 1 (mod p) for every prime factor q of (p - 1).
    """
    if isinstance(g, bool) or not isinstance(g, int):
        return False
    if isinstance(p, bool) or not isinstance(p, int):
        return False
    if not is_prime(p) or p < 5:
        return False
    if not (2 <= g <= p - 2):
        return False

    totient = p - 1
    for factor in prime_factors(totient):
        if pow(g, totient // factor, p) == 1:
            return False
    return True


def validate_parameters(p: Any, g: Any) -> Tuple[int, int]:
    """Validate prime modulus p >= 5 and generator g modulo p."""
    p_int = validate_integer(p, "Prime modulus (p)")
    g_int = validate_integer(g, "Generator (g)")

    if p_int < 5 or not is_prime(p_int):
        raise DiffieHellmanError(
            f"Prime modulus p={p_int} must be a prime number greater than or equal to 5."
        )

    if not (2 <= g_int <= p_int - 2):
        raise DiffieHellmanError(
            f"Generator g={g_int} must satisfy 2 <= g <= p - 2 ({p_int - 2})."
        )

    if not is_generator(g_int, p_int):
        raise DiffieHellmanError(
            f"g={g_int} is not a primitive root (generator) modulo p={p_int}."
        )

    return p_int, g_int


def validate_private_key(key: Any, p: int, owner: str = "Private key") -> int:
    """Validate that a private key is an integer in the range [2, p - 2]."""
    p_int = validate_integer(p, "Prime modulus (p)")
    if p_int < 5 or not is_prime(p_int):
        raise DiffieHellmanError(
            f"Prime modulus p={p_int} must be a prime number >= 5."
        )

    key_int = validate_integer(key, owner)
    if not (2 <= key_int <= p_int - 2):
        raise DiffieHellmanError(
            f"{owner} ({key_int}) must be an integer between 2 and p - 2 ({p_int - 2})."
        )
    return key_int


def validate_public_key(public_key: Any, p: int, owner: str = "Public key") -> int:
    """Validate that a received public key lies in the non-trivial subgroup [2, p - 2].

    Rejects trivial/degenerate values (0, 1, p - 1, or values outside [2, p - 2])
    that would leak the shared secret or force a small subgroup.
    """
    p_int = validate_integer(p, "Prime modulus (p)")
    if p_int < 5 or not is_prime(p_int):
        raise DiffieHellmanError(
            f"Prime modulus p={p_int} must be a prime number >= 5."
        )

    pub_int = validate_integer(public_key, owner)
    if not (2 <= pub_int <= p_int - 2):
        raise DiffieHellmanError(
            f"{owner} ({pub_int}) must lie in [2, p - 2] ({p_int - 2}) to avoid trivial values."
        )
    return pub_int


def generate_private_key(p: Any) -> int:
    """Generate a cryptographically random private key in [2, p - 2] using secrets."""
    p_int = validate_integer(p, "Prime modulus (p)")
    if p_int < 5 or not is_prime(p_int):
        raise DiffieHellmanError(
            "p must be a prime number greater than or equal to 5."
        )
    return secrets.randbelow(p_int - 3) + 2


def modular_exponentiation_steps(
    base: Any, exponent: Any, modulus: Any
) -> Tuple[int, List[ModularStep]]:
    """Compute (base ** exponent) % modulus using binary square-and-multiply.

    Returns the final integer result along with a step-by-step trace of every bit
    processed from least-significant bit (LSB) to most-significant bit (MSB).
    """
    base_int = validate_integer(base, "Base")
    exp_int = validate_integer(exponent, "Exponent")
    mod_int = validate_integer(modulus, "Modulus")

    if mod_int < 2:
        raise DiffieHellmanError("Modulus must be an integer >= 2.")
    if exp_int < 0:
        raise DiffieHellmanError("Exponent must be a non-negative integer.")

    if exp_int == 0:
        final_val = 1 % mod_int
        step = ModularStep(
            step_index=1,
            bit=0,
            base_before=base_int % mod_int,
            result_before=1,
            multiplied=False,
            result_after=final_val,
            base_after=(base_int * base_int) % mod_int,
            explanation=f"Exponent is 0, so {base_int}^0 mod {mod_int} = {final_val}.",
        )
        return final_val, [step]

    steps: List[ModularStep] = []
    result = 1
    current_base = base_int % mod_int
    remaining_exp = exp_int
    step_idx = 1

    while remaining_exp > 0:
        bit = remaining_exp & 1
        result_before = result
        base_before = current_base

        if bit == 1:
            result = (result * current_base) % mod_int
            multiplied = True
            mult_desc = (
                f"Bit is 1: multiply result = ({result_before} * {base_before}) mod {mod_int} = {result}."
            )
        else:
            multiplied = False
            mult_desc = f"Bit is 0: keep result = {result_before} unchanged."

        next_base = (current_base * current_base) % mod_int
        remaining_exp >>= 1

        if remaining_exp > 0:
            square_desc = f" Square base for next bit: ({base_before}^2) mod {mod_int} = {next_base}."
        else:
            square_desc = " Final bit processed; squaring no longer needed."

        steps.append(
            ModularStep(
                step_index=step_idx,
                bit=bit,
                base_before=base_before,
                result_before=result_before,
                multiplied=multiplied,
                result_after=result,
                base_after=next_base,
                explanation=mult_desc + square_desc,
            )
        )
        current_base = next_base
        step_idx += 1

    return result, steps


def calculate_exchange(p: Any, g: Any, a: Any, b: Any) -> ExchangeResult:
    """Validate parameters and execute a full two-party Diffie-Hellman key exchange."""
    p_int, g_int = validate_parameters(p, g)
    a_int = validate_private_key(a, p_int, "Alice private key (a)")
    b_int = validate_private_key(b, p_int, "Bob private key (b)")

    alice_public = pow(g_int, a_int, p_int)
    bob_public = pow(g_int, b_int, p_int)

    validate_public_key(alice_public, p_int, "Alice public key (A)")
    validate_public_key(bob_public, p_int, "Bob public key (B)")

    alice_secret = pow(bob_public, a_int, p_int)
    bob_secret = pow(alice_public, b_int, p_int)

    if alice_secret != bob_secret:
        raise DiffieHellmanError(
            "Shared secrets derived by Alice and Bob do not match."
        )

    return {
        "p": p_int,
        "g": g_int,
        "a": a_int,
        "b": b_int,
        "A": alice_public,
        "B": bob_public,
        "alice_secret": alice_secret,
        "bob_secret": bob_secret,
        "shared_secret": alice_secret,
    }
