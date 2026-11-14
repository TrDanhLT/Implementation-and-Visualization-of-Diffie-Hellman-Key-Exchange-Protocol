"""Cryptographic attack demonstrations: Man-in-the-Middle (MITM) and Brute-Force DLP."""

import time
from typing import Any, Callable, Optional, TypedDict

from dh_app.diffie_hellman import (
    DiffieHellmanError,
    validate_integer,
    validate_parameters,
    validate_private_key,
    validate_public_key,
)


class MITMResult(TypedDict):
    """Structured output for a Man-in-the-Middle simulation."""

    p: int
    g: int
    a: int
    b: int
    eve_a: int
    eve_b: int
    alice_original_public: int
    bob_original_public: int
    eve_public_to_bob: int
    eve_public_to_alice: int
    alice_shared_secret: int
    eve_secret_with_alice: int
    bob_shared_secret: int
    eve_secret_with_bob: int
    alice_eve_match: bool
    bob_eve_match: bool
    attack_succeeded: bool


class BruteForceResult(TypedDict):
    """Structured output for an exhaustive discrete logarithm search."""

    p: int
    g: int
    target_public_key: int
    max_attempts: int
    attempts: int
    elapsed_seconds: float
    found: bool
    recovered_private_key: Optional[int]
    limit_reached: bool


def simulate_mitm_attack(
    p: Any, g: Any, a: Any, b: Any, eve_a: Any, eve_b: Any
) -> MITMResult:
    """Simulate an active Man-in-the-Middle (MITM) key-substitution attack by Eve.

    Flow:
    1. Alice computes A = g^a mod p and transmits A toward Bob.
    2. Eve intercepts A, generates her own keypair (eve_a, E_A = g^eve_a mod p),
       and forwards E_A to Bob in place of A.
    3. Bob computes B = g^b mod p and transmits B toward Alice.
    4. Eve intercepts B, generates a second keypair (eve_b, E_B = g^eve_b mod p),
       and forwards E_B to Alice in place of B.
    5. Alice computes S_AE = (E_B)^a mod p; Eve computes S_EA = A^(eve_b) mod p.
    6. Bob computes S_BE = (E_A)^b mod p; Eve computes S_EB = B^(eve_a) mod p.
    """
    p_int, g_int = validate_parameters(p, g)
    a_int = validate_private_key(a, p_int, "Alice private key (a)")
    b_int = validate_private_key(b, p_int, "Bob private key (b)")
    eve_a_int = validate_private_key(
        eve_a, p_int, "Eve private key toward Bob (eve_a)"
    )
    eve_b_int = validate_private_key(
        eve_b, p_int, "Eve private key toward Alice (eve_b)"
    )

    alice_public = pow(g_int, a_int, p_int)
    bob_public = pow(g_int, b_int, p_int)

    # Eve's forged public keys sent to Bob and Alice respectively
    eve_public_to_bob = pow(g_int, eve_a_int, p_int)
    eve_public_to_alice = pow(g_int, eve_b_int, p_int)

    validate_public_key(alice_public, p_int, "Alice public key (A)")
    validate_public_key(bob_public, p_int, "Bob public key (B)")
    validate_public_key(eve_public_to_bob, p_int, "Eve forged key to Bob")
    validate_public_key(eve_public_to_alice, p_int, "Eve forged key to Alice")

    # Independent shared secrets established with Eve
    alice_shared_secret = pow(eve_public_to_alice, a_int, p_int)
    eve_secret_with_alice = pow(alice_public, eve_b_int, p_int)

    bob_shared_secret = pow(eve_public_to_bob, b_int, p_int)
    eve_secret_with_bob = pow(bob_public, eve_a_int, p_int)

    alice_eve_match = alice_shared_secret == eve_secret_with_alice
    bob_eve_match = bob_shared_secret == eve_secret_with_bob

    return {
        "p": p_int,
        "g": g_int,
        "a": a_int,
        "b": b_int,
        "eve_a": eve_a_int,
        "eve_b": eve_b_int,
        "alice_original_public": alice_public,
        "bob_original_public": bob_public,
        "eve_public_to_bob": eve_public_to_bob,
        "eve_public_to_alice": eve_public_to_alice,
        "alice_shared_secret": alice_shared_secret,
        "eve_secret_with_alice": eve_secret_with_alice,
        "bob_shared_secret": bob_shared_secret,
        "eve_secret_with_bob": eve_secret_with_bob,
        "alice_eve_match": alice_eve_match,
        "bob_eve_match": bob_eve_match,
        "attack_succeeded": alice_eve_match and bob_eve_match,
    }


def brute_force_discrete_log(
    p: Any,
    g: Any,
    target_public_key: Any,
    max_attempts: int = 50_000,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> BruteForceResult:
    """Attempt to recover x in [2, p - 2] such that g^x mod p == target_public_key.

    This is an educational exhaustive search (O(p) time complexity) intended solely
    to illustrate why small parameters are insecure. It is not a modern discrete-log
    attack benchmark (such as Baby-Step Giant-Step, Pollard's rho, or Number Field Sieve).
    """
    p_int, g_int = validate_parameters(p, g)
    target_int = validate_public_key(
        target_public_key, p_int, "Target public key"
    )
    max_att_int = validate_integer(max_attempts, "max_attempts")
    if max_att_int < 1:
        raise DiffieHellmanError("max_attempts must be at least 1.")

    search_upper = p_int - 2
    total_candidates = max(1, search_upper - 1)
    effective_limit = min(total_candidates, max_att_int)

    start_time = time.perf_counter()
    attempts = 0
    recovered: Optional[int] = None
    limit_reached = False

    # Incremental multiplication avoids recomputing pow() from scratch on every step
    current_value = (g_int * g_int) % p_int  # g^2 mod p
    for candidate in range(2, search_upper + 1):
        attempts += 1
        if current_value == target_int:
            recovered = candidate
            break

        if attempts >= max_att_int:
            limit_reached = candidate < search_upper
            break

        if progress_callback is not None and (
            attempts % 250 == 0 or attempts == effective_limit
        ):
            progress_callback(attempts, effective_limit)

        current_value = (current_value * g_int) % p_int

    elapsed = time.perf_counter() - start_time
    if progress_callback is not None:
        progress_callback(attempts, effective_limit)

    return {
        "p": p_int,
        "g": g_int,
        "target_public_key": target_int,
        "max_attempts": max_att_int,
        "attempts": attempts,
        "elapsed_seconds": elapsed,
        "found": recovered is not None,
        "recovered_private_key": recovered,
        "limit_reached": limit_reached,
    }
