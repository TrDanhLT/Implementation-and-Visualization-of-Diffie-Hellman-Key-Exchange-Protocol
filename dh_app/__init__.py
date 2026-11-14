"""Core cryptographic and educational simulation modules for Diffie-Hellman."""

from dh_app.attacks import (
    BruteForceResult,
    MITMResult,
    brute_force_discrete_log,
    simulate_mitm_attack,
)
from dh_app.diffie_hellman import (
    DiffieHellmanError,
    ExchangeResult,
    ModularStep,
    calculate_exchange,
    generate_private_key,
    is_generator,
    is_prime,
    modular_exponentiation_steps,
    prime_factors,
    validate_integer,
    validate_parameters,
    validate_private_key,
    validate_public_key,
)
from dh_app.key_derivation import derive_hex_key

__all__ = [
    "DiffieHellmanError",
    "ExchangeResult",
    "ModularStep",
    "MITMResult",
    "BruteForceResult",
    "validate_integer",
    "is_prime",
    "prime_factors",
    "is_generator",
    "validate_parameters",
    "validate_private_key",
    "validate_public_key",
    "generate_private_key",
    "modular_exponentiation_steps",
    "calculate_exchange",
    "simulate_mitm_attack",
    "brute_force_discrete_log",
    "derive_hex_key",
]
