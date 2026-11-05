
import secrets


class DiffieHellmanError(ValueError):
    """Error for invalid Diffie-Hellman parameters."""


def is_prime(n):
    """Check whether n is a prime number."""

    if n < 2:
        return False

    if n == 2:
        return True

    if n % 2 == 0:
        return False

    for i in range(3, int(n ** 0.5) + 1, 2):
        if n % i == 0:
            return False

    return True


def prime_factors(n):
    """Return the unique prime factors of n."""

    factors = set()
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


def is_generator(g, p):
    """Check whether g is a primitive root modulo prime p."""

    if not is_prime(p):
        return False

    if not 1 < g < p:
        return False

    for factor in prime_factors(p - 1):
        if pow(g, (p - 1) // factor, p) == 1:
            return False

    return True


def generate_private_key(p):
    """Generate a cryptographically secure random private key."""

    if (
        not isinstance(p, int)
        or isinstance(p, bool)
        or not is_prime(p)
        or p < 5
    ):
        raise DiffieHellmanError(
            "p must be a prime number greater than or equal to 5."
        )

    return secrets.randbelow(p - 3) + 2


def calculate_exchange(p, g, a, b):
    """Perform the complete Diffie-Hellman exchange."""

    # 1. Validate prime modulus
    if not is_prime(p):
        raise DiffieHellmanError(
            "p must be a prime number."
        )

    # 2. Validate generator
    if not is_generator(g, p):
        raise DiffieHellmanError(
            "g must be a primitive root modulo p."
        )

    # 3. Validate private keys
    if not 2 <= a <= p - 2:
        raise DiffieHellmanError(
            "Invalid Alice private key."
        )

    if not 2 <= b <= p - 2:
        raise DiffieHellmanError(
            "Invalid Bob private key."
        )

    # 4. Calculate public keys
    A = pow(g, a, p)
    B = pow(g, b, p)

    # 5. Calculate shared secrets
    alice_secret = pow(B, a, p)
    bob_secret = pow(A, b, p)

    # 6. Verify shared secrets
    if alice_secret != bob_secret:
        raise DiffieHellmanError(
            "Shared secrets do not match."
        )

    return {
        "p": p,
        "g": g,
        "a": a,
        "b": b,
        "A": A,
        "B": B,
        "alice_secret": alice_secret,
        "bob_secret": bob_secret,
        "shared_secret": alice_secret
    }
