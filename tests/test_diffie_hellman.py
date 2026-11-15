"""Unit tests for core Diffie-Hellman arithmetic, validation, and key derivation."""

import unittest

from dh_app.diffie_hellman import (
    DiffieHellmanError,
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
from dh_app.key_derivation import derive_hex_key, derive_key


class TestDiffieHellmanCore(unittest.TestCase):
    """Comprehensive verification of mathematical rules and input validation."""

    def test_validate_integer_accepts_int_and_rejects_bool_and_non_int(self):
        self.assertEqual(validate_integer(23, "p"), 23)
        with self.assertRaises(DiffieHellmanError):
            validate_integer(True, "p")
        with self.assertRaises(DiffieHellmanError):
            validate_integer(False, "p")
        with self.assertRaises(DiffieHellmanError):
            validate_integer(23.5, "p")
        with self.assertRaises(DiffieHellmanError):
            validate_integer("23", "p")

    def test_is_prime_valid_and_invalid(self):
        self.assertTrue(is_prime(2))
        self.assertTrue(is_prime(5))
        self.assertTrue(is_prime(23))
        self.assertTrue(is_prime(7919))
        self.assertFalse(is_prime(1))
        self.assertFalse(is_prime(0))
        self.assertFalse(is_prime(-7))
        self.assertFalse(is_prime(24))
        self.assertFalse(is_prime(True))
        self.assertFalse(is_prime("23"))

    def test_prime_factors(self):
        self.assertEqual(prime_factors(22), {2, 11})
        self.assertEqual(prime_factors(360), {2, 3, 5})
        with self.assertRaises(DiffieHellmanError):
            prime_factors(1)

    def test_is_generator(self):
        self.assertTrue(is_generator(5, 23))
        self.assertTrue(is_generator(7, 23))
        self.assertFalse(is_generator(4, 23))
        self.assertFalse(is_generator(1, 23))
        self.assertFalse(is_generator(22, 23))
        self.assertFalse(is_generator(5, 24))
        self.assertFalse(is_generator(True, 23))

    def test_validate_parameters_rejects_invalid_inputs(self):
        self.assertEqual(validate_parameters(23, 5), (23, 5))
        with self.assertRaises(DiffieHellmanError):
            validate_parameters(3, 2)  # p < 5
        with self.assertRaises(DiffieHellmanError):
            validate_parameters(24, 5)  # composite p
        with self.assertRaises(DiffieHellmanError):
            validate_parameters(23, 4)  # non-generator g
        with self.assertRaises(DiffieHellmanError):
            validate_parameters(True, 5)  # boolean p

    def test_validate_private_and_public_keys(self):
        self.assertEqual(validate_private_key(6, 23), 6)
        with self.assertRaises(DiffieHellmanError):
            validate_private_key(1, 23)
        with self.assertRaises(DiffieHellmanError):
            validate_private_key(22, 23)
        with self.assertRaises(DiffieHellmanError):
            validate_private_key(True, 23)

        self.assertEqual(validate_public_key(8, 23), 8)
        with self.assertRaises(DiffieHellmanError):
            validate_public_key(0, 23)
        with self.assertRaises(DiffieHellmanError):
            validate_public_key(1, 23)
        self.assertEqual(validate_public_key(22, 23), 22)  # allowed in the full-group model
        with self.assertRaises(DiffieHellmanError):
            validate_public_key(23, 23)  # outside the field
        with self.assertRaises(DiffieHellmanError):
            validate_public_key(False, 23)

    def test_generate_private_key_range_and_validation(self):
        for _ in range(25):
            key = generate_private_key(23)
            self.assertGreaterEqual(key, 2)
            self.assertLessEqual(key, 21)

        with self.assertRaises(DiffieHellmanError):
            generate_private_key(24)
        with self.assertRaises(DiffieHellmanError):
            generate_private_key(3)
        with self.assertRaises(DiffieHellmanError):
            generate_private_key(True)

    def test_modular_exponentiation_steps(self):
        val, steps = modular_exponentiation_steps(5, 6, 23)
        self.assertEqual(val, pow(5, 6, 23))
        self.assertEqual(val, 8)
        self.assertEqual(len(steps), 3)  # 6 in binary is 110 (3 bits)
        self.assertEqual(steps[-1].result_after, 8)

        zero_val, zero_steps = modular_exponentiation_steps(5, 0, 23)
        self.assertEqual(zero_val, 1)
        self.assertEqual(len(zero_steps), 1)

        with self.assertRaises(DiffieHellmanError):
            modular_exponentiation_steps(5, -1, 23)
        with self.assertRaises(DiffieHellmanError):
            modular_exponentiation_steps(5, 6, 1)

    def test_modular_exponentiation_matches_builtin_across_edges(self):
        for base in (-7, 0, 1, 5, 23):
            for exponent in (0, 1, 2, 7, 16):
                for modulus in (2, 5, 23, 97):
                    actual, _ = modular_exponentiation_steps(base, exponent, modulus)
                    self.assertEqual(actual, pow(base, exponent, modulus))

    def test_successful_key_exchange(self):
        result = calculate_exchange(23, 5, 6, 15)
        self.assertEqual(result["A"], 8)
        self.assertEqual(result["B"], 19)
        self.assertEqual(result["alice_secret"], 2)
        self.assertEqual(result["bob_secret"], 2)
        self.assertEqual(result["shared_secret"], 2)

    def test_key_exchange_rejects_invalid_inputs(self):
        with self.assertRaises(DiffieHellmanError):
            calculate_exchange(24, 5, 6, 15)
        with self.assertRaises(DiffieHellmanError):
            calculate_exchange(23, 4, 6, 15)
        with self.assertRaises(DiffieHellmanError):
            calculate_exchange(23, 5, 1, 15)
        with self.assertRaises(DiffieHellmanError):
            calculate_exchange(23, 5, 6, 22)
        with self.assertRaises(DiffieHellmanError):
            calculate_exchange(23, 5, True, 15)

    def test_smallest_supported_prime_exchange(self):
        result = calculate_exchange(5, 2, 2, 3)
        self.assertEqual(result["alice_secret"], result["bob_secret"])

    def test_key_derivation(self):
        hex_key = derive_hex_key(2, byte_length=16)
        self.assertEqual(len(hex_key), 32)
        key = derive_key(2, salt=b"salt", info=b"test", byte_length=32)
        self.assertEqual(len(key), 32)
        self.assertEqual(key, derive_key(2, salt=b"salt", info=b"test", byte_length=32))
        self.assertNotEqual(key, derive_key(2, salt=b"other", info=b"test", byte_length=32))
        self.assertNotEqual(key, derive_key(2, salt=b"salt", info=b"other", byte_length=32))
        with self.assertRaises(DiffieHellmanError):
            derive_hex_key(-1)
        with self.assertRaises(DiffieHellmanError):
            derive_key(2, byte_length=8161)
        with self.assertRaises(DiffieHellmanError):
            derive_key(2, salt="not bytes")


if __name__ == "__main__":
    unittest.main()
