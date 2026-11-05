
import unittest

from dh_app.diffie_hellman import (
    is_prime,
    is_generator,
    calculate_exchange,
    generate_private_key,
    DiffieHellmanError,
)


class TestDiffieHellman(unittest.TestCase):

    def test_prime_number(self):
        self.assertTrue(is_prime(23))

    def test_non_prime_number(self):
        self.assertFalse(is_prime(24))

    def test_valid_generator(self):
        self.assertTrue(is_generator(5, 23))

    def test_invalid_generator(self):
        self.assertFalse(is_generator(4, 23))

    def test_successful_key_exchange(self):
        result = calculate_exchange(23, 5, 6, 15)
        self.assertEqual(result["alice_secret"], 2)
        self.assertEqual(result["bob_secret"], 2)
        self.assertEqual(result["shared_secret"], 2)

    def test_invalid_prime(self):
        with self.assertRaises(DiffieHellmanError):
            calculate_exchange(24, 5, 6, 15)

    def test_invalid_private_key(self):
        with self.assertRaises(DiffieHellmanError):
            calculate_exchange(23, 5, 1, 15)

    def test_generate_private_key(self):
        key = generate_private_key(23)
        self.assertGreaterEqual(key, 2)
        self.assertLessEqual(key, 21)

    def test_generate_private_key_rejects_non_prime(self):
        with self.assertRaises(DiffieHellmanError):
            generate_private_key(24)

if __name__ == "__main__":
    unittest.main()
