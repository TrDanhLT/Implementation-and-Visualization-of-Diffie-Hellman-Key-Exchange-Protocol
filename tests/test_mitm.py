"""Unit tests for the Man-in-the-Middle (MITM) attack simulation."""

import unittest

from dh_app.attacks import simulate_mitm_attack
from dh_app.diffie_hellman import DiffieHellmanError


class TestMITMAttack(unittest.TestCase):
    """Verify Eve's interception, key substitution, and independent shared secrets."""

    def test_mitm_establishes_two_separate_secrets(self):
        mitm = simulate_mitm_attack(p=23, g=5, a=6, b=15, eve_a=7, eve_b=9)
        self.assertTrue(mitm["attack_succeeded"])
        self.assertTrue(mitm["alice_eve_match"])
        self.assertTrue(mitm["bob_eve_match"])

        # Alice and Eve share S_AE = (g^9)^6 mod 23 = 11^6 mod 23 = 9
        self.assertEqual(mitm["alice_shared_secret"], pow(5, 6 * 9, 23))
        self.assertEqual(mitm["eve_secret_with_alice"], mitm["alice_shared_secret"])

        # Bob and Eve share S_BE = (g^7)^15 mod 23 = 17^15 mod 23 = 12
        self.assertEqual(mitm["bob_shared_secret"], pow(5, 15 * 7, 23))
        self.assertEqual(mitm["eve_secret_with_bob"], mitm["bob_shared_secret"])

        # Confirm Alice and Bob do not share the same secret
        self.assertNotEqual(mitm["alice_shared_secret"], mitm["bob_shared_secret"])

    def test_mitm_rejects_invalid_parameters(self):
        with self.assertRaises(DiffieHellmanError):
            simulate_mitm_attack(p=24, g=5, a=6, b=15, eve_a=7, eve_b=9)
        with self.assertRaises(DiffieHellmanError):
            simulate_mitm_attack(p=23, g=4, a=6, b=15, eve_a=7, eve_b=9)
        with self.assertRaises(DiffieHellmanError):
            simulate_mitm_attack(p=23, g=5, a=6, b=15, eve_a=1, eve_b=9)
        with self.assertRaises(DiffieHellmanError):
            simulate_mitm_attack(p=23, g=5, a=6, b=15, eve_a=7, eve_b=True)


if __name__ == "__main__":
    unittest.main()
