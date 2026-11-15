"""Unit tests for the discrete logarithm brute-force demonstration."""

import unittest

from dh_app.attacks import brute_force_discrete_log
from dh_app.diffie_hellman import DiffieHellmanError


class TestBruteForceDiscreteLog(unittest.TestCase):
    """Verify exhaustive search correctness, search caps, and validation."""

    def test_recovers_private_key(self):
        # 5^6 mod 23 = 8
        res = brute_force_discrete_log(p=23, g=5, target_public_key=8, max_attempts=100)
        self.assertTrue(res["found"])
        self.assertEqual(res["recovered_private_key"], 6)
        self.assertEqual(pow(5, res["recovered_private_key"], 23), 8)
        self.assertEqual(res["attempts"], 5)  # candidates 2, 3, 4, 5, 6
        self.assertFalse(res["limit_reached"])
        self.assertGreaterEqual(res["elapsed_seconds"], 0.0)

    def test_respects_max_attempts_limit(self):
        # 5^15 mod 23 = 19; cap at 5 attempts (candidates 2..6) cannot reach 15
        res = brute_force_discrete_log(p=23, g=5, target_public_key=19, max_attempts=5)
        self.assertFalse(res["found"])
        self.assertIsNone(res["recovered_private_key"])
        self.assertEqual(res["attempts"], 5)
        self.assertTrue(res["limit_reached"])

    def test_progress_callback_invoked(self):
        calls = []
        res = brute_force_discrete_log(
            p=23,
            g=5,
            target_public_key=8,
            max_attempts=100,
            progress_callback=lambda done, total: calls.append((done, total)),
        )
        self.assertTrue(res["found"])
        self.assertGreaterEqual(len(calls), 1)

    def test_rejects_invalid_inputs(self):
        with self.assertRaises(DiffieHellmanError):
            brute_force_discrete_log(p=24, g=5, target_public_key=8)
        with self.assertRaises(DiffieHellmanError):
            brute_force_discrete_log(p=23, g=5, target_public_key=1)
        with self.assertRaises(DiffieHellmanError):
            brute_force_discrete_log(p=23, g=5, target_public_key=8, max_attempts=0)
        with self.assertRaises(DiffieHellmanError):
            brute_force_discrete_log(p=23, g=5, target_public_key=True)


if __name__ == "__main__":
    unittest.main()
