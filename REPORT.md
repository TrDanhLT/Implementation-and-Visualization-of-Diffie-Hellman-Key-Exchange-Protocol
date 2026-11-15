# Implementation and Visualization of Diffie-Hellman Key Exchange Protocol

## 1. Introduction

This project is an educational Streamlit application for exploring finite-field Diffie-Hellman (DH), modular exponentiation, unauthenticated key substitution, and the discrete logarithm problem. It is designed for classroom demonstrations, not for protecting real data.

## 2. Objectives and Scope

- Show how Alice and Bob derive a common value from public parameters and private exponents.
- Trace right-to-left Square-and-Multiply calculations.
- Demonstrate a bounded exhaustive discrete-log search on small examples.
- Show the two independent secrets created when Eve substitutes unauthenticated public keys.
- Distinguish a raw DH shared integer from key material derived with HKDF-SHA256.

The implementation retains the full multiplicative group modulo a prime, matching the existing interface and classic example. It does not claim prime-order subgroup security.

## 3. Cryptographic Background and Mathematical Principles

Let `p` be prime and `g` a primitive root modulo `p`. Alice chooses private `a` and sends `A = g^a mod p`; Bob chooses private `b` and sends `B = g^b mod p`. Each calculates `S = g^(ab) mod p` independently:

```text
Alice: B^a mod p = (g^b)^a mod p = g^(ab) mod p
Bob:   A^b mod p = (g^a)^b mod p = g^(ab) mod p
```

For the classic demonstration `p=23, g=5, a=6, b=15`:

```text
A = 5^6 mod 23 = 8
B = 5^15 mod 23 = 19
S_A = 19^6 mod 23 = 2
S_B = 8^15 mod 23 = 2
```

The shared integer is not itself an encryption protocol or an identity proof. Implementations normally feed the agreed secret into a KDF and bind the exchange to authentication and protocol context.

## 4. System Architecture

- `dh_app/diffie_hellman.py`: validation, secure random exponent generation, exchange calculations, Square-and-Multiply trace.
- `dh_app/key_derivation.py`: HKDF-SHA256 derivation using the `cryptography` package.
- `dh_app/attacks.py`: MITM arithmetic and bounded DLP exhaustive search.
- `app.py` and `pages/`: Streamlit routing, controls, educational walkthroughs, diagrams, and test runner.
- `tests/`: deterministic `unittest` checks for core operations and attack demonstrations.

## 5. Implementation Details and DH Demonstration

Inputs are checked for Python integer type (booleans are rejected), primality, primitive-root conditions, private exponent range, and public field-element range. `secrets.randbelow` is used to generate exponents. Python's three-argument `pow` computes modular powers efficiently. Calculations remain small and transparent for the application's intended examples.

Square-and-Multiply processes exponent bits from least significant to most significant. For each bit, it multiplies the accumulator by the current base when the bit is one, then squares the base modulo `p` for the next bit. The trace records the values used by the implementation. For `5^6 mod 23`, the binary exponent is `110₂` and the result is `8`.

## 6. MITM Attack Simulation

Eve replaces Alice's public value on its way to Bob and Bob's public value on its way to Alice. Alice then shares `S_AE` with Eve, and Bob shares `S_BE` with Eve. Eve computes matching copies of both values. Since the public-key exchange has no authentication, neither side can tell from the DH arithmetic alone that the peer key was replaced.

The current page simulates key agreement only. It does **not** implement message encryption, decryption, or tamper detection; any description of Eve reading or changing application messages is conceptual. Authentication (for example, signed key exchange in a standard protocol) is needed to prevent this attack.

## 7. Discrete Logarithm and Brute Force

Given `p`, `g`, and `A = g^a mod p`, the DLP asks for `a`. The demonstration tests candidate exponents by incremental modular multiplication, stopping at a configured attempt limit. It reports candidate count and `time.perf_counter` elapsed duration. This naive search is `O(p)` candidates in the full-group teaching model and is intended only for small values. The UI caps work to avoid long searches; it does not attempt attacks on production-size groups.

## 8. Key Derivation

The raw shared integer is encoded as unsigned big-endian bytes and passed to HKDF-SHA256. HKDF's salt and `info` inputs separate extraction and application-specific expansion context. The UI displays derived key material distinctly from the raw DH result. HKDF does not authenticate the peer or make weak DH parameters secure.

## 9. Testing and Results

Run the suite from the project root:

```bash
python3 -m unittest discover -s tests -v
```

At the time of this report, the modified suite contains 19 tests covering prime and parameter validation, key ranges, exchange equality, the smallest supported prime case, modular exponentiation across edge inputs, HKDF output/context, MITM secret equality, brute-force recovery, limits, and invalid inputs. The latest observed run passed all 19 tests. This is a unit-test count, not a formal coverage percentage.

## 10. Security Analysis and Limitations

- The core models the full group `Z_p*`, with a primitive root and small demonstration primes. It does not use a safe-prime subgroup or implement general small-subgroup defense.
- Trial division is suitable only for the current educational input range. It is not a production parameter validation method.
- DH is unauthenticated in this project and therefore vulnerable to active key substitution.
- The MITM simulation does not exercise an encrypted message channel.
- HKDF is a standard KDF primitive, but the overall application is not a production protocol.
- The exhaustive DLP search is deliberately naive and bounded.

## 11. Future Improvements

- Add a clearly separate safe-prime subgroup mode with order-`q` generator and public-key membership checks.
- Add a bounded authenticated-encryption message demonstration (for example AES-GCM) with explicit educational-only labeling.
- Add browser-based visual smoke tests and a reproducible screenshot set after installing UI dependencies.
- Consider standardized parameter handling and transcript-bound authenticated key exchange only as a separate, carefully scoped lesson.

## 12. Conclusion

The application provides an inspectable demonstration of full-group finite-field DH, modular exponentiation, key substitution, and the DLP. The revised materials distinguish raw secrets, KDF output, and authentication. Its small parameters and limited validation scope make it a teaching artifact only.

## References

- W. Diffie and M. E. Hellman, “New Directions in Cryptography,” *IEEE Transactions on Information Theory*, 1976.
- RFC 5869, “HMAC-based Extract-and-Expand Key Derivation Function (HKDF),” https://www.rfc-editor.org/rfc/rfc5869
- Python documentation, `secrets`: https://docs.python.org/3/library/secrets.html
- `cryptography` documentation, HKDF: https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#hkdf
