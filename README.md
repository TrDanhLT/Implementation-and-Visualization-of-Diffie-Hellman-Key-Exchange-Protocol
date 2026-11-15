# Implementation and Visualization of Diffie-Hellman Key Exchange Protocol

An interactive Python and Streamlit educational simulator demonstrating the Diffie-Hellman Key Exchange protocol, binary modular exponentiation, active Man-in-the-Middle (MITM) key substitution attacks, and discrete logarithm exhaustive search.

---

## 1. Project Overview

The Diffie-Hellman Key Exchange protocol (1976) enables two parties—traditionally named **Alice** and **Bob**—to derive a shared secret over an insecure public communication channel without prior shared secrets.

This application separates the mathematical core from the Streamlit user interface so students and instructors can inspect clean cryptographic routines, run automated unit tests independently of the UI, and step visually through each stage of the protocol.

---

## 2. Features

- **Dashboard & Protocol Overview:** Introduces the protocol, summarizes educational objectives, previews the active simulation state and HKDF-SHA256 derived key material, and provides direct navigation to every module.
- **9-Stage Interactive Key Exchange Walkthrough:** Steps through public parameter agreement, private key selection, public key generation, public channel transmission, shared secret computation, and verification with `Previous Step`, `Next Step`, `Reset`, and stage-jump controls.
- **Square-and-Multiply Modular Exponentiation Explorer:** Breaks down $g^e \bmod p$ bit-by-bit (LSB to MSB) using the binary square-and-multiply algorithm on live simulation values or custom small integers.
- **Man-in-the-Middle (MITM) Attack Simulation:** Visualizes how an active attacker (**Eve**) intercepts and substitutes public keys on an unauthenticated channel to establish two independent shared secrets ($S_{AE}$ with Alice and $S_{BE}$ with Bob).
- **Discrete Logarithm Brute-Force Demonstration:** Measures candidate attempts and execution time for a naive $O(p)$ exhaustive search with a configurable safety limit and live progress bar.
- **Protocol Flowchart:** Renders an interactive Plotly sequence diagram clearly separating private values, public channel transmissions, and shared secrets.
- **Automated Unit Testing Suite:** Executes Python `unittest` suites covering parameter validation, key exchange, MITM attacks, and brute-force limits directly from the CLI or inside the Testing page.

---

## 3. Screenshots

Add application screenshots to `docs/screenshots/` after running locally:

- **Dashboard Overview:** `docs/screenshots/dashboard.png` — Displays protocol summary, live parameter metrics, and module cards.
- **9-Step Key Exchange & Square-and-Multiply:** `docs/screenshots/key_exchange.png` — Shows Alice, Public Channel, and Bob state panels alongside step-by-step modular exponentiation.
- **MITM Sequence Diagram:** `docs/screenshots/mitm_attack.png` — Illustrates Eve intercepting $A$ and $B$ and injecting forged public keys $E_A$ and $E_B$.
- **Protocol Flowchart:** `docs/screenshots/flowchart.png` — Displays the two-party sequence diagram with color-coded private and public values.

---

## 4. Requirements & Installation

### Prerequisites
- Python **3.10** or newer
- `pip` package manager

### Setup Instructions

1. Clone or extract the repository and enter the project directory:
   ```bash
   cd Implementation-and-Visualization-of-Diffie-Hellman-Key-Exchange-Protocol
   ```

2. Create and activate a virtual environment:
   ```bash
   # Linux / macOS
   python3 -m venv .venv
   source .venv/bin/activate

   # Windows (PowerShell)
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## 5. How to Run the Application

From the project root directory, launch Streamlit:

```bash
streamlit run app.py
```

Streamlit will start a local web server and open the simulator in your default browser (typically at `http://localhost:8501`).

---

## 6. How to Execute Unit Tests

All unit tests are independent of Streamlit and can be executed with a single command from the project root:

```bash
python3 -m unittest discover -s tests -v
```

---

## 7. Project Architecture

```text
Implementation-and-Visualization-of-Diffie-Hellman-Key-Exchange-Protocol/
├── app.py                     # Main Streamlit entry point, layout, and shared parameter bar
├── dh_app/                    # Pure Python cryptography and simulation engine (UI-independent)
│   ├── __init__.py
│   ├── diffie_hellman.py      # Prime/generator validation, CSPRNG keys, DH exchange, square-and-multiply
│   ├── attacks.py             # MITM simulation and bounded discrete-log exhaustive search
│   └── key_derivation.py      # HKDF-SHA256 key derivation helper
├── pages/                     # Modular Streamlit page views
│   ├── __init__.py
│   ├── dashboard.py           # Landing page, objectives, snapshot, and quick navigation
│   ├── key_exchange.py        # 9-stage interactive walkthrough & modular exponentiation explorer
│   ├── mitm_attack.py         # Active MITM sequence diagram and breakdown
│   ├── brute_force.py         # Exhaustive DLP search with progress indicator and safety cap
│   ├── flowchart.py           # Interactive Plotly protocol sequence diagram
│   └── testing.py             # Live unittest runner and test summary
├── styles/
│   └── custom.css             # Dark theme styling, semantic role badges, and responsive rules
├── tests/                     # Independent unittest suite
│   ├── __init__.py
│   ├── test_diffie_hellman.py # Core math, validation, boolean rejection, and KDF tests
│   ├── test_mitm.py           # MITM key-substitution and dual-secret tests
│   └── test_brute_force.py    # Brute-force recovery, search cap, and callback tests
├── requirements.txt           # Runtime dependencies (streamlit, plotly, cryptography)
├── .streamlit/config.toml     # Streamlit theme and server configuration
├── .gitignore
└── README.md
```

---

## 8. Cryptographic Concepts Explained

### Diffie-Hellman Key Exchange
1. **Public Parameters:** Alice and Bob agree on a prime modulus $p$ and primitive root $g$ modulo $p$. This teaching implementation models the full multiplicative group $\mathbb{Z}_p^*$.
2. **Private Keys:** Alice selects a random secret $a \in [2, p-2]$; Bob selects $b \in [2, p-2]$.
3. **Public Keys:** Alice computes $A = g^a \bmod p$ and Bob computes $B = g^b \bmod p$.
4. **Exchange & Shared Secret:** After exchanging $A$ and $B$ publicly, Alice computes $S_A = B^a \bmod p$ and Bob computes $S_B = A^b \bmod p$. Because $(g^b)^a \equiv (g^a)^b \equiv g^{ab} \pmod p$, both derive the same raw integer $S$.
5. **Key Derivation:** The raw DH integer is encoded as unsigned big-endian bytes and passed through HKDF-SHA256 with salt and `info` context to derive key material. This does not authenticate the exchange or make toy parameters safe.

### Man-in-the-Middle (MITM) Attack
Basic Diffie-Hellman does **not** authenticate the sender of $A$ or $B$. An active attacker (**Eve**) positioned between Alice and Bob can intercept $A$ and $B$, substitute her own public keys $E_A = g^{e_a} \bmod p$ and $E_B = g^{e_b} \bmod p$, and establish two separate shared secrets ($S_{AE}$ with Alice and $S_{BE}$ with Bob). Countermeasures include digital signatures, X.509 certificates (TLS), or pre-shared keys.

### Discrete Logarithm Brute Force
Recovering $a$ from $(p, g, A = g^a \bmod p)$ is the Discrete Logarithm Problem (DLP). This page uses a bounded naive search for small examples. Its $O(p)$ candidate count grows exponentially in bit length; it is not a meaningful attack on standardized groups.

---

## 9. Security Disclaimer & Limitations

- **Educational Purpose Only:** This software is built strictly for classroom instruction and self-study. Do **not** use this code or its small demonstration primes to protect real data.
- **Group Validation Scope:** The core verifies prime $p$, a primitive root $g$, private exponent ranges, and non-identity public field elements. It does not implement a prime-order subgroup or general small-subgroup defense.
- **MITM Scope:** The simulation computes Eve's two independent shared secrets. It does not implement message encryption, decryption, or tamper detection; those effects are explained conceptually only.
- **Key Derivation Scope:** HKDF-SHA256 is a standard KDF primitive provided by `cryptography`; a correct KDF does not replace authenticated key exchange, transcript binding, or production group selection.
- **Naive Brute-Force Loop:** The brute-force module implements a linear search ($O(p)$) for pedagogical clarity rather than sub-exponential cryptanalytic algorithms (such as Baby-Step Giant-Step, Pollard's rho, or the General Number Field Sieve).
- **No Network Transport:** All participants execute in local Python memory to visualize message flow without socket or TLS overhead.

---

## 10. Future Improvements

- Add an **Authenticated Diffie-Hellman (STS / Digital Signature)** mode demonstrating how signing public keys defeats MITM attacks.
- Add an **Elliptic-Curve Diffie-Hellman (ECDH)** module comparing finite-field parameters with elliptic-curve point multiplication.
- Export step-by-step protocol transcripts as JSON or Markdown reports for lab assignments.
