"""Educational Discrete Logarithm exhaustive search (brute-force) demonstration."""

from typing import Optional
import streamlit as st

from dh_app.attacks import brute_force_discrete_log
from dh_app.diffie_hellman import DiffieHellmanError, ExchangeResult


def render_brute_force(result: Optional[ExchangeResult]) -> None:
    """Render the discrete logarithm brute-force demonstration page."""
    st.header("Discrete Logarithm Brute-Force Demonstration")
    st.write(
        "An eavesdropper (Eve) observes the public modulus p, generator g, and Alice's public "
        "key A = g^a mod p. Recovering the exponent a from A is the Discrete Logarithm Problem (DLP)."
    )

    if result is None:
        st.warning("Configure valid parameters above to run the brute-force demonstration.")
        return

    p, g, a, A = result["p"], result["g"], result["a"], result["A"]

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Public Modulus (p)", p)
    c2.metric("Generator (g)", g)
    c3.metric("Target Public Key (A)", A)
    c4.metric("Search Space [2, p - 2]", max(1, p - 3))

    max_attempts = st.slider(
        "Safety cap on candidate attempts",
        min_value=100,
        max_value=100_000,
        value=min(50_000, max(100, p)),
        step=100,
        help="Prevents UI freezes when experimenting with larger prime moduli.",
    )

    if p > 100_000:
        st.warning(
            f"p = {p:,} exceeds the interactive search cap of 100,000 candidates. "
            "Only the first 100,000 exponents will be tested."
        )

    if st.button("Run Exhaustive Search", type="primary"):
        progress_bar = st.progress(0.0)
        status_text = st.empty()

        def on_progress(done: int, total: int) -> None:
            ratio = min(1.0, done / max(1, total))
            progress_bar.progress(ratio)
            status_text.caption(f"Testing candidates: {done:,} / {total:,}")

        try:
            bf = brute_force_discrete_log(
                p=p,
                g=g,
                target_public_key=A,
                max_attempts=int(max_attempts),
                progress_callback=on_progress,
            )
        except DiffieHellmanError as exc:
            st.error(str(exc))
            return

        progress_bar.progress(1.0)
        status_text.empty()

        r1, r2, r3 = st.columns(3)
        r1.metric("Attempts Tested", f"{bf['attempts']:,}")
        r2.metric("Elapsed Time", f"{bf['elapsed_seconds'] * 1000:.3f} ms")
        r3.metric(
            "Recovered Exponent",
            str(bf["recovered_private_key"]) if bf["found"] else "Not Found",
        )

        if bf["found"]:
            st.success(
                f"Recovered exponent x = {bf['recovered_private_key']} in {bf['attempts']:,} "
                f"attempts ({bf['elapsed_seconds'] * 1000:.3f} ms)."
            )
            if bf["recovered_private_key"] == a:
                st.info(
                    f"Exact match: recovered x = {bf['recovered_private_key']} equals Alice's "
                    f"private key a = {a}."
                )
        elif bf["limit_reached"]:
            st.warning(
                f"Stopped after reaching the safety limit of {bf['max_attempts']:,} attempts "
                f"without finding a match. Increase the limit or choose a smaller prime p."
            )
        else:
            st.warning("No matching exponent was found in [2, p - 2].")

    st.divider()
    st.subheader("Why Parameter Size Matters")
    st.markdown(
        """
        - **Naive Exhaustive Search Complexity:** Testing every exponent in `[2, p - 2]` takes up to $O(p)$ modular multiplications, which grows exponentially with the bit length $n = \lceil \log_2 p \rceil$ as $O(2^n)$.
        - **Educational Scope Notice:** This loop is a naive linear search meant to visualize small-group weakness. It is **not** a modern cryptanalytic benchmark (such as Baby-Step Giant-Step in $O(\sqrt{p})$, Pollard's rho, or the General Number Field Sieve).
        - **Real-World Security:** Standard Diffie-Hellman groups use 2048-bit to 3072-bit safe primes ($p \approx 2^{2048}$), making exhaustive search physically impossible.
        """
    )
