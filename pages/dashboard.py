"""Dashboard page: project introduction, protocol overview, status, and module navigation."""

from typing import Optional
import streamlit as st

from dh_app.diffie_hellman import ExchangeResult
from dh_app.key_derivation import derive_hex_key


def render_dashboard(result: Optional[ExchangeResult]) -> None:
    """Render the main Dashboard landing page."""
    st.header("Dashboard & Protocol Overview")
    st.write(
        "The Diffie-Hellman Key Exchange (1976) allows two participants—traditionally "
        "named Alice and Bob—to establish a shared secret over an insecure, eavesdropped "
        "communication channel without having met beforehand."
    )

    cta_col, note_col = st.columns([1.2, 2.8])
    with cta_col:
        if st.button("Start Simulation ->", type="primary", use_container_width=True):
            st.session_state.nav_page = "Key Exchange"
            st.session_state.step = 0
            st.rerun()
    with note_col:
        st.caption(
            "Launch the interactive 9-step walkthrough using the parameters configured above."
        )

    st.subheader("Educational Objectives")
    obj1, obj2, obj3 = st.columns(3)
    with obj1:
        st.markdown(
            """
            <div class="role-card role-public">
                <span class="badge badge-public">01 • Mathematics</span>
                <h4>Modular Arithmetic & Generators</h4>
                <p>Observe how prime moduli, primitive roots, and binary modular exponentiation
                create a one-way trapdoor function.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with obj2:
        st.markdown(
            """
            <div class="role-card role-alice">
                <span class="badge badge-alice">02 • Key Agreement</span>
                <h4>Step-by-Step Exchange</h4>
                <p>Trace Alice and Bob independently as they generate keypairs, exchange public
                values, and converge on the same secret.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with obj3:
        st.markdown(
            """
            <div class="role-card role-eve">
                <span class="badge badge-eve">03 • Threat Analysis</span>
                <h4>Attacks & Countermeasures</h4>
                <p>Analyze Man-in-the-Middle key substitution and Discrete Logarithm brute force
                to see why authentication and large primes are mandatory.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.divider()
    st.subheader("Current Simulation Snapshot")
    if result is not None:
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Prime Modulus (p)", result["p"])
        m2.metric("Generator (g)", result["g"])
        m3.metric("Public Keys (A, B)", f"{result['A']}, {result['B']}")
        m4.metric("Shared Secret (S)", result["shared_secret"])

        derived_hex = derive_hex_key(result["shared_secret"], byte_length=16)
        st.success(
            f"Valid parameters: Alice and Bob derive matching shared secret S = {result['shared_secret']} "
            f"(HKDF-SHA256 128-bit key-material preview: {derived_hex})."
        )
        st.caption(
            "The shared secret is raw DH output. HKDF derives key material from it; "
            "this preview is not an authenticated or production protocol key."
        )
    else:
        st.warning(
            "The current parameter configuration is invalid. Fix the inputs in the panel above "
            "to enable live protocol calculations."
        )

    st.divider()
    st.subheader("Simulator Modules")
    modules = [
        ("Key Exchange", "9-stage interactive walkthrough with participant cards, channel arrows, and square-and-multiply trace."),
        ("MITM Attack", "Active Man-in-the-Middle simulation showing Eve intercepting and replacing public keys."),
        ("Brute Force", "Exhaustive discrete logarithm search measuring attempts, elapsed time, and parameter growth."),
        ("Protocol Flowchart", "Interactive sequence diagram separating private state, public messages, and shared secrets."),
        ("Testing", "Live unit-test suite runner executing the project's independent unittest verification suite."),
    ]

    nav_cols = st.columns(len(modules))
    for idx, (mod_name, mod_desc) in enumerate(modules):
        with nav_cols[idx]:
            with st.container(border=True):
                st.markdown(f"**{mod_name}**")
                st.caption(mod_desc)
                if st.button(f"Open {mod_name}", key=f"dash_nav_{mod_name}", use_container_width=True):
                    st.session_state.nav_page = mod_name
                    st.rerun()

    st.warning(
        "Security Disclaimer: This application is an educational simulator designed for small "
        "demonstration integers. Real-world cryptography requires standardized 2048-bit+ safe primes "
        "or elliptic curves (such as X25519) paired with authenticated key exchange (e.g., TLS 1.3)."
    )
