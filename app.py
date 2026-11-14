"""Streamlit entry point for the Diffie-Hellman Key Exchange Visualization Project."""

import os
import streamlit as st

from dh_app.diffie_hellman import (
    DiffieHellmanError,
    calculate_exchange,
    generate_private_key,
    is_prime,
)
from pages.brute_force import render_brute_force
from pages.dashboard import render_dashboard
from pages.flowchart import render_flowchart
from pages.key_exchange import render_key_exchange
from pages.mitm_attack import render_mitm_attack
from pages.testing import render_testing

# Page configuration must be the first Streamlit command
st.set_page_config(
    page_title="Diffie-Hellman Key Exchange Simulator",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

NAV_PAGES = [
    "Dashboard",
    "Key Exchange",
    "MITM Attack",
    "Brute Force",
    "Protocol Flowchart",
    "Testing",
]


def _load_custom_css() -> None:
    """Inject external stylesheet from styles/custom.css."""
    css_path = os.path.join(os.path.dirname(__file__), "styles", "custom.css")
    if os.path.exists(css_path):
        with open(css_path, "r", encoding="utf-8") as css_file:
            st.markdown(f"<style>{css_file.read()}</style>", unsafe_allow_html=True)


def _generate_random_keys() -> None:
    """Callback to populate cryptographically random private keys in [2, p - 2]."""
    p_value = int(st.session_state.parameter_p)
    if is_prime(p_value) and p_value >= 5:
        st.session_state.alice_private_input = generate_private_key(p_value)
        st.session_state.bob_private_input = generate_private_key(p_value)
        st.session_state.random_key_error = None
    else:
        st.session_state.random_key_error = (
            "Enter a valid prime number p >= 5 before generating private keys."
        )


def main() -> None:
    """Render shared layout, parameter controls, and selected page module."""
    _load_custom_css()

    if "nav_page" not in st.session_state:
        st.session_state.nav_page = "Dashboard"
    if "alice_private_input" not in st.session_state:
        st.session_state.alice_private_input = 6
    if "bob_private_input" not in st.session_state:
        st.session_state.bob_private_input = 15

    # Sidebar Navigation
    st.sidebar.title("DH Key Exchange")
    st.sidebar.caption("University Cryptography Simulator")
    st.sidebar.divider()

    selected_page = st.sidebar.radio(
        "Navigation",
        options=NAV_PAGES,
        key="nav_page",
    )

    st.sidebar.divider()
    st.sidebar.info(
        "Educational Note: Small primes are used so calculations remain transparent. "
        "Production systems require 2048-bit+ safe primes or elliptic curves with authentication."
    )

    # Header
    st.title("Diffie-Hellman Key Exchange Protocol Simulator")
    st.caption(
        "Interactive visualization of modular exponentiation, key agreement, Man-in-the-Middle "
        "attacks, and discrete logarithm complexity."
    )

    # Shared Configuration Panel
    with st.container(border=True):
        st.subheader("Simulation Parameters")
        st.caption(
            "Configure the public group (p, g) and secret exponents (a, b). "
            "All pages dynamically reflect these values."
        )

        col_p, col_g, col_a, col_b = st.columns(4)
        with col_p:
            p = st.number_input(
                "Prime modulus (p)",
                min_value=5,
                max_value=1_000_000,
                value=23,
                step=1,
                key="parameter_p",
                help="A prime integer >= 5 defining the finite field Z_p.",
            )
        with col_g:
            g = st.number_input(
                "Generator (g)",
                min_value=2,
                max_value=999_999,
                value=5,
                step=1,
                key="parameter_g",
                help="A primitive root modulo p (generates all non-zero residues mod p).",
            )
        with col_a:
            a = st.number_input(
                "Alice private key (a)",
                min_value=2,
                max_value=999_999,
                step=1,
                key="alice_private_input",
                help="Alice's secret exponent in [2, p - 2].",
            )
        with col_b:
            b = st.number_input(
                "Bob private key (b)",
                min_value=2,
                max_value=999_999,
                step=1,
                key="bob_private_input",
                help="Bob's secret exponent in [2, p - 2].",
            )

        btn_col, preset_col, disclaimer_col = st.columns([1.2, 1.3, 2.5])
        with btn_col:
            st.button(
                "Generate Random Keys",
                use_container_width=True,
                on_click=_generate_random_keys,
            )
        with preset_col:
            if st.button("Reset Classic Example (p=23, g=5)", use_container_width=True):
                st.session_state.parameter_p = 23
                st.session_state.parameter_g = 5
                st.session_state.alice_private_input = 6
                st.session_state.bob_private_input = 15
                st.session_state.random_key_error = None
                st.rerun()
        with disclaimer_col:
            st.caption(
                "Educational simulator only: small integer parameters provide zero real-world "
                "cryptographic security."
            )

        if st.session_state.get("random_key_error"):
            st.error(st.session_state.random_key_error)
            st.session_state.random_key_error = None

    # Validate & compute shared exchange result
    result = None
    validation_error = None
    try:
        result = calculate_exchange(int(p), int(g), int(a), int(b))
    except (DiffieHellmanError, ValueError) as exc:
        validation_error = str(exc)

    if validation_error:
        st.error(f"Parameter Validation Error: {validation_error}")
        st.info(
            "Ensure p is a prime >= 5, g is a primitive root modulo p, and private keys "
            "a and b lie in [2, p - 2]."
        )

    # Page Routing
    if selected_page == "Dashboard":
        render_dashboard(result)
    elif selected_page == "Key Exchange":
        render_key_exchange(result)
    elif selected_page == "MITM Attack":
        render_mitm_attack(result)
    elif selected_page == "Brute Force":
        render_brute_force(result)
    elif selected_page == "Protocol Flowchart":
        render_flowchart(result)
    elif selected_page == "Testing":
        render_testing()

    st.divider()
    st.caption(
        "Implementation and Visualization of Diffie-Hellman Key Exchange Protocol | "
        "Educational Use Only"
    )


if __name__ == "__main__":
    main()
