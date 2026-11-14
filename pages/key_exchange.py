"""Interactive 9-step Diffie-Hellman Key Exchange & Modular Exponentiation page."""

from typing import Optional
import streamlit as st

from dh_app.diffie_hellman import (
    DiffieHellmanError,
    ExchangeResult,
    modular_exponentiation_steps,
)
from dh_app.key_derivation import derive_hex_key

STAGES = [
    "1. Public Parameters",
    "2. Alice's Private Key",
    "3. Bob's Private Key",
    "4. Alice's Public Key",
    "5. Bob's Public Key",
    "6. Public Key Exchange",
    "7. Alice's Shared Secret",
    "8. Bob's Shared Secret",
    "9. Verification & KDF",
]


def _render_participant_panels(result: ExchangeResult, step: int) -> None:
    """Render side-by-side Alice, Public Channel, and Bob state cards for the current step."""
    p, g, a, b = result["p"], result["g"], result["a"], result["b"]
    A, B = result["A"], result["B"]
    s_a, s_b = result["alice_secret"], result["bob_secret"]

    alice_col, channel_col, bob_col = st.columns([1.2, 1.0, 1.2])

    with alice_col:
        alice_lines = [f"<p><strong>Public Parameters:</strong> p = {p}, g = {g}</p>"]
        if step >= 1:
            alice_lines.append(
                f"<p><span class='badge badge-secret'>Private</span> <strong>a = {a}</strong> (kept secret)</p>"
            )
        if step >= 3:
            alice_lines.append(
                f"<p><span class='badge badge-public'>Public</span> <strong>A = {g}<sup>{a}</sup> mod {p} = {A}</strong></p>"
            )
        if step >= 5:
            alice_lines.append(
                f"<p><strong>Received from Bob:</strong> B = {B}</p>"
            )
        if step >= 6:
            alice_lines.append(
                f"<p><span class='badge badge-secret'>Shared Secret</span> <strong>S<sub>A</sub> = {B}<sup>{a}</sup> mod {p} = {s_a}</strong></p>"
            )

        st.markdown(
            f"""
            <div class="role-card role-alice">
                <span class="badge badge-alice">Participant: Alice</span>
                <h4>Alice's Local State</h4>
                {''.join(alice_lines)}
            </div>
            """,
            unsafe_allow_html=True,
        )

    with channel_col:
        channel_items = [
            f"<div class='channel-arrow'>PUBLIC PARAMETERS<br>p = {p}, g = {g}</div>"
        ]
        if step >= 5:
            channel_items.append(
                f"<div class='channel-arrow'>Alice ------ A = {A} ------&gt; Bob</div>"
            )
            channel_items.append(
                f"<div class='channel-arrow'>Alice &lt;----- B = {B} ------ Bob</div>"
            )
        else:
            channel_items.append(
                "<p style='text-align:center;color:#9aabc2;font-size:0.88rem;'>"
                "No public keys transmitted yet.</p>"
            )
        channel_items.append(
            "<p style='text-align:center;color:#9aabc2;font-size:0.8rem;margin-top:0.5rem;'>"
            "Private keys (a, b) never enter the network channel.</p>"
        )

        st.markdown(
            f"""
            <div class="role-card role-public">
                <span class="badge badge-public">Insecure Public Network</span>
                <h4>Transmitted Messages</h4>
                {''.join(channel_items)}
            </div>
            """,
            unsafe_allow_html=True,
        )

    with bob_col:
        bob_lines = [f"<p><strong>Public Parameters:</strong> p = {p}, g = {g}</p>"]
        if step >= 2:
            bob_lines.append(
                f"<p><span class='badge badge-secret'>Private</span> <strong>b = {b}</strong> (kept secret)</p>"
            )
        if step >= 4:
            bob_lines.append(
                f"<p><span class='badge badge-public'>Public</span> <strong>B = {g}<sup>{b}</sup> mod {p} = {B}</strong></p>"
            )
        if step >= 5:
            bob_lines.append(
                f"<p><strong>Received from Alice:</strong> A = {A}</p>"
            )
        if step >= 7:
            bob_lines.append(
                f"<p><span class='badge badge-secret'>Shared Secret</span> <strong>S<sub>B</sub> = {A}<sup>{b}</sup> mod {p} = {s_b}</strong></p>"
            )

        st.markdown(
            f"""
            <div class="role-card role-bob">
                <span class="badge badge-bob">Participant: Bob</span>
                <h4>Bob's Local State</h4>
                {''.join(bob_lines)}
            </div>
            """,
            unsafe_allow_html=True,
        )


def _render_modular_exponentiation_explorer(result: ExchangeResult) -> None:
    """Interactive Square-and-Multiply modular exponentiation walkthrough."""
    st.subheader("Modular Exponentiation Explorer (Square-and-Multiply)")
    st.write(
        "Diffie-Hellman relies on modular exponentiation g^e mod p. Instead of computing a huge "
        "power g^e first, computers use the binary Square-and-Multiply algorithm to keep every "
        "intermediate number smaller than p^2."
    )

    preset_col, base_col, exp_col, mod_col = st.columns([1.4, 1, 1, 1])
    with preset_col:
        preset = st.selectbox(
            "Load value from simulation",
            [
                "Alice Public Key (g^a mod p)",
                "Bob Public Key (g^b mod p)",
                "Alice Shared Secret (B^a mod p)",
                "Bob Shared Secret (A^b mod p)",
                "Custom small integers",
            ],
            key="modexp_preset",
        )

    if preset == "Alice Public Key (g^a mod p)":
        default_base, default_exp, default_mod = result["g"], result["a"], result["p"]
    elif preset == "Bob Public Key (g^b mod p)":
        default_base, default_exp, default_mod = result["g"], result["b"], result["p"]
    elif preset == "Alice Shared Secret (B^a mod p)":
        default_base, default_exp, default_mod = result["B"], result["a"], result["p"]
    elif preset == "Bob Shared Secret (A^b mod p)":
        default_base, default_exp, default_mod = result["A"], result["b"], result["p"]
    else:
        default_base, default_exp, default_mod = 5, 6, 23

    disabled_inputs = preset != "Custom small integers"

    with base_col:
        base_val = st.number_input(
            "Base",
            min_value=1,
            max_value=1_000_000,
            value=int(default_base),
            step=1,
            disabled=disabled_inputs,
            key=f"modexp_base_{preset}",
        )
    with exp_col:
        exp_val = st.number_input(
            "Exponent",
            min_value=0,
            max_value=1_000_000,
            value=int(default_exp),
            step=1,
            disabled=disabled_inputs,
            key=f"modexp_exp_{preset}",
        )
    with mod_col:
        mod_val = st.number_input(
            "Modulus (p)",
            min_value=2,
            max_value=1_000_000,
            value=int(default_mod),
            step=1,
            disabled=disabled_inputs,
            key=f"modexp_mod_{preset}",
        )

    try:
        final_val, steps = modular_exponentiation_steps(
            int(base_val), int(exp_val), int(mod_val)
        )
        binary_repr = bin(int(exp_val))[2:]
        st.latex(
            rf"{int(base_val)}^{{{int(exp_val)}}} \bmod {int(mod_val)} = {final_val}"
            rf"\quad (\text{{exponent in binary: }} {binary_repr}_2)"
        )

        table_rows = [
            {
                "Step (LSB -> MSB)": s.step_index,
                "Exponent Bit": s.bit,
                "Current Base": s.base_before,
                "Result Before": s.result_before,
                "Action": "Multiply & Square" if s.multiplied else "Square Only",
                "Result After": s.result_after,
                "Next Base": s.base_after,
            }
            for s in steps
        ]
        st.dataframe(table_rows, use_container_width=True, hide_index=True)

        with st.expander("Detailed step-by-step trace"):
            for s in steps:
                st.markdown(f"**Step {s.step_index} (bit = {s.bit}):** {s.explanation}")
    except DiffieHellmanError as exc:
        st.error(str(exc))


def render_key_exchange(result: Optional[ExchangeResult]) -> None:
    """Render the 9-stage interactive Diffie-Hellman key exchange walkthrough."""
    st.header("Interactive Diffie-Hellman Key Exchange")
    st.write(
        "Step through all nine protocol stages to observe how Alice and Bob construct "
        "an identical shared secret over a public channel."
    )

    if result is None:
        st.warning("Configure valid parameters above to run the key exchange simulation.")
        return

    if "step" not in st.session_state:
        st.session_state.step = 0

    step = max(0, min(st.session_state.step, len(STAGES) - 1))
    st.session_state.step = step

    st.progress((step + 1) / len(STAGES))
    st.caption(f"Stage {step + 1} of {len(STAGES)} — {STAGES[step]}")

    # Navigation controls
    prev_col, reset_col, jump_col, next_col = st.columns([1, 1, 2, 1])
    with prev_col:
        if st.button("<- Previous Step", disabled=(step == 0), use_container_width=True):
            st.session_state.step -= 1
            st.rerun()
    with reset_col:
        if st.button("Reset", use_container_width=True):
            st.session_state.step = 0
            st.rerun()
    with jump_col:
        selected_stage = st.selectbox(
            "Jump to stage",
            options=list(range(len(STAGES))),
            index=step,
            format_func=lambda idx: STAGES[idx],
            label_visibility="collapsed",
        )
        if selected_stage != step:
            st.session_state.step = selected_stage
            st.rerun()
    with next_col:
        if st.button("Next Step ->", disabled=(step == len(STAGES) - 1), use_container_width=True):
            st.session_state.step += 1
            st.rerun()

    st.divider()

    p, g, a, b = result["p"], result["g"], result["a"], result["b"]
    A, B = result["A"], result["B"]
    s_a, s_b = result["alice_secret"], result["bob_secret"]

    # Stage-specific mathematical explanation
    if step == 0:
        st.subheader("Stage 1: Agree on Public Parameters (p, g)")
        st.write(
            "Alice and Bob publicly agree on a prime modulus p and a generator g. "
            "An eavesdropper (Eve) is allowed to know both numbers."
        )
        st.latex(rf"p = {p} \text{{ (prime modulus)}}, \quad g = {g} \text{{ (primitive root mod }} {p}\text{{)}}")
    elif step == 1:
        st.subheader("Stage 2: Alice Selects Her Private Key (a)")
        st.write(
            "Alice chooses a secret integer a in the range [2, p - 2]. She stores it locally "
            "and never transmits it over the network."
        )
        st.latex(rf"a = {a} \in [2, {p - 2}]")
    elif step == 2:
        st.subheader("Stage 3: Bob Selects His Private Key (b)")
        st.write(
            "Independently, Bob chooses his own secret integer b in the range [2, p - 2]. "
            "Alice does not know b, and Bob does not know a."
        )
        st.latex(rf"b = {b} \in [2, {p - 2}]")
    elif step == 3:
        st.subheader("Stage 4: Alice Computes Her Public Key (A)")
        st.write(
            "Alice raises the public generator g to her private exponent a modulo p. "
            "Recovering a from A is the Discrete Logarithm Problem."
        )
        st.latex(rf"A = g^a \bmod p = {g}^{{{a}}} \bmod {p} = {A}")
    elif step == 4:
        st.subheader("Stage 5: Bob Computes His Public Key (B)")
        st.write(
            "Bob performs the matching modular exponentiation using his private key b."
        )
        st.latex(rf"B = g^b \bmod p = {g}^{{{b}}} \bmod {p} = {B}")
    elif step == 5:
        st.subheader("Stage 6: Alice and Bob Exchange Public Keys")
        st.write(
            "Alice sends A to Bob and Bob sends B to Alice over the insecure channel. "
            "Only A and B are transmitted; private keys a and b remain hidden."
        )
        st.latex(rf"\text{{Alice}} \xrightarrow{{A = {A}}} \text{{Bob}}, \qquad \text{{Bob}} \xrightarrow{{B = {B}}} \text{{Alice}}")
    elif step == 6:
        st.subheader("Stage 7: Alice Computes the Shared Secret (S_A)")
        st.write(
            "Alice takes Bob's public key B and raises it to her own private exponent a modulo p."
        )
        st.latex(rf"S_A = B^a \bmod p = {B}^{{{a}}} \bmod {p} = {s_a}")
    elif step == 7:
        st.subheader("Stage 8: Bob Computes the Shared Secret (S_B)")
        st.write(
            "Bob takes Alice's public key A and raises it to his own private exponent b modulo p."
        )
        st.latex(rf"S_B = A^b \bmod p = {A}^{{{b}}} \bmod {p} = {s_b}")
    elif step == 8:
        st.subheader("Stage 9: Shared Secret Verification & Key Derivation")
        st.write(
            "Because modular exponentiation commutes, both parties arrive at the exact same integer:"
        )
        st.latex(
            rf"S_A = (g^b)^a \bmod p = g^{{ab}} \bmod p = {s_a} = {s_b} = (g^a)^b \bmod p = S_B"
        )
        if s_a == s_b:
            derived_key = derive_hex_key(result["shared_secret"], byte_length=32)
            st.success(
                f"Match Verified! Both Alice and Bob hold shared secret S = {result['shared_secret']}."
            )
            st.code(f"SHA-256 Derived 256-bit Session Key: {derived_key}", language="text")
        else:
            st.error("Shared secrets do not match.")

    st.markdown("---")
    _render_participant_panels(result, step)

    st.divider()
    _render_modular_exponentiation_explorer(result)
