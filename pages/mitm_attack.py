"""Man-in-the-Middle (MITM) active key-substitution attack simulation page."""

from typing import Optional
import plotly.graph_objects as go
import streamlit as st

from dh_app.attacks import MITMResult, simulate_mitm_attack
from dh_app.diffie_hellman import DiffieHellmanError, ExchangeResult


def _build_mitm_diagram(mitm: MITMResult) -> go.Figure:
    """Create a clean Plotly sequence diagram showing Eve intercepting and substituting keys."""
    fig = go.Figure()

    # Participant lifelines: Alice (x=0), Eve (x=1), Bob (x=2)
    participants = [
        (0.0, "Alice", "#38bdf8"),
        (1.0, "Eve (Attacker)", "#f87171"),
        (2.0, "Bob", "#34d399"),
    ]

    for x_pos, label, color in participants:
        fig.add_trace(
            go.Scatter(
                x=[x_pos, x_pos],
                y=[0.5, 5.2],
                mode="lines",
                line=dict(color=color, width=2, dash="dot"),
                hoverinfo="skip",
                showlegend=False,
            )
        )
        fig.add_annotation(
            x=x_pos,
            y=5.45,
            text=f"<b>{label}</b>",
            showarrow=False,
            font=dict(size=14, color=color),
            bgcolor="#101b2d",
            bordercolor=color,
            borderwidth=1.5,
            borderpad=6,
        )

    messages = [
        (0.0, 0.96, 4.6, f"1. Alice sends A = {mitm['alice_original_public']}", "#38bdf8"),
        (1.04, 2.0, 3.9, f"2. Eve substitutes E_A = {mitm['eve_public_to_bob']}", "#f87171"),
        (2.0, 1.04, 3.1, f"3. Bob sends B = {mitm['bob_original_public']}", "#34d399"),
        (0.96, 0.0, 2.4, f"4. Eve substitutes E_B = {mitm['eve_public_to_alice']}", "#f87171"),
    ]

    for x0, x1, y_pos, text, color in messages:
        fig.add_annotation(
            x=x1,
            y=y_pos,
            ax=x0,
            ay=y_pos,
            xref="x",
            yref="y",
            axref="x",
            ayref="y",
            showarrow=True,
            arrowhead=3,
            arrowsize=1.3,
            arrowwidth=2.2,
            arrowcolor=color,
        )
        fig.add_annotation(
            x=(x0 + x1) / 2,
            y=y_pos + 0.24,
            text=text,
            showarrow=False,
            font=dict(size=12, color="#e8eef8"),
            bgcolor="#0f1b2e",
            bordercolor=color,
            borderwidth=1,
            borderpad=4,
        )

    # Bottom secret boxes
    secrets_boxes = [
        (0.0, 1.1, f"Alice Secret<br>S_AE = {mitm['alice_shared_secret']}", "#38bdf8"),
        (1.0, 1.1, f"Eve holds BOTH:<br>S_EA={mitm['eve_secret_with_alice']} | S_EB={mitm['eve_secret_with_bob']}", "#f87171"),
        (2.0, 1.1, f"Bob Secret<br>S_BE = {mitm['bob_shared_secret']}", "#34d399"),
    ]
    for x_pos, y_pos, label, color in secrets_boxes:
        fig.add_annotation(
            x=x_pos,
            y=y_pos,
            text=label,
            showarrow=False,
            font=dict(size=12, color="#e8eef8"),
            bgcolor="#142238",
            bordercolor=color,
            borderwidth=1.5,
            borderpad=6,
        )

    fig.update_layout(
        height=440,
        margin=dict(l=25, r=25, t=35, b=20),
        paper_bgcolor="#080f1d",
        plot_bgcolor="#080f1d",
        xaxis=dict(range=[-0.45, 2.45], visible=False),
        yaxis=dict(range=[0.4, 5.8], visible=False),
    )
    return fig


def render_mitm_attack(result: Optional[ExchangeResult]) -> None:
    """Render the active Man-in-the-Middle simulation page."""
    st.header("Man-in-the-Middle (MITM) Attack Simulation")
    st.write(
        "Unauthenticated Diffie-Hellman verifies mathematical consistency, not identity. "
        "If an active attacker (Eve) controls the network channel, she can intercept public "
        "keys and substitute her own."
    )

    if result is None:
        st.warning("Configure valid parameters above to run the MITM simulation.")
        return

    p = result["p"]
    c1, c2 = st.columns(2)
    with c1:
        eve_a = st.number_input(
            "Eve's private key toward Bob (eve_a)",
            min_value=2,
            max_value=max(2, p - 2),
            value=min(7, max(2, p - 2)),
            step=1,
            key="mitm_eve_a",
            help="Eve uses E_A = g^(eve_a) mod p to impersonate Alice to Bob.",
        )
    with c2:
        eve_b = st.number_input(
            "Eve's private key toward Alice (eve_b)",
            min_value=2,
            max_value=max(2, p - 2),
            value=min(9, max(2, p - 2)),
            step=1,
            key="mitm_eve_b",
            help="Eve uses E_B = g^(eve_b) mod p to impersonate Bob to Alice.",
        )

    try:
        mitm = simulate_mitm_attack(
            p=result["p"],
            g=result["g"],
            a=result["a"],
            b=result["b"],
            eve_a=int(eve_a),
            eve_b=int(eve_b),
        )
    except DiffieHellmanError as exc:
        st.error(f"Invalid MITM parameters: {exc}")
        return

    st.subheader("1. Sequence Diagram: Interception & Key Substitution")
    st.plotly_chart(_build_mitm_diagram(mitm), use_container_width=True)

    st.subheader("2. Message-by-Message Breakdown")
    col_a, col_e, col_b = st.columns(3)

    with col_a:
        st.markdown(
            f"""
            <div class="role-card role-alice">
                <span class="badge badge-alice">Alice</span>
                <h4>Believes she talks to Bob</h4>
                <p>1. Sends <strong>A = {mitm['alice_original_public']}</strong></p>
                <p>4. Receives forged <strong>E<sub>B</sub> = {mitm['eve_public_to_alice']}</strong></p>
                <p>5. Computes <strong>S<sub>AE</sub> = (E<sub>B</sub>)<sup>a</sup> mod p = {mitm['alice_shared_secret']}</strong></p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_e:
        st.markdown(
            f"""
            <div class="role-card role-eve">
                <span class="badge badge-eve">Eve (Active Attacker)</span>
                <h4>Splits the Channel in Two</h4>
                <p>2. Blocks A; sends <strong>E<sub>A</sub> = {mitm['eve_public_to_bob']}</strong> to Bob</p>
                <p>3. Blocks B; sends <strong>E<sub>B</sub> = {mitm['eve_public_to_alice']}</strong> to Alice</p>
                <p>6. Computes <strong>S<sub>EA</sub> = {mitm['eve_secret_with_alice']}</strong> &amp; <strong>S<sub>EB</sub> = {mitm['eve_secret_with_bob']}</strong></p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_b:
        st.markdown(
            f"""
            <div class="role-card role-bob">
                <span class="badge badge-bob">Bob</span>
                <h4>Believes he talks to Alice</h4>
                <p>2. Receives forged <strong>E<sub>A</sub> = {mitm['eve_public_to_bob']}</strong></p>
                <p>3. Sends <strong>B = {mitm['bob_original_public']}</strong></p>
                <p>6. Computes <strong>S<sub>BE</sub> = (E<sub>A</sub>)<sup>b</sup> mod p = {mitm['bob_shared_secret']}</strong></p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.subheader("3. Resulting Compromised Secrets")
    s1, s2, s3, s4 = st.columns(4)
    s1.metric("Alice's Secret (S_AE)", mitm["alice_shared_secret"])
    s2.metric("Eve's Secret w/ Alice", mitm["eve_secret_with_alice"])
    s3.metric("Bob's Secret (S_BE)", mitm["bob_shared_secret"])
    s4.metric("Eve's Secret w/ Bob", mitm["eve_secret_with_bob"])

    if mitm["attack_succeeded"]:
        st.error(
            "MITM Attack Succeeded: Eve shares S_AE with Alice and S_BE with Bob. "
            "Eve can decrypt Alice's messages with S_AE, read or alter them, and re-encrypt "
            "them for Bob using S_BE without either party detecting tampering."
        )
        if mitm["alice_shared_secret"] == mitm["bob_shared_secret"]:
            st.warning(
                "Note: With these specific numbers, S_AE and S_BE happen to have the same integer value, "
                "but they were still negotiated across two independent Eve-controlled sessions."
            )

    st.info(
        "Why can't Alice and Bob detect Eve? Because raw Diffie-Hellman public keys carry no "
        "cryptographic proof of origin. Real protocols prevent MITM attacks using digital signatures, "
        "X.509 certificates (TLS), or pre-shared authentication keys."
    )
