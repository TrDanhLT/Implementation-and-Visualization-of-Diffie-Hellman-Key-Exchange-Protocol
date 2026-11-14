"""Protocol Flowchart page using an interactive Plotly sequence diagram."""

from typing import Optional
import plotly.graph_objects as go
import streamlit as st

from dh_app.diffie_hellman import ExchangeResult


def _build_protocol_flowchart(result: ExchangeResult) -> go.Figure:
    """Build a structured two-party Diffie-Hellman protocol sequence diagram."""
    p, g, a, b = result["p"], result["g"], result["a"], result["b"]
    A, B, S = result["A"], result["B"], result["shared_secret"]

    fig = go.Figure()

    # Alice (x=0.2) and Bob (x=1.8) vertical lifelines
    for x_pos, title, color in [
        (0.25, "ALICE", "#38bdf8"),
        (1.75, "BOB", "#34d399"),
    ]:
        fig.add_trace(
            go.Scatter(
                x=[x_pos, x_pos],
                y=[0.4, 6.2],
                mode="lines",
                line=dict(color=color, width=2.5, dash="dash"),
                hoverinfo="skip",
                showlegend=False,
            )
        )
        fig.add_annotation(
            x=x_pos,
            y=6.55,
            text=f"<b>{title}</b>",
            showarrow=False,
            font=dict(size=15, color=color),
            bgcolor="#101b2d",
            bordercolor=color,
            borderwidth=1.5,
            borderpad=8,
        )

    # Top shared public parameters banner
    fig.add_annotation(
        x=1.0,
        y=6.55,
        text=f"<b>Public Parameters</b><br>p = {p}, g = {g}",
        showarrow=False,
        font=dict(size=12, color="#fde68a"),
        bgcolor="#1a1d24",
        bordercolor="#fbbf24",
        borderwidth=1.2,
        borderpad=6,
    )

    # Local computation boxes
    boxes = [
        (0.25, 5.55, f"<b>1. Private Key (Secret)</b><br>a = {a}", "#a78bfa"),
        (1.75, 5.55, f"<b>1. Private Key (Secret)</b><br>b = {b}", "#a78bfa"),
        (0.25, 4.55, f"<b>2. Public Key</b><br>A = {g}^{a} mod {p} = <b>{A}</b>", "#38bdf8"),
        (1.75, 4.55, f"<b>2. Public Key</b><br>B = {g}^{b} mod {p} = <b>{B}</b>", "#34d399"),
        (0.25, 1.75, f"<b>4. Shared Secret</b><br>S_A = {B}^{a} mod {p} = <b>{S}</b>", "#38bdf8"),
        (1.75, 1.75, f"<b>4. Shared Secret</b><br>S_B = {A}^{b} mod {p} = <b>{S}</b>", "#34d399"),
    ]
    for x_pos, y_pos, text, border_color in boxes:
        fig.add_annotation(
            x=x_pos,
            y=y_pos,
            text=text,
            showarrow=False,
            font=dict(size=12, color="#e8eef8"),
            bgcolor="#101b2d",
            bordercolor=border_color,
            borderwidth=1.4,
            borderpad=7,
        )

    # Public key transmission arrows
    arrows = [
        (0.32, 1.68, 3.55, f"3a. Public Transmission: Alice sends A = {A} to Bob", "#fbbf24"),
        (1.68, 0.32, 2.75, f"3b. Public Transmission: Bob sends B = {B} to Alice", "#fbbf24"),
    ]
    for x0, x1, y_pos, label, color in arrows:
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
            x=1.0,
            y=y_pos + 0.24,
            text=label,
            showarrow=False,
            font=dict(size=12, color="#fde68a"),
            bgcolor="#0d1728",
            bordercolor=color,
            borderwidth=1,
            borderpad=4,
        )

    # Final verification banner
    fig.add_annotation(
        x=1.0,
        y=0.72,
        text=f"<b>5. Verified Shared Secret: S_A = S_B = {S}</b>",
        showarrow=False,
        font=dict(size=13, color="#6ee7b7"),
        bgcolor="#0f2922",
        bordercolor="#34d399",
        borderwidth=1.5,
        borderpad=8,
    )

    fig.update_layout(
        height=560,
        margin=dict(l=20, r=20, t=25, b=20),
        paper_bgcolor="#080f1d",
        plot_bgcolor="#080f1d",
        xaxis=dict(range=[-0.15, 2.15], visible=False),
        yaxis=dict(range=[0.25, 7.0], visible=False),
    )
    return fig


def render_flowchart(result: Optional[ExchangeResult]) -> None:
    """Render the Protocol Flowchart page."""
    st.header("Diffie-Hellman Protocol Flowchart")
    st.write(
        "End-to-end visual sequence diagram illustrating private state, public key exchange, "
        "and shared secret derivation."
    )

    if result is None:
        st.warning("Configure valid parameters above to render the protocol flowchart.")
        return

    st.plotly_chart(_build_protocol_flowchart(result), use_container_width=True)

    legend1, legend2, legend3 = st.columns(3)
    with legend1:
        st.markdown(
            "<span class='badge badge-secret'>Private Values (a, b, S)</span><br>"
            "Computed and stored locally by Alice and Bob; never transmitted.",
            unsafe_allow_html=True,
        )
    with legend2:
        st.markdown(
            "<span class='badge badge-public'>Public Values (p, g, A, B)</span><br>"
            "Exchanged openly over the network; visible to any observer.",
            unsafe_allow_html=True,
        )
    with legend3:
        st.markdown(
            "<span class='badge badge-bob'>Mathematical Equivalence</span><br>"
            "Both sides compute g^(ab) mod p without revealing a or b.",
            unsafe_allow_html=True,
        )
