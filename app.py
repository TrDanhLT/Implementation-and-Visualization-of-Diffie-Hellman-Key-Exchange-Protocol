import streamlit as st

from dh_app.diffie_hellman import (
    DiffieHellmanError,
    calculate_exchange,
    generate_private_key,
    is_generator,
    is_prime,
)

# --------------------------------------------------
# PAGE CONFIGURATION
# Must be the first Streamlit command in this file.
# --------------------------------------------------

st.set_page_config(
    page_title="Diffie-Hellman Simulator",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# --------------------------------------------------
# CUSTOM DESIGN
# --------------------------------------------------

st.markdown(
    """
    <style>
    /* ---------- Global theme ---------- */
    :root {
        --bg: #080f1d;
        --surface: #101b2d;
        --surface-soft: #142238;
        --border: rgba(148, 163, 184, 0.16);
        --text: #e8eef8;
        --muted: #9aabc2;
        --accent: #67e8f9;
        --accent-strong: #38bdf8;
    }

    .stApp {
        background:
            radial-gradient(ellipse at 82% 0%, rgba(56, 189, 248, 0.12), transparent 34%),
            radial-gradient(ellipse at 8% 22%, rgba(99, 102, 241, 0.10), transparent 32%),
            var(--bg);
        color: var(--text);
    }

    .main .block-container {
        max-width: 1380px;
        padding: 2.4rem 2.5rem 3.5rem;
    }

    /* ---------- Typography ---------- */
    h1, h2, h3, h4 {
        color: var(--text) !important;
        letter-spacing: -0.025em;
    }

    h1 {
        font-size: clamp(2rem, 3vw, 2.8rem) !important;
        font-weight: 800 !important;
        line-height: 1.15 !important;
    }

    h2 {
        font-size: 1.65rem !important;
        font-weight: 750 !important;
        margin-top: 1.3rem !important;
    }

    h3, h4 {
        font-weight: 700 !important;
    }

    p, li, label, .stCaption {
        color: #c4d0e0;
        line-height: 1.7;
    }

    [data-testid="stCaptionContainer"] p {
        color: var(--muted) !important;
    }

    /* ---------- Sidebar ---------- */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #101c30 0%, #0b1424 100%);
        border-right: 1px solid var(--border);
    }

    [data-testid="stSidebar"] > div:first-child {
        padding-top: 1.5rem;
    }

    [data-testid="stSidebar"] h1,
    [data-testid="stSidebar"] h2,
    [data-testid="stSidebar"] h3 {
        color: #f1f7ff !important;
    }

    [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p {
        color: var(--muted);
    }

    /* Navigation radio items */
    [data-testid="stSidebar"] div[role="radiogroup"] {
        gap: 0.35rem;
    }

    [data-testid="stSidebar"] div[role="radiogroup"] label {
        background: rgba(255, 255, 255, 0.025);
        border: 1px solid transparent;
        border-radius: 11px;
        padding: 0.55rem 0.75rem;
        transition: all 160ms ease;
    }

    [data-testid="stSidebar"] div[role="radiogroup"] label:hover {
        background: rgba(56, 189, 248, 0.08);
        border-color: rgba(56, 189, 248, 0.22);
    }

    /* ---------- Cards and metrics ---------- */
    [data-testid="stMetric"] {
        background: linear-gradient(145deg, rgba(22, 39, 63, 0.96), rgba(15, 27, 45, 0.96));
        border: 1px solid var(--border);
        border-radius: 18px;
        padding: 1.15rem 1.25rem;
        box-shadow: 0 12px 32px rgba(0, 0, 0, 0.16);
        transition: transform 160ms ease, border-color 160ms ease;
    }

    [data-testid="stMetric"]:hover {
        transform: translateY(-2px);
        border-color: rgba(103, 232, 249, 0.32);
    }

    [data-testid="stMetricLabel"] {
        color: #a8bad1 !important;
        font-size: 0.86rem !important;
        font-weight: 600 !important;
    }

    [data-testid="stMetricValue"] {
        color: var(--accent) !important;
        font-size: 1.8rem !important;
        font-weight: 800 !important;
    }

    /* ---------- Buttons ---------- */
    .stButton > button,
    .stDownloadButton > button {
        min-height: 2.7rem;
        border-radius: 11px;
        border: 1px solid rgba(103, 232, 249, 0.25);
        background: linear-gradient(135deg, #12324a, #16415a);
        color: #e8fbff;
        font-weight: 700;
        transition: all 160ms ease;
    }

    .stButton > button:hover,
    .stDownloadButton > button:hover {
        border-color: var(--accent);
        background: linear-gradient(135deg, #16445e, #15516b);
        color: white;
        transform: translateY(-1px);
    }

    .stButton > button:focus {
        box-shadow: 0 0 0 0.2rem rgba(56, 189, 248, 0.2);
    }

    /* ---------- Inputs ---------- */
    .stTextInput input,
    .stNumberInput input,
    .stTextArea textarea,
    .stSelectbox div[data-baseweb="select"] > div {
        background: #101d30;
        color: var(--text);
        border-color: rgba(148, 163, 184, 0.22);
        border-radius: 10px;
    }

    [data-baseweb="popover"] {
        background: #142238;
    }

    /* ---------- Alerts and progress ---------- */
    [data-testid="stAlert"] {
        border-radius: 13px;
        border: 1px solid var(--border);
    }

    [data-testid="stProgressBar"] > div > div {
        background: linear-gradient(90deg, #38bdf8, #67e8f9);
        border-radius: 99px;
    }

    /* ---------- Dividers and code ---------- */
    hr {
        border-color: rgba(148, 163, 184, 0.17) !important;
        margin: 1.5rem 0 !important;
    }

    [data-testid="stCodeBlock"] {
        border: 1px solid var(--border);
        border-radius: 12px;
    }

    /* ---------- Responsive spacing ---------- */
    @media (max-width: 768px) {
        .main .block-container {
            padding: 1.4rem 1rem 2.5rem;
        }

        h1 {
            font-size: 1.9rem !important;
        }

        [data-testid="stMetric"] {
            padding: 0.9rem;
        }
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# --------------------------------------------------
# SIDEBAR: NAVIGATION ONLY
# --------------------------------------------------

st.sidebar.title("🔐 DH Simulator")
st.sidebar.caption("Cryptography learning project")
st.sidebar.divider()

page = st.sidebar.radio(
    "Navigate",
    [
        "Dashboard",
        "Key Exchange",
        "MITM Attack",
        "Brute Force",
        "Protocol Flowchart",
        "Testing",
    ],
)

# --------------------------------------------------
# COMMON HEADER
# --------------------------------------------------

st.title("🔐 Diffie-Hellman Key Exchange Simulator")
st.caption("An interactive learning environment for understanding secure key exchange.")

def generate_random_keys():
    p_value = int(st.session_state.parameter_p)

    if is_prime(p_value) and p_value >= 5:
        st.session_state.alice_private_input = generate_private_key(p_value)
        st.session_state.bob_private_input = generate_private_key(p_value)
    else:
        st.session_state.random_key_error = (
            "Enter a valid prime number before generating private keys."
        )
# --------------------------------------------------
# MAIN-WORKSPACE CONFIGURATION
# --------------------------------------------------

with st.container(border=True):
    st.subheader("⚙️ Simulation Configuration")
    st.caption(
        "Set the public parameters and private keys here. The calculations "
        "throughout the simulator update using these values."
    )

    # Keep private-key input values in session state so the random-key
    # button can update them before the widgets are rendered again.
    if "alice_private_input" not in st.session_state:
        st.session_state.alice_private_input = 6
    if "bob_private_input" not in st.session_state:
        st.session_state.bob_private_input = 15

    config1, config2, config3, config4 = st.columns(4)

    with config1:
        p = st.number_input(
            "Prime modulus (p)",
            min_value=5,
            max_value=1_000_000,
            value=23,
            step=1,
            key="parameter_p",
            help="A prime number used as the modulus.",
        )

    with config2:
        g = st.number_input(
            "Generator (g)",
            min_value=2,
            max_value=999_999,
            value=5,
            step=1,
            key="parameter_g",
            help="A generator modulo p.",
        )

    with config3:
        a = st.number_input(
            "Alice private key (a)",
            min_value=2,
            max_value=999_999,
            step=1,
            key="alice_private_input",
        )

    with config4:
        b = st.number_input(
            "Bob private key (b)",
            min_value=2,
            max_value=999_999,
            step=1,
            key="bob_private_input",
        )

    random_col, note_col = st.columns([1, 2])

    random_col, note_col = st.columns([1, 2])

    with random_col:
        st.button(
            "🎲 Generate random private keys",
            use_container_width=True,
            on_click=generate_random_keys
        )

        if st.session_state.get("random_key_error"):
            st.error(st.session_state.random_key_error)
            st.session_state.random_key_error = None
        
    with note_col:
        st.caption(
            "Learning mode only: the small example values used here are not "
            "suitable for real-world cryptographic security."
        )
# SHARED VALIDATION AND CALCULATION
result = None
validation_error = None

try:
    result = calculate_exchange(int(p), int(g), int(a), int(b))
except (DiffieHellmanError, ValueError) as error:
    validation_error = str(error)

if validation_error:
    st.error(f"Configuration error: {validation_error}")
    st.info(
        "Use a prime number for p, a valid generator for g, and private keys "
        "between 2 and p − 2. Adjust the configuration above."
    )

# --------------------------------------------------
# PAGE 1: DASHBOARD
# --------------------------------------------------

if page == "Dashboard":
    st.header("Project Overview")
    st.write(
        "Diffie-Hellman is a key-agreement method that allows two participants "
        "to create the same shared secret while communicating over a public "
        "channel. They exchange public values, but keep their private keys "
        "to themselves."
    )

    st.subheader("🎯 Project Objectives")
    objective1, objective2, objective3 = st.columns(3)
    with objective1:
        st.markdown("#### Understand the protocol")
        st.write(
            "Learn how public parameters, private keys, public keys, and "
            "modular exponentiation work together."
        )
    with objective2:
        st.markdown("#### Visualize the calculations")
        st.write(
            "Follow Alice and Bob step by step and see why both sides "
            "arrive at the same shared secret."
        )
    with objective3:
        st.markdown("#### Explore security limitations")
        st.write(
            "Use the MITM and brute-force demonstrations to understand why "
            "authentication and strong parameters matter."
        )

    st.divider()
    st.subheader("🔄 How the Project Works")
    st.write(
        "The simulator is organized as a sequence of stages. Start with the "
        "shared public parameters, follow the key exchange, and then explore "
        "what happens when an attacker interferes."
    )

    flow = [
        ("01", "Configure parameters", "Choose prime p, generator g, and Alice and Bob's private keys."),
        ("02", "Generate public keys", "Alice calculates A = gᵃ mod p. Bob calculates B = gᵇ mod p."),
        ("03", "Exchange public keys", "Alice sends A to Bob, and Bob sends B to Alice. Private keys stay secret."),
        ("04", "Calculate shared secrets", "Alice calculates Bᵃ mod p. Bob calculates Aᵇ mod p."),
        ("05", "Verify the result", "Both calculations should produce the same shared secret."),
        ("06", "Explore security tests", "Examine a man-in-the-middle scenario and a small brute-force demonstration."),
    ]

    flow_columns = st.columns(3)
    for index, (number, title, description) in enumerate(flow):
        with flow_columns[index % 3]:
            with st.container(border=True):
                st.markdown(f"**STEP {number}**")
                st.markdown(f"#### {title}")
                st.write(description)

    st.divider()
    st.subheader("📌 Current Simulation")
    if result is not None:
        metric1, metric2, metric3 = st.columns(3)
        metric1.metric("Prime modulus (p)", result["p"])
        metric2.metric("Generator (g)", result["g"])
        metric3.metric("Shared secret", result["shared_secret"])
        st.success(
            "The current parameters produce a matching shared secret "
            "for Alice and Bob."
        )
    else:
        st.warning("The current configuration is invalid. Update the parameters above.")

    st.subheader("🧭 Modules in This Simulator")
    modules = [
        ("🔑 Key Exchange", "A guided, six-stage walkthrough of the normal Diffie-Hellman protocol."),
        ("🕵️ MITM Attack", "A demonstration of how an attacker can replace public keys and create separate secrets."),
        ("🔓 Brute Force", "A limited educational search showing why tiny demonstration parameters are weak."),
        ("📊 Protocol Flowchart", "A compact view of the participants, exchanged values, and calculations."),
        ("🧪 Testing", "An overview of the automated unit tests and the command used to run them."),
    ]
    for module_name, module_description in modules:
        st.markdown(f"**{module_name}**")
        st.write(module_description)

    st.warning(
        "Security note: this application is an educational simulator. "
        "It does not implement production-grade cryptography and its small "
        "demonstration values must not be used to protect real information."
    )

# --------------------------------------------------
# PAGE 2: NORMAL KEY EXCHANGE
# --------------------------------------------------

elif page == "Key Exchange":
    st.header("Normal Diffie-Hellman Key Exchange")
    st.write("Use the Next and Previous buttons to move through the protocol.")

    if result is not None:
        if "step" not in st.session_state:
            st.session_state.step = 0

        step = st.session_state.step
        progress = (step + 1) / 6
        st.progress(progress)
        st.caption(f"Stage {step + 1} of 6")

        if step == 0:
            st.subheader("1. Agree on public parameters")
            st.write("Alice and Bob publicly agree on a prime modulus p and a generator g.")
            c1, c2 = st.columns(2)
            c1.metric("Prime modulus (p)", result["p"])
            c2.metric("Generator (g)", result["g"])
            st.info("These parameters are public. They do not need to be secret.")

        elif step == 1:
            st.subheader("2. Alice generates her public key")
            st.write("Alice keeps her private key secret and calculates her public key.")
            st.metric("Alice private key (a)", result["a"])
            st.latex(r"A = g^a \bmod p")
            st.latex(
                f"A = {result['g']}^{{{result['a']}}} "
                f"\\bmod {result['p']} = {result['A']}"
            )
            st.success(f"Alice's public key A = {result['A']}")

        elif step == 2:
            st.subheader("3. Bob generates his public key")
            st.write("Bob keeps his private key secret and calculates his public key.")
            st.metric("Bob private key (b)", result["b"])
            st.latex(r"B = g^b \bmod p")
            st.latex(
                f"B = {result['g']}^{{{result['b']}}} "
                f"\\bmod {result['p']} = {result['B']}"
            )
            st.success(f"Bob's public key B = {result['B']}")

        elif step == 3:
            st.subheader("4. Exchange public keys")
            c1, c2 = st.columns(2)
            c1.metric("Alice sends A to Bob", result["A"])
            c2.metric("Bob sends B to Alice", result["B"])
            st.info("Only public keys are exchanged. Private keys are never transmitted.")

        elif step == 4:
            st.subheader("5. Both calculate the shared secret")
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("#### Alice calculates")
                st.latex(r"K_A = B^a \bmod p")
                st.latex(
                    f"K_A = {result['B']}^{{{result['a']}}} "
                    f"\\bmod {result['p']} = {result['alice_secret']}"
                )
            with c2:
                st.markdown("#### Bob calculates")
                st.latex(r"K_B = A^b \bmod p")
                st.latex(
                    f"K_B = {result['A']}^{{{result['b']}}} "
                    f"\\bmod {result['p']} = {result['bob_secret']}"
                )

        elif step == 5:
            st.subheader("6. Verify the shared secret")
            c1, c2 = st.columns(2)
            c1.metric("Alice's shared secret", result["alice_secret"])
            c2.metric("Bob's shared secret", result["bob_secret"])
            if result["alice_secret"] == result["bob_secret"]:
                st.success("Success! Alice and Bob have established the same shared secret.")
                st.metric("Final shared secret", result["shared_secret"])
            else:
                st.error("The shared secrets do not match.")

        st.divider()
        prev_col, restart_col, next_col = st.columns(3)

        with prev_col:
            if st.button("⬅ Previous", disabled=(step == 0), use_container_width=True):
                st.session_state.step -= 1
                st.rerun()

        with restart_col:
            if st.button("🔄 Restart", use_container_width=True):
                st.session_state.step = 0
                st.rerun()

        with next_col:
            if st.button("Next Step ➡", disabled=(step == 5), use_container_width=True):
                st.session_state.step += 1
                st.rerun()

# --------------------------------------------------
# PAGE 3: MAN-IN-THE-MIDDLE ATTACK
# --------------------------------------------------

elif page == "MITM Attack":
    st.header("🕵️ Eve: Man-in-the-Middle Attack")
    st.write(
        "Eve intercepts and replaces the public keys exchanged between Alice and Bob. "
        "This demonstrates why basic Diffie-Hellman needs authentication."
    )

    if result is not None:
        st.warning("Eve substitutes public keys so that Alice and Bob each establish a different secret with Eve.")

        c1, c2 = st.columns(2)
        with c1:
            eve_a = st.number_input(
                "Eve private key used to impersonate Alice to Bob",
                min_value=2,
                max_value=999_999,
                value=7,
                step=1,
                key="eve_a",
            )
        with c2:
            eve_b = st.number_input(
                "Eve private key used to impersonate Bob to Alice",
                min_value=2,
                max_value=999_999,
                value=9,
                step=1,
                key="eve_b",
            )

        if not (2 <= eve_a <= int(p) - 2 and 2 <= eve_b <= int(p) - 2):
            st.error("Eve's private keys must be between 2 and p − 2.")
        else:
            eve_public_alice = pow(int(g), int(eve_a), int(p))
            eve_public_bob = pow(int(g), int(eve_b), int(p))

            alice_fake_key = eve_public_bob
            bob_fake_key = eve_public_alice

            alice_eve_secret = pow(alice_fake_key, int(a), int(p))
            bob_eve_secret = pow(bob_fake_key, int(b), int(p))

            eve_alice_secret = pow(result["A"], int(eve_b), int(p))
            eve_bob_secret = pow(result["B"], int(eve_a), int(p))

            st.subheader("1. Eve intercepts and replaces the public keys")
            left, right = st.columns(2)
            with left:
                st.markdown("#### Alice")
                st.metric("Original Bob public key", result["B"])
                st.metric("Key Alice receives from Eve", alice_fake_key)
            with right:
                st.markdown("#### Bob")
                st.metric("Original Alice public key", result["A"])
                st.metric("Key Bob receives from Eve", bob_fake_key)

            st.subheader("2. Two separate shared secrets are created")
            left, right = st.columns(2)
            with left:
                st.markdown("#### Alice ↔ Eve")
                st.metric("Alice's secret", alice_eve_secret)
                st.metric("Eve's matching secret", eve_alice_secret)
            with right:
                st.markdown("#### Bob ↔ Eve")
                st.metric("Bob's secret", bob_eve_secret)
                st.metric("Eve's matching secret", eve_bob_secret)

            if (
                alice_eve_secret == eve_alice_secret
                and bob_eve_secret == eve_bob_secret
            ):
                st.error("MAN-IN-THE-MIDDLE ATTACK SUCCESSFUL")
                st.write(
                    "Eve has established two separate shared secrets. "
                    "Alice and Bob are not sharing one end-to-end secret."
                )
                if alice_eve_secret == bob_eve_secret:
                    st.warning(
                        "For these particular values, the two numeric secrets happen to match. "
                        "The protocol still has two separate Eve-mediated exchanges."
                    )
            else:
                st.error("The simulated key calculations did not match.")

            st.info(
                "Basic Diffie-Hellman does not authenticate public keys. "
                "Authenticated key exchange, digital signatures, or certificate-based "
                "protocols such as TLS help prevent this substitution attack."
            )

# --------------------------------------------------
# PAGE 4: BRUTE-FORCE DEMONSTRATION
# --------------------------------------------------

elif page == "Brute Force":
    st.header("🔓 Educational Brute-Force Demonstration")
    st.write(
        "The attacker knows p, g, and Alice's public key A, and tries candidate "
        "private keys until one produces the same public key."
    )

    if result is not None:
        c1, c2, c3 = st.columns(3)
        c1.metric("Prime modulus (p)", result["p"])
        c2.metric("Generator (g)", result["g"])
        c3.metric("Alice's public key (A)", result["A"])

        if int(p) <= 1000:
            if st.button("🚀 Run brute-force search", key="run_brute_force"):
                recovered_key = None
                attempts = 0

                for candidate in range(2, int(p) - 1):
                    attempts += 1
                    if pow(int(g), candidate, int(p)) == result["A"]:
                        recovered_key = candidate
                        break

                if recovered_key is not None:
                    st.success(f"Private key recovered after {attempts} attempts.")
                    left, right = st.columns(2)
                    left.metric("Original private key", int(a))
                    right.metric("Recovered private key", recovered_key)
                    if recovered_key == int(a):
                        st.success("The recovered candidate matches Alice's private key.")
                    else:
                        st.warning(
                            "A matching exponent was found, but it differs from the entered "
                            "private key. In modular arithmetic, more than one exponent can "
                            "produce the same public value."
                        )
                else:
                    st.warning("No matching candidate was found in the searched range.")
        else:
            st.warning(
                "This educational search is limited to p ≤ 1000 to keep the demonstration "
                "responsive. It is not a realistic attack benchmark."
            )

        st.subheader("What does this demonstrate?")
        st.markdown(
            """
            - The public values are visible to an observer.
            - With tiny demonstration parameters, trying candidate exponents is easy.
            - Real Diffie-Hellman uses carefully selected groups and much larger security parameters.
            - This simple loop is a teaching example, not a modern discrete-logarithm attack.
            """
        )

# --------------------------------------------------
# PAGE 5: PROTOCOL FLOWCHART
# --------------------------------------------------

elif page == "Protocol Flowchart":
    st.header("📊 Diffie-Hellman Protocol Flowchart")
    st.write("A visual summary of the normal key exchange.")

    if result is not None:
        st.info(f"Public parameters: p = {p}, g = {g}")

        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown("#### 1. Alice")
            st.write("Chooses private key a.")
            st.code(f"a = {a}")
            st.code("A = g^a mod p")
            st.metric("Public key A", result["A"])
        with c2:
            st.markdown("#### 2. Bob")
            st.write("Chooses private key b.")
            st.code(f"b = {b}")
            st.code("B = g^b mod p")
            st.metric("Public key B", result["B"])
        with c3:
            st.markdown("#### 3. Public exchange")
            st.write("They exchange public keys.")
            st.code(f"Alice sends A = {result['A']}")
            st.code(f"Bob sends B = {result['B']}")
            st.success("Public keys exchanged")

        st.markdown(
            "<div style='text-align:center;font-size:30px;'>⬇️</div>",
            unsafe_allow_html=True,
        )

        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown("#### 4. Alice calculates")
            st.latex(r"K_A = B^a \bmod p")
            st.metric("Alice's shared secret", result["alice_secret"])
        with c2:
            st.markdown("#### 5. Bob calculates")
            st.latex(r"K_B = A^b \bmod p")
            st.metric("Bob's shared secret", result["bob_secret"])
        with c3:
            st.markdown("#### 6. Verification")
            if result["alice_secret"] == result["bob_secret"]:
                st.success("Both shared secrets match.")
                st.metric("Final shared secret", result["shared_secret"])
            else:
                st.error("The shared secrets do not match.")

        st.caption("Private keys are never transmitted. Only public keys are exchanged.")

# --------------------------------------------------
# PAGE 6: TESTING
# --------------------------------------------------

elif page == "Testing":
    st.header("🧪 Unit Testing")
    st.write(
        "The project uses Python's built-in unittest framework to check the "
        "Diffie-Hellman functions."
    )

    st.success("You reported that all 8 unit tests passed.")

    test_cases = [
        ("Prime number validation", "Checks that 23 is identified as prime."),
        ("Non-prime validation", "Checks that 24 is rejected as non-prime."),
        ("Valid generator", "Checks that 5 is a primitive root modulo 23."),
        ("Invalid generator", "Checks that 4 is rejected modulo 23."),
        ("Successful key exchange", "Checks that Alice and Bob calculate the same secret."),
        ("Invalid prime handling", "Checks that an invalid modulus raises DiffieHellmanError."),
        ("Invalid private key handling", "Checks that an out-of-range private key is rejected."),
        ("Private key generation", "Checks that a generated key is within the permitted range."),
    ]

    for index, (name, description) in enumerate(test_cases, start=1):
        st.markdown(f"**{index}. {name}**")
        st.caption(description)

    st.subheader("Run the tests again")
    st.code(
        r".\.venv\Scripts\python.exe -m unittest discover -s tests -v",
        language="powershell",
    )
    st.info(
        "Run this command from the project root folder in PowerShell. "
        "The tests are separate from the Streamlit website."
    )

# --------------------------------------------------
# FOOTER
# --------------------------------------------------

st.divider()
st.caption(
    "Diffie-Hellman Key Exchange Simulator | Educational project | "
    "Not intended for production cryptographic use."
)
