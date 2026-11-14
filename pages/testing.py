"""Live Unit Testing runner and test suite inspection page."""

import io
import os
import time
import unittest
import streamlit as st


def _discover_and_run_tests():
    """Discover and execute all unit tests in the tests/ directory."""
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    tests_dir = os.path.join(project_root, "tests")

    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=tests_dir, pattern="test_*.py", top_level_dir=project_root)

    stream = io.StringIO()
    runner = unittest.TextTestRunner(stream=stream, verbosity=2)
    start = time.perf_counter()
    test_result = runner.run(suite)
    elapsed = time.perf_counter() - start
    return test_result, stream.getvalue(), elapsed


def render_testing() -> None:
    """Render the automated unit testing verification page."""
    st.header("Automated Unit Testing")
    st.write(
        "All cryptographic calculations, parameter validators, MITM simulations, and brute-force "
        "routines are decoupled from Streamlit and verified via Python's built-in unittest framework."
    )

    if st.button("Run Unit Test Suite Now", type="primary") or "last_test_run" not in st.session_state:
        test_result, output_log, elapsed = _discover_and_run_tests()
        st.session_state.last_test_run = {
            "total": test_result.testsRun,
            "failures": len(test_result.failures),
            "errors": len(test_result.errors),
            "passed": test_result.testsRun - len(test_result.failures) - len(test_result.errors),
            "was_successful": test_result.wasSuccessful(),
            "elapsed_ms": elapsed * 1000,
            "log": output_log,
        }

    report = st.session_state.last_test_run

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Tests Discovered", report["total"])
    m2.metric("Passed", report["passed"])
    m3.metric("Failed / Errors", report["failures"] + report["errors"])
    m4.metric("Execution Time", f"{report['elapsed_ms']:.2f} ms")

    if report["was_successful"]:
        st.success(f"All {report['total']} unit tests passed.")
    else:
        st.error(
            f"Test suite reported {report['failures']} failure(s) and {report['errors']} error(s)."
        )

    st.subheader("Test Suite Coverage")
    c1, c2, c3 = st.columns(3)
    with c1:
        with st.container(border=True):
            st.markdown("**tests/test_diffie_hellman.py**")
            st.caption(
                "Validates prime checks, primitive root generators, integer/boolean rejection, "
                "private/public key bounds, square-and-multiply steps, key derivation, and full exchanges."
            )
    with c2:
        with st.container(border=True):
            st.markdown("**tests/test_mitm.py**")
            st.caption(
                "Verifies Eve's key substitution, independent Alice-Eve and Bob-Eve shared secrets, "
                "and rejection of invalid prime, generator, or private key inputs."
            )
    with c3:
        with st.container(border=True):
            st.markdown("**tests/test_brute_force.py**")
            st.caption(
                "Verifies discrete logarithm recovery, attempt counting, max-attempt search caps, "
                "and rejection of invalid public keys or non-positive limits."
            )

    st.subheader("Live Unittest Output")
    st.code(report["log"], language="text")

    st.subheader("Command-Line Execution")
    st.code("python -m unittest discover -s tests -v", language="bash")
