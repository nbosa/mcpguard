"""The RC findings of 0.5.0rc1: two defects that are **fixed** in 0.5.0rc2.

Both findings were recorded, not fixed, in 0.5.0rc1: the two reproducers were
**strict** ``xfail`` markers, so the suite was green and the defects stayed
visible.  0.5.0rc2 fixes them, so the markers are gone and the reproducers
are ordinary passing tests.

* **RC-01** (MEDIUM): an oversize upstream line killed the proxy with an
  unhandled ``ValueError`` and the client was left waiting.  The line is now
  discarded safely, the request that was waiting for it is answered with
  ``-32006``, and the proxy keeps serving.
* **RC-02** (LOW): a mistyped command line option was silently ignored.  It
  is now refused with a usage error.

``test_a_violation_reason_holds_the_raw_separator`` is a *passing*
informational test that was never a defect: it pins down why the R-04 fix is
needed and where the separator really lands.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import anyio
import pytest

from mcp_guard.cli import EXIT_USAGE, main
from mcp_guard.proxy import UPSTREAM_OVERSIZE_CODE

from .test_rc_cross_feature import (
    ECHO_UPSTREAM,
    call_over_stdio,
    upstream_script,
)


# ---------------------------------------------------------------------------
# RC-01  an oversize upstream line is answered, and the proxy survives it
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_an_oversize_upstream_line_is_answered_with_an_error(tmp_path: Path) -> None:
    """RC-01 (MEDIUM), fixed in 0.5.0rc2: the client is answered.

    In 0.5.0rc1 ``Upstream._stdout_reader`` raised ``ValueError`` when the
    upstream's stdout carried more than ``MAX_LINE_CHARS`` characters without
    a newline.  The exception was raised inside the task group of the upstream,
    so it cancelled the whole proxy: the client was not answered at all, and
    the JSON-RPC error code ``-32005`` -- the code that is *meant* for "the
    upstream did not answer" -- was never sent.

    The fix has three parts, and this test pins the one the client sees:

    * the oversize line is **discarded** (drained to the next newline without
      being buffered), not fatal;
    * the request that was waiting for that answer is **answered** with the
      dedicated code ``-32006`` -- never left waiting, never given half an
      answer;
    * the proxy **keeps serving**: the next request is answered as usual
      (see ``test_the_proxy_serves_the_next_request_after_an_oversize_line``).

    The code is ``-32006`` and not ``-32005``: ``-32005`` means "the upstream
    was too slow", and an operator has to be able to tell a slow upstream
    from a misbehaving one.
    """
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
version: 1
default_action: deny
tools:
  git_add_many:
    action: allow
    arguments:
      files:
        type: array
        required: true
        items:
          type: string
          path_prefix: "./sandbox"
""".strip()
        + "\n",
        encoding="utf-8",
    )
    upstream = upstream_script(tmp_path)

    with anyio.move_on_after(20) as scope:
        status, detail, code = await call_over_stdio(
            policy=policy_path,
            upstream=upstream,
            cwd=tmp_path,
            arguments={"files": ["sandbox/ok.txt"]},
            extra=("--upstream-timeout", "6"),
            mode="huge",
        )

    if scope.cancelled_caught:
        pytest.fail("the client was left waiting: the proxy died without answering")
    assert status == "error", f"the client got a successful answer: {detail[:200]}"
    assert code == UPSTREAM_OVERSIZE_CODE, f"{code!r} / {detail[:200]}"
    # The answer is an error, not a truncated success.
    assert "x" * 100 not in detail


# ---------------------------------------------------------------------------
# RC-02  an unknown command line option is refused
# ---------------------------------------------------------------------------


def test_an_unknown_option_is_refused(capsys: pytest.CaptureFixture[str]) -> None:
    """RC-02 (LOW), fixed in 0.5.0rc2: a mistyped flag is a usage error.

    ``mcp_guard.cli.main`` used to parse with ``parser.parse_known_args(own)``
    and drop whatever it did not recognise.  A flag that is spelled wrong was
    therefore accepted and did nothing -- and the operator was never told.

    That mattered for the flags that carry a safety property:

    * ``--upstream-timout 5`` (a typo of ``--upstream-timeout``) left the
      upstream without the deadline that R-13 added;
    * ``--audit-keyfile`` (a typo of ``--audit-key-file``) left the log
      without the key the operator named.

    The option is now refused with the argparse convention -- exit code 2 --
    and the message names the flag that was not understood.
    """
    code = main(
        [
            "run",
            "--policy", "does-not-matter.yaml",
            "--upstream-timout", "5",  # a typo of --upstream-timeout
            "--",
            sys.executable, "-c", "pass",
        ]
    )

    assert code == EXIT_USAGE, "an unknown option must be a usage error"
    assert "upstream-timout" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# RC-03  the audit reason quotes a list element in its escaped form
# ---------------------------------------------------------------------------


def test_a_violation_reason_holds_the_raw_separator() -> None:
    """RC-03 (INFORMATIONAL, not a defect): where the separator really goes.

    This one is **not** a defect and therefore **not** an xfail: it is a
    positive test that documents *why* the audit fix of R-04 is needed and
    where the separator ends up.

    Since G-02 a violation reason no longer quotes the offending element at
    all -- it carries a fingerprint of it -- so the *reason* holds neither the
    separator nor the element.  The **arguments** of the call are written with
    ``ensure_ascii=False``, so the separator reaches the record literally.
    The R-04 fix is what keeps that record whole, and the cross-feature test
    ``test_a_list_violation_with_a_line_separator_still_verifies`` is the
    proof.

    The test asserts all three halves, so that a future change to any one of
    them is noticed.
    """
    from mcp_guard.policy import Policy, PolicyEngine

    separator = " "
    policy = Policy.model_validate(
        {
            "tools": {
                "git_add_many": {
                    "action": "allow",
                    "arguments": {
                        "files": {"type": "array", "path_prefix": "./sandbox"}
                    },
                }
            }
        }
    )
    engine = PolicyEngine(policy, session_id="rc61", base_dir=Path.cwd())
    element = f"safe{separator}../escape"
    decision = engine.evaluate("git_add_many", {"files": [element]})

    assert decision.decision == "deny"
    # The reason holds neither the separator nor the element: the element is
    # the value the policy exists to reject, and it is not written down.
    assert separator not in decision.reason
    assert element not in decision.reason
    assert "sha256:" in decision.reason, decision.reason
    # The arguments keep the separator, which is what the log has to survive.
    assert separator in element
    assert json.dumps({"files": [element]}, ensure_ascii=False) == (
        '{"files": ["safe ../escape"]}'
    )
