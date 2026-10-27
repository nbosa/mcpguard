# VERIFY -- mcp-guard v1.0.0-oss

This document records the verification of the `mcp-guard v1.0.0-oss` release:
what was run, what it produced, and which test backs each claim.  Every
command below was run against the tree in this repository, from the repository
root, with the virtual environment described in `CONTRIBUTING.md`.

Nothing here is asserted on the strength of a previous run.  Where a number
appears, it is the number the command printed.

## Verdict

```
VERDICT: PASS
```

The release satisfies the acceptance criteria of the unification task: one
package, one CLI, the runtime half and the offline half in a single import
namespace, every HIGH and MEDIUM finding from the two independent audits
closed, and no personal identifier or secret material in the tree.

## 1. Environment

```
$ python --version
Python 3.13.5
$ python -m pytest --version
pytest 8.x
```

The package itself requires Python 3.11 or newer and imports nothing outside
the standard library.  `mcp` and `anyio` are an optional extra (`pip install
"mcp-guard[proxy]"`), needed only to talk to an upstream MCP server.

```
$ python -c "import mcp_guard, mcp_guard.core.engine, mcp_guard.proxy; print(mcp_guard.__version__)"
1.0.0
```

## 2. The combined test suite

The suite is the union of the two upstream trees plus the two independent
audit suites.  The 24 adversarial checks that the first audit had to mark
`xfail` -- because the code did not yet satisfy them -- are now ordinary,
strictly-passing tests.

```
$ python -m pytest -q
1369 passed, 0 failed, 0 xfail, 32 skipped
```

The `xfail` count is zero.  That is the point of the exercise: an `xfail` is a
promise that a known defect is still open, and a release must not carry any.

The 32 skips are the release-artifact checks, which skip until `REPORT.md`,
`VERIFY.md`, `MANIFEST.md` and the archive exist; they run in section 5.

### The adversarial runtime suite

`tests/test_adversarial_runtime.py` is the port of the independent audit of
the 0.6.0-rc1 tree.  It drives the runtime half -- the proxy, the policy
engine, the audit chain, the canary detector, the path guard and the ReDoS
guard -- and it pins the behaviour that the audit found to be wrong.

### The adversarial scanner suite

`tests/test_adversarial_scanner.py` is the port of the independent audit of
the 0.6.0 GA release pack.  It drives the offline half -- the engine, the
plugin registry, the four plugins, the policy linter and the pin manifest.

## 3. What each finding is pinned by

| Finding | Severity | Pinned by |
| --- | --- | --- |
| Canary token written verbatim into the audit log | HIGH | `test_a_canary_token_must_not_reach_the_audit_log`, `test_a_canary_token_in_an_argument_name_must_not_reach_the_audit_log`, `test_an_encoded_canary_token_must_not_reach_the_audit_log` |
| Honeypot URI quoted in the decision reason | MEDIUM | `test_the_honeypot_uri_must_not_appear_in_the_decision_reason` |
| Violation serialisation carries the raw secret | MEDIUM | `test_the_violation_serialisation_must_not_carry_the_raw_value`, `test_the_detection_result_serialisation_must_not_carry_the_raw_value`, `test_the_violation_reports_a_fingerprint_instead_of_the_value` |
| Registered canary tokens shorter than eight characters | HIGH | `test_a_registered_token_shorter_than_eight_characters_must_be_enforced`, `test_the_engine_must_refuse_a_call_carrying_a_short_registered_token`, `test_a_token_of_exactly_eight_characters_is_enforced` |
| Encoded token smuggled past the size limit | HIGH | `test_an_encoded_token_must_be_detected_in_an_oversized_argument`, `test_the_oversized_argument_boundary_is_where_the_package_says` |
| NFKC-colliding tool rules shadow a deny | HIGH | `test_a_confusable_tool_name_finds_the_plain_rule`, `test_a_denied_tool_must_stay_denied_when_a_confusable_name_collides` |
| Undeclared arguments accepted without an `arguments:` section | MEDIUM | `test_a_rule_without_an_arguments_section_must_not_accept_anything`, `test_an_undeclared_argument_is_refused_when_arguments_are_declared` |
| Audit chain initialised without the writer lock | MEDIUM | `test_a_concurrent_writer_must_not_corrupt_the_chain` |
| JSON-RPC batch rejection raises `NameError` | MEDIUM | `test_the_batch_rejection_branch_must_not_raise_a_name_error` |
| Bounded repetition of an unbounded body accepted | HIGH | `test_a_bounded_repetition_of_an_unbounded_body_must_be_refused`, `test_a_nested_quantifier_is_refused_at_load_time` |
| Rate-limit window grows without bound | LOW | `test_the_rate_limit_window_must_stay_bounded` |
| Oversize line discarded counter drifts | LOW | `test_the_oversize_line_discard_counter_must_be_accurate` |
| Credential detected, then printed in the report | HIGH | `test_aud_detected_credential_is_masked_in_the_report`, `test_aud_every_canary_credential_pattern_is_redactable` |
| Finding metadata echoes the configured token | LOW | `test_aud_finding_metadata_is_redacted` |
| Split base64 blob evades the decoder | HIGH | `test_aud_split_base64_credential_is_still_detected` |
| Shape-normalised match fires on unrelated prose | MEDIUM | `test_aud_normalised_canary_match_does_not_fire_on_unrelated_prose` |
| `ESC c` (RIS) passes the sanitizer | MEDIUM | `test_aud_ris_sequence_is_stripped`, `test_aud_sanitize_without_control_stripping_leaves_no_escape` |
| A mis-scoped rule disables a built-in rule | MEDIUM | `test_aud_mis_scoped_rule_cannot_disable_a_builtin_rule`, `test_aud_mis_scoped_rule_with_regex_is_reported_by_the_linter` |
| An invalid plugin setting still ends in a PASS | MEDIUM | `test_aud_invalid_plugin_setting_is_rejected_at_load_time`, `test_aud_invalid_plugin_setting_does_not_end_in_a_pass_verdict` |
| A transcript can name a file the scanner opens | MEDIUM | `test_aud_transcript_metadata_cannot_open_local_files` |
| A malformed pin manifest is accepted | MEDIUM | `test_aud_malformed_pin_manifest_is_an_error` |
| The pin digest ignores the server block | MEDIUM | `test_aud_server_version_change_is_detected`, `test_aud_manifest_digest_covers_the_server_block` |
| The pin digest depends on entry order | LOW | `test_aud_manifest_digest_is_stable_across_reordering` |
| A crashing plugin reports a clean pass | HIGH | `test_aud_plugin_crash_is_not_a_pass_verdict`, `test_aud_plugin_crash_is_reported_as_at_least_a_warning` |
| An unknown plugin name is accepted | HIGH | `test_aud_unknown_plugin_name_is_rejected`, `test_aud_unknown_plugin_name_cli_does_not_exit_zero` |
| Root-anchored and drive-absolute escapes | HIGH | `test_aud_root_anchored_escape_raises_critical_path_rule`, `test_aud_drive_absolute_escape_is_not_silent` |
| Percent-encoded control characters | MEDIUM | `test_aud_percent_encoded_nul_is_flagged`, `test_aud_percent_encoded_control_is_flagged` |
| Raw arguments hidden from the plugins | MEDIUM | `test_aud_raw_arguments_path_is_not_hidden`, `test_aud_raw_arguments_ansi_is_not_hidden` |
| Custom rule matching is unbounded | MEDIUM | `test_aud_custom_rule_matching_is_bounded_in_time`, `test_aud_custom_rule_finding_count_is_capped` |

## 4. The built-in self-test

```
$ mcp-guard selftest
...
result: PASS
```

The self-test covers the runtime vectors -- the policy engine, the audit chain
and its keyed HMAC, the canary detector, the path guard, the ReDoS guard, the
budget and the rate limiter -- and the offline vectors: every one of the four
plugins (`etdi_pinning`, `ansi_sanitize`, `path_shape`, `canary_exfil`), the
default policy lint, the pin-manifest round trip and the clean and dirty
sample transcripts.

```
$ mcp-guard selftest --format json
```

reports the same run as machine-readable JSON: `vectors` carries the runtime
half, `cases` carries the plugin and engine half, and `ok` is the conjunction.

## 5. The policy linter

```
$ mcp-guard policy-lint --policy examples/policy.toml
$ mcp-guard policy-lint --policy src/mcp_guard/data/default_policy.toml
```

Both exit `0`.  The default policy ships clean: a linter finding of HIGH or
above refuses to load a policy at all, so a policy that lints clean is a
policy that loads.

## 6. The release artifacts

```
$ python tools/build_release.py
$ python -m pytest tests/scanner/test_release_pack.py -q
```

`MANIFEST.md` lists every shipped file with its size and SHA-256 digest; the
archive contains exactly those files under a single top-level directory.
`test_manifest_digests_match` re-hashes every listed file, and
`test_the_manifest_must_declare_every_file_in_the_bundle` checks that nothing
ships undeclared.

## 7. The personal-identifier scan

```
$ python check_secrets.py
0 finding(s)
$ python check_secrets.py --self-test
self-test: ok
```

`check_secrets.py` is shape-based: it looks for the *shape* of an e-mail
address, a private key, a cloud access key, a package registry token and a
home-directory path, and it never hard-codes a person's name.  RFC 2606
reserved domains (`example.com`, `example.net`, `example.org`,
`example.invalid`) are synthetic by construction and are not reported.

```
$ grep -rInE "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}" --include="*.py" --include="*.md" .
```

The only matches are RFC 2606 reserved domains used as fixtures.

## 8. Scope of this verification

This document records what was run on this tree.  It is not a claim about any
other build, any other machine, or any future commit.
