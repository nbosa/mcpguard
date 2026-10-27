# Contributing

Thank you for considering a contribution. This guide describes how to set the
project up, how to run the tests, and what a change is expected to look like.

## Development setup

The project needs Python 3.11 or newer. Nothing else is required to work on
the core: the scanner, the policy engine, the audit chain and every plugin
run on the standard library alone.

```bash
python -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

The `dev` extra installs the test runner and the build tooling. Add the
`proxy` extra as well if you intend to work on the runtime half:

```bash
.venv/bin/pip install -e ".[dev,proxy]"
```

The test suite imports the package from `src/`, so it runs against the
checkout without an installation and `.venv/bin/pytest` works in a bare
clone.

## Running the tests

```bash
.venv/bin/pytest
```

The suite is split into three directories, each of which can be run on its own:

```bash
.venv/bin/pytest tests/scanner   # the offline scanner and the plugins
.venv/bin/pytest tests/runtime   # the proxy, the policy engine, the audit chain
.venv/bin/pytest tests/audit     # the audit suites, written against behaviour
```

Tests that start an MCP server or a subprocess are marked `slow`. Run them
with:

```bash
.venv/bin/pytest -m slow
```

## Running the self-test

The package carries its own verification suite, which exercises the proxy, the
audit chain, the canary detector, every plugin, the default policy and the
sample transcripts:

```bash
.venv/bin/mcp-guard selftest
```

It is independent of the test suite and should pass in any installation. Add
`--verbose` to see the detail of passing cases, and `--json` for a
machine-readable report.

The repository also ships a hygiene scanner that reads the whole tree,
including itself, and reports the shape of any personal data or credential
material it finds:

```bash
.venv/bin/python check_secrets.py
.venv/bin/python check_secrets.py --self-test
```

Neither command prints the value of a finding, only the kind and a short
description of the shape.

## Code style

- Python 3.11 is the floor. Use the syntax and the standard library it
  provides; the core carries no third-party dependency.
- Every module, class and public function carries a docstring that says what
  it does and, where it is not obvious, why. The project treats the docstring
  as part of the code: it is the specification, and the tests are written
  against the behaviour it describes.
- Type annotations are expected on public functions. The code uses
  `from __future__ import annotations` and the modern union syntax.
- Keep lines within 100 characters. The existing code follows this.
- Prefer the standard library. A new dependency in the core needs a strong
  reason and a discussion; a dependency in the `proxy` extra needs less of
  one.
- Keep the two halves separate. The offline half must not import the MCP
  SDK, and the core must not import anything from `mcp_guard.proxy`.
- Security-relevant behaviour is written to fail closed. When a decision is
  uncertain, refuse it and say why.
- Do not weaken a check to make a test pass. A test that has to change
  because the behaviour changed is a normal review comment, not something to
  work around.

## Adding a rule

A rule is an entry in a plugin's built-in catalogue. The catalogue maps a
rule id to a severity, an operator-facing message and a remediation hint.

1. **Pick the id.** A rule id is made of an upper-case prefix and three
   digits, for example `PATH-012`. The prefix belongs to the plugin that owns
   the rule; a rule id is unique across the whole catalogue, and
   `policy-lint` reports a duplicate or an unknown id as an error.
2. **Add it to the plugin's `RULES` mapping.** Every entry carries at least a
   `severity` and a `message`. Add a `remediation` when the operator has
   something concrete to do about the finding.
3. **Emit it through the plugin.** Use `self.emit(findings, "PREFIX-000", ...)`
   rather than constructing a `Finding` directly, so that a policy can
   disable the rule. `emit` returns nothing when the rule is disabled, which
   is what makes `enabled = false` in a policy work.
4. **Choose the severity honestly.** `CRITICAL` and `HIGH` block a request in
   the proxy. `MEDIUM` and below are informational there, and the offline
   thresholds decide whether they fail a run.
5. **Document it.** Add the rule to the rules reference in `docs/en/rules.md`
   and in `docs/zh-CN/rules.md`.
6. **Test it.** Add a case to the plugin's test module and a case to the
   plugin's `self_test()` method, so that `mcp-guard selftest` covers it too.

## Adding a plugin

A plugin is a class that derives from `GuardPlugin`.

1. **Create the module** under `src/mcp_guard/plugins/`. Give the class a
   stable `name`, a `settings_key` when it reads its own block from the
   policy, a `version`, and a `RULES` catalogue.
2. **Implement `analyze(self, request) -> list[Finding]`.** This is the
   contract: the request carries the calls, the results and the metadata, and
   the method returns the findings. It must not raise for malformed input;
   return a finding or nothing.
3. **Implement `self_test(self) -> list[SelfTestCase]`.** Every plugin
   carries its own assertions, and `mcp-guard selftest` runs them.
4. **Register it.** Add the class to `PLUGIN_CLASSES` and add the name to
   `PLUGIN_ORDER` in `src/mcp_guard/core/registry.py`. The order is the
   evaluation order, and it runs from the cheapest, most structural check to
   the most expensive content inspection.
5. **Add its settings** to the policy model in `src/mcp_guard/core/policy.py`
   and to the built-in default, so that the setting has a default and a
   documented type.
6. **Document it.** Add the plugin to the plugin tables in both READMEs, to
   the rules reference in both languages, and to the architecture note.
7. **Test it.** Add a test module under `tests/scanner/` with a clean case
   and at least one case per rule.

## The personal-data rule

This project ships a scanner and a set of fixtures, and both are held to one
rule: **no real personal identifier may enter the repository.**

- Use the names that RFC 2606 reserves for documentation: `example.com`,
  `example.net`, `example.org` and `example.invalid`, and any name under
  them. A mail address in a fixture is `user@example.com`, never a real
  address.
- Credentials in a fixture are synthetic. Build them from fragments rather
  than pasting a value that looks real, and never reuse a value that was
  issued to anybody.
- A home directory in a fixture is a made-up path, not a real user's. The
  `check_secrets.py` scanner reports an absolute path into a home directory
  as a finding, so keep the fixtures generic.
- When you report a security issue, replace every real value in the policy,
  the transcript and the payload with a synthetic one.

Run the scanner before you open a pull request:

```bash
.venv/bin/python check_secrets.py
```

It exits with `0` when the tree is clean and `1` when it is not. The scanner
reads every text file in the repository, including itself and including the
archives, so a value that has been committed cannot hide behind a file name.

## Pull requests

- One change per pull request, with a description that says what the change
  does and why.
- The test suite passes, and `mcp-guard selftest` passes.
- `check_secrets.py` reports no finding.
- New behaviour has a test; a bug fix has a test that fails without the
  fix.
- Documentation is updated in both English and Simplified Chinese when the
  change affects the documented behaviour. The two trees carry the same set
  of files, and the test suite checks that they do.
- When the change alters a command, a flag, an exit code, a rule id or a
  default, the changelog gets an entry under the unreleased heading.
