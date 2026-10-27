# The mcp-guard demo

A complete, reproducible walkthrough: a real MCP client talks to a real
`mcp-guard` process, which talks to a real MCP server that would happily do
anything it is asked to.

```
demo/client.py  ──stdio──▶  mcp-guard  ──stdio──▶  demo/danger_server.py
                            (policy)                  (read_file, run_shell,
                                                        send_email)
```

## Setup

Run everything from the **root of the repository**, with the virtual
environment activated:

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

`demo/client.py` puts `src/` on the `PYTHONPATH` of the proxy it starts, so it
also works without installing the package.

The demo writes its audit log to `demo/audit.jsonl`.  Start from a clean slate
so the record counts below are the ones you see:

```bash
rm -f demo/audit.jsonl demo/audit.jsonl.keyed
```

Every walkthrough below prints the same three line warning on stderr, because
no audit key is configured: the demo log is an **unkeyed legacy chain**, which
detects an edited file but not a *rewritten* one.  [The keyed
walkthrough](#the-keyed-audit-log) at the end of this file shows what changes
with `mcp-guard keygen`.

## (a) An allowed call

`read_file` is allowed, but only for paths inside `./demo/sandbox`.

```bash
python demo/client.py --policy demo/policy.yaml --audit demo/audit.jsonl --legacy-unkeyed \
    --tool read_file --args '{"path": "demo/sandbox/hello.txt"}'
```

stdout:

```
STATUS: ok
CONTENT: hello from the mcp-guard sandbox
```

stderr:

```
mcp-guard: no audit key is configured, so the audit log is an UNKEYED legacy chain: a full
rewrite with recomputed hashes will NOT be detected. Configure --audit-key-file (or
MCP_GUARD_AUDIT_KEY) for an HMAC chained log.
```

The call was forwarded to `demo/danger_server.py`, which read the file.

## (b) A denied path traversal

The same tool, a path that leaves the sandbox.  The proxy normalises the path
(`..` is resolved) and refuses it.  The upstream is never reached.

```bash
python demo/client.py --policy demo/policy.yaml --audit demo/audit.jsonl --legacy-unkeyed \
    --tool read_file --args '{"path": "../../etc/passwd"}'
```

stdout:

```
STATUS: error
ERROR_CODE: deny
ERROR_MESSAGE: deny: argument 'path' violates path_prefix './demo/sandbox': path '../../etc/passwd' resolves outside the allowed prefix './demo/sandbox'
```

stderr:

```
mcp-guard: no audit key is configured, so the audit log is an UNKEYED legacy chain: a full
rewrite with recomputed hashes will NOT be detected. Configure --audit-key-file (or
MCP_GUARD_AUDIT_KEY) for an HMAC chained log.
```

An absolute path is refused for the same reason, with a different reason
string:

```bash
python demo/client.py --policy demo/policy.yaml --audit demo/audit.jsonl --legacy-unkeyed \
    --tool read_file --args '{"path": "/etc/passwd"}'
```

```
STATUS: error
ERROR_CODE: deny
ERROR_MESSAGE: deny: argument 'path' violates path_prefix './demo/sandbox': absolute path '/etc/passwd' is not allowed: the policy prefix './demo/sandbox' is relative
```

## (c) A denied tool

`run_shell` is denied by the policy, so it is never called.

```bash
python demo/client.py --policy demo/policy.yaml --audit demo/audit.jsonl --legacy-unkeyed \
    --tool run_shell --args '{"cmd": "rm -rf /"}'
```

stdout:

```
STATUS: error
ERROR_CODE: deny
ERROR_MESSAGE: deny: shell access is not permitted by policy
```

stderr:

```
mcp-guard: no audit key is configured, so the audit log is an UNKEYED legacy chain: a full
rewrite with recomputed hashes will NOT be detected. Configure --audit-key-file (or
MCP_GUARD_AUDIT_KEY) for an HMAC chained log.
```

## (d) A call that needs an approval

`send_email` is allowed, but it requires an explicit approval.  The proxy
answers with the stable error code `approval_required` and does **not** forward
the call.

```bash
python demo/client.py --policy demo/policy.yaml --audit demo/audit.jsonl --legacy-unkeyed \
    --tool send_email --args '{"to": "someone@example.com", "body": "hello"}'
```

stdout:

```
STATUS: error
ERROR_CODE: approval_required
ERROR_MESSAGE: approval_required: outbound e-mail needs an explicit approval
```

stderr:

```
mcp-guard: no audit key is configured, so the audit log is an UNKEYED legacy chain: a full
rewrite with recomputed hashes will NOT be detected. Configure --audit-key-file (or
MCP_GUARD_AUDIT_KEY) for an HMAC chained log.
```

## (e) The tool list is filtered

The client asks which tools exist.  `run_shell` is denied by the policy, so it
is not advertised at all -- the client never learns that it exists.
`send_email` stays visible, because it is reachable: it is the *call* that
needs the approval.

```bash
python demo/client.py --policy demo/policy.yaml --audit demo/audit.jsonl --legacy-unkeyed --list
```

stdout:

```
TOOLS: read_file, send_email
```

stderr:

```
mcp-guard: no audit key is configured, so the audit log is an UNKEYED legacy chain: a full
rewrite with recomputed hashes will NOT be detected. Configure --audit-key-file (or
MCP_GUARD_AUDIT_KEY) for an HMAC chained log.
```

## The audit log

Every decision above is in `demo/audit.jsonl`.  The file in the repository,
`demo/audit-sample.jsonl`, is the log of one allowed `read_file` call, so the
output below is the same on every machine:

```bash
mcp-guard verify demo/audit-sample.jsonl
```

```
REFUSED: legacy unkeyed chain: 2 record(s) verified, hash chain intact, but not one record carries
a MAC or a key id: ...
```

That is exit `3`, and it is the point of 0.4: an unkeyed log authenticates
nothing, so `verify` refuses it unless you ask for it:

```bash
mcp-guard verify demo/audit-sample.jsonl --allow-legacy
```

```
OK: 2 record(s) verified, hash chain intact
```

(on stderr: a reminder that this log has no MAC and that a full rewrite with
recomputed hashes is not detectable.)

(`mcp-guard verify-log` is still accepted as the old name of the command.)

The two records are the call itself and the tool list the client asked for:

```json
{"arguments":{"path":"demo/sandbox/hello.txt"},"decision":"allow","hash":"c18b60cd095c130b2f257ee55bb8cf963a64ff4c7caff5c2093ec9edf8efa192","method":"tools/call","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","reason":"reading inside the demo sandbox is allowed","session_id":"84fb482b2c303cd7992a01f6ce82f635","timestamp":"2026-10-18T09:17:11.103466Z","tool_name":"read_file","upstream_latency_ms":6.171}
{"arguments":{"advertised":["read_file","send_email"],"hidden":["run_shell"]},"decision":"allow","hash":"b84b6a1d17ce2d63c8a50f065ac2c187c4f9b206f0b633fe6d91765ae79cef00","method":"tools/list","prev_hash":"c18b60cd095c130b2f257ee55bb8cf963a64ff4c7caff5c2093ec9edf8efa192","reason":"advertised 2 tool(s), hid 1 tool(s) denied by policy","session_id":"84fb482b2c303cd7992a01f6ce82f635","timestamp":"2026-10-18T09:17:11.107578Z","tool_name":null,"upstream_latency_ms":1.811}
```

### Tampering is detected

Change a single byte and the chain no longer verifies:

```bash
cp demo/audit-sample.jsonl /tmp/tampered.jsonl
python - <<'PY'
from pathlib import Path
p = Path("/tmp/tampered.jsonl")
data = p.read_bytes()
index = data.index(b"hello.txt")
p.write_bytes(data[:index] + b"H" + data[index + 1:])
PY
mcp-guard verify /tmp/tampered.jsonl
```

```
BROKEN: line 1: hash 'c18b60cd095c130b2f257ee55bb8cf963a64ff4c7caff5c2093ec9edf8efa192' does not match the recomputed hash '60f924099b99d4b003ce3373c8ea995020ba4013a809c80186865f5f132bede1'
```

The exit code is `1`.  The proxy itself refuses to append to a log whose chain
does not verify.

## The keyed audit log

The sample log above is an **unkeyed** chain: it catches a byte that was
flipped, but an attacker who rewrites the *whole file* can recompute every
hash and the result looks untouched.  With a key, that stops working.

```bash
mcp-guard keygen --out /tmp/demo-audit.key
# wrote a new audit key to /tmp/demo-audit.key (mode 0600, key id 5e841c6f2b5d411d)
# the key itself is never printed and never written to the audit log

python demo/client.py --policy demo/policy.yaml --audit /tmp/demo-audit.jsonl \
    --audit-key-file /tmp/demo-audit.key \
    --tool read_file --args '{"path": "demo/sandbox/hello.txt"}'
```

stdout:

```
STATUS: ok
CONTENT: hello from the mcp-guard sandbox
```

stderr: *(empty -- there is a key, so there is nothing to warn about)*

The log now carries an HMAC-SHA256 per record, plus the clean-shutdown
checkpoint:

```bash
mcp-guard verify /tmp/demo-audit.jsonl --audit-key-file /tmp/demo-audit.key
```

```
OK: 2 record(s) verified, HMAC-SHA256 chain intact, key 5e841c6f2b5d411d, 1 checkpoint(s), 0 rotation(s)
```

Rewriting the log is no longer enough.  Change every decision and recompute
every unkeyed hash:

```bash
python - <<'PY'
import json
from pathlib import Path
from mcp_guard.audit import compute_hash
records = [json.loads(l) for l in Path("/tmp/demo-audit.jsonl").read_text().splitlines()]
previous = "0" * 64
for record in records:
    record["reason"] = "everything is fine"
    record["prev_hash"] = previous
    checkpoint = record.get("checkpoint")
    if isinstance(checkpoint, dict):
        checkpoint["hash"] = previous
    record["hash"] = compute_hash(record)
    previous = record["hash"]
Path("/tmp/rewritten.jsonl").write_text(
    "\n".join(json.dumps(r, sort_keys=True, separators=(",", ":")) for r in records) + "\n")
PY
mcp-guard verify /tmp/rewritten.jsonl --audit-key-file /tmp/demo-audit.key; echo "exit=$?"
```

```
BROKEN: line 1: mac 'd7a0260d9858132dac91125f2bb41d5ee605739492bb0cb7ff68f4fb7a97c48f' does not match the recomputed mac 'b82c74584b5deecdc78ed21567efb8692beb126661147ae0d0efd21a29b65782' under key '5e841c6f2b5d411d': the record was modified, or the log was rebuilt without the key
exit=1
```

The unkeyed chain in that rewritten file is perfect -- every `hash` is the
SHA-256 of its own record and every `prev_hash` points at its predecessor.  It
is the MAC that cannot be forged without the key.

(The two MAC values above depend on the run, because every record carries a
timestamp; the verdict, the line number and the exit code do not.  The
`audit-sample.jsonl` numbers earlier in this file are fixed because that log is
committed to the repository.)

## Running the proxy by hand

`demo/client.py` is only a convenience.  The proxy is an ordinary stdio
server, so a real MCP client can be pointed at it:

```bash
mcp-guard run --policy demo/policy.yaml --ttl 300 --audit demo/audit.jsonl \
    --audit-key-file /tmp/demo-audit.key \
    -- python demo/danger_server.py
```

The command after the `--` is the upstream server.  In a real MCP client
configuration this looks like:

```json
{
  "mcpServers": {
    "files": {
      "command": "mcp-guard",
      "args": [
        "run", "--policy", "/etc/mcp-guard/policy.yaml",
        "--ttl", "3600", "--audit", "/var/log/mcp-guard/audit.jsonl",
        "--audit-key-file", "/etc/mcp-guard/audit.key",
        "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/srv/data"
      ]
    }
  }
}
```
