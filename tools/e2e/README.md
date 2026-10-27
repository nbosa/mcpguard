# The end-to-end proof: the same call, two guards

`e2e.py` starts the **real** `mcp-guard run` proxy in front of a
list-taking MCP server (`git_server.py`, one tool: `git_add_many(files=[...])`)
and calls it with four arguments.

The two policies differ only in what the guard can say about the elements of
the list:

* `policy-v4.yaml` -- `type: array`, `max_length: 64`: all that mcp-guard
  0.4 can express for a list.
* `policy-v5.yaml` -- the same, plus `items: {type: string, path_prefix:
  "./cases/workspace"}`.

The fixture is the corpus layout: `cases/workspace/repo-a/` is the
repository, `CANARY-ESCAPE-9f3a.txt` is one level above it.

## Running it

```bash
# the 0.4 guard (a pristine copy of the upstream tree)
python e2e.py /path/to/mcp-guard-v4 policy-v4.yaml "mcp-guard 0.4"

# the 0.5 guard (this work directory)
python e2e.py ../../src-copy policy-v5.yaml "mcp-guard 0.5"
```

The output is in `reports/e2e-v4-vs-v5.txt`.

## What it shows

```
--- mcp-guard 0.4 (type and length only -- all v4 can express) ---
  traversal in a list              ok     staged: ["../CANARY-ESCAPE-9f3a.txt"]
  safe list                        ok     staged: ["cases/workspace/repo-a/src/app.py", ...]
  traversal as the second element  ok     staged: ["cases/workspace/repo-a/src/app.py", "../CANARY-ESCAPE-9f3a.txt"]
  wrong type in a list             ok     staged: ["cases/workspace/repo-a/src/app.py", 42]

--- mcp-guard 0.5 (per-element constraint) ---
  traversal in a list              error  deny: argument 'files[0]' violates path_prefix './cases/workspace': ...
  safe list                        ok     staged: ["cases/workspace/repo-a/src/app.py", ...]
  traversal as the second element  error  deny: argument 'files[1]' violates path_prefix './cases/workspace': ...
  wrong type in a list             error  deny: argument 'files[1]' must be of type string, got int
```

`staged:` is the **upstream** speaking: under 0.4 the traversal reached the
server, which is the vulnerability.  Under 0.5 it never gets there, and the
legitimate multi-file call still works.

Nothing outside this directory is written: the proxy is started without an
audit log, and the upstream only echoes the arguments it was given.
