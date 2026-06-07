# mcpguard Live View — Usage Report

`mcpguard view` tails the JSONL report written by `mcpguard proxy` and serves
a real-time HTML viewer at `http://127.0.0.1:7337`. New findings appear in
the browser as the proxy writes them, with no build step, no external assets,
and no JavaScript framework — a single embedded HTML file in a 12MB Go binary.

## 1. Empty state — waiting for the first finding

The viewer starts empty with a hint to run the proxy with
`--proxy-report <path>`. The header shows a live indicator (green dot), a
zero-findings count, and a path pill on the right. `clear`, `autoscroll`, and
`pause` controls sit in the toolbar.

![Empty state](screenshots/01-empty-state.png)

## 2. Single CRITICAL finding — a rug pull

The first finding is a CRITICAL rug pull, blocked by the proxy. The card has
a red left border, red `CRITICAL` and `BLOCKED` badges, the classifier name,
JSON-RPC location, request id, and the evidence that triggered the detection
(added tool `shell_exec`, removed tool `search`).

![Single CRITICAL](screenshots/02-single-critical.png)

## 3. Two findings — CRITICAL upstream + HIGH client

A second finding arrives: a HIGH-severity prompt injection in the client-side
`tools/call` parameters (the classic "ignore all previous instructions"
pattern). Note the colour difference between the two cards — the rug pull is
red, the prompt injection is amber — and the direction tags distinguish
upstream-to-client (server-side threats) from client-to-upstream (user-driven
threats).

![Two findings](screenshots/03-two-findings.png)

## 4. Mixed severities — INFO PASSED, MEDIUM/HIGH/CRITICAL BLOCKED

After appending a handful of additional findings, the view shows the full
severity palette. Note the `info` card is the only one with a green `PASSED`
badge: the proxy was not actually configured to block this event (it is a
lifecycle event, not a threat). Everything else is blocked.

![Mixed severities](screenshots/04-mixed-severities.png)

## 5. Realistic threat — Unicode obfuscation (CRITICAL)

A more sophisticated prompt-injection attempt that uses Unicode zero-width
characters to hide payload bytes. The classifier names it explicitly
("Obfuscated Unicode zero-width characters in payload") so the user can
understand what tripped the rule. The CRITICAL badge is reserved for
patterns that, by themselves, are diagnostic of an attack.

![Unicode obfuscation](screenshots/05-unicode-obfuscation.png)

## 6. Load test — sustained stream of findings

Appending 25 findings in a tight loop stresses the SSE path: every event is
streamed to the browser within one poll interval (200ms) and rendered as a
new card. The header count updates live, autoscroll keeps the latest card
visible, and the page never blocks the proxy's writing process.

![Load test](screenshots/06-load-test.png)

## Operating notes

| Behaviour | Detail |
| :--- | :--- |
| Polling interval | 200 ms (`view.PollInterval` configurable) |
| Replay on connect | Last 1,000 events re-sent to new clients |
| File truncation | Detected via inode + size diff; offset resets |
| Per-client buffer | 128 SSE events (`view.SSEBufferSize`); slow clients drop oldest |
| Multiple tabs | Each tab is an independent SSE consumer |
| Authentication | None — bind on `127.0.0.1` only by default |

## Quick start

```bash
# Terminal 1
mcpguard proxy --upstream-command node --upstream-arg server.js \
  --proxy-report /tmp/mcpguard.jsonl

# Terminal 2
mcpguard view --report /tmp/mcpguard.jsonl
# → http://127.0.0.1:7337
```

Flags:

```text
--report string   path to the proxy JSONL report file (required)
--port    int     HTTP listen port (default 7337)
--no-browser      suppress the open-browser hint
```

Endpoints:

| Path | Description |
| :--- | :--- |
| `GET /` | Single-page HTML viewer |
| `GET /events` | Server-Sent Events stream of `hello` + `finding` events |
| `GET /healthz` | Liveness probe (`200 ok`) |

## Reproducing these screenshots

The screenshots were captured on a Linux VM (Ubuntu 22.04, XFCE, VNC) by:

1. Starting `mcpguard view --report /tmp/shoot_report.jsonl --port 7399 --no-browser`
2. Launching Firefox via `screen -dmS shoot` and navigating to
   `http://127.0.0.1:7399/` with `xdotool`
3. Appending JSONL finding lines to the report file with `echo >>`
4. Taking a screenshot per state with `import -window root` (ImageMagick)

The full reproducer is `/tmp/shoot_firefox.sh` on the VM.
