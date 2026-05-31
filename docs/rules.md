# Rules Reference & Matcher Schemas

This document describes how to write custom security rules, the supported matcher types, and their parameters.

---

## Rule YAML Schema

A rule is a single YAML block with the following fields:

| Field | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `id` | string | Yes | Unique rule identifier (e.g., `MCP-SEC-005`). |
| `title` | string | Yes | Brief description of the issue. |
| `severity` | string | Yes | Classification: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. |
| `description` | string | Yes | Detailed description of the security vulnerability. |
| `remediation` | string | Yes | Guidance on how to fix the issue. |
| `references` | list[string] | No | Reference links to OWASP, MCPLIB, or external advisories. |
| `tags` | list[string] | No | Rule tags (e.g. `secrets`, `injection`). |
| `matchers` | list[Matcher] | Yes | One or more matcher specifications. |

---

## Matcher Types

Each matcher entry inside `matchers` defines an evaluation strategy:

### 1. `regex`
Matches file contents line-by-line using regular expressions.

```yaml
matchers:
  - type: regex
    pattern: "(eval|exec)\\("
    file_types: ["py", "js"]
```

Optional `entropy_min` can be used with regex matchers. When set, the scanner evaluates the last regex capture group, or the full match if there are no capture groups, and only reports when its Shannon entropy meets the threshold.

### 2. `file_path`
Matches the scan path or file extension.

```yaml
matchers:
  - type: file_path
    pattern: "\\.env$"
```

### 3. `config_key`
Inspects configuration files (JSON) for specific executable commands, arguments, or environment variables.

```yaml
matchers:
  - type: config_key
    config_keys: ["command"]
    pattern: "^(bash|cmd)$"
```

`config_key` matchers flatten JSON/YAML objects into dotted paths, so a key such as `command` matches `mcpServers.filesystem.command`.

---

## Built-in Rules catalog

By default, `mcpguard` executes the following pre-compiled rules:

### `MCP-SEC-002` (Severity: HIGH)
- **Title**: Unicode Homoglyph / Obfuscation Detected
- **Description**: Identifies zero-width characters and directional overrides used to obfuscate code and bypass security scanning.
- **Pattern**: `[\x{200B}-\x{200D}\x{FEFF}\x{202A}-\x{202E}]`

### `MCP-SEC-004` (Severity: HIGH / CRITICAL)
- **Title**: Excessive Permissions: Raw Shell Execution & Broad System Access
- **Description**: Flags configuration files executing command lines through generic shell processes or specifying broad directories.
- **Pattern**: Command containing `bash`, `sh`, `powershell`, or argument flags matching `--allow-all`, `-A`, `/`.

### `MCP-SEC-008` (Severity: HIGH)
- **Title**: Potential Secret Leakage Detected
- **Description**: Evaluates strings mapped to secret fields or token assignments for high Shannon entropy.
- **Threshold**: Shannon Entropy $\ge 4.0$ with character length $> 12$.

### `MCP-SEC-005` (Severity: HIGH)
- **Title**: Insecure Deletion Operations
- **Description**: Detects configuration or codebase assets attempting broad database drops or filesystem deletions.
- **Pattern**: Matches patterns like `rm -rf`, `drop database`, `os.remove`, or `fs.unlink`.

### `MCP-SEC-006` (Severity: HIGH)
- **Title**: Unrestricted Network Commands
- **Description**: Flags configuration files executing broad network diagnostic or query tools like curl, wget, nmap, or netcat.
- **Pattern**: Command strings starting with `curl`, `wget`, `nc`, or `nmap`.

### `MCP-SEC-009` (Severity: CRITICAL)
- **Title**: Hardcoded Private Key Exposure
- **Description**: Identifies cryptographic private key blocks hardcoded in codebase files or configurations.
- **Pattern**: Matches the header block `-----BEGIN ... PRIVATE KEY-----`.

### `MCP-SEC-014` (Severity: HIGH)
- **Title**: Insecure Tool Description Prompt Injection Warning
- **Description**: Flags tool instructions containing phrases instructing models to ignore checks or act as administrators.
- **Pattern**: Matches phrases like `ignore previous instructions`, `jailbreak`, or `bypass safety`.
