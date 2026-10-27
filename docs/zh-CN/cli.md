# CLI 参考 — mcp-guard v0.6.0

> English version: [../en/cli.md](../en/cli.md)

```
mcp-guard <命令> [选项]
```

| 退出码 | 含义 |
| --- | --- |
| `0` | 成功——没有阻断性发现项。 |
| `1` | 发现项达到策略阈值。 |
| `2` | 用法错误、输入不可读或内部失败。 |

所有命令都支持 `--format text`（默认）和 `--format json`。

---

## `mcp-guard check`

对 transcript 运行所有已启用的插件。

```
mcp-guard check [TARGET] [--policy PATH] [--fail-on LEVEL]
                            [--pins PATH] [--etdi PATH]
                            [--plugin NAME]... [--format text|json] [--quiet]
```

| 选项 | 说明 |
| --- | --- |
| `TARGET` | JSON transcript 路径，或 `-` 表示标准输入（默认）。 |
| `--policy PATH` | 策略文件；不指定则使用内置默认策略。 |
| `--fail-on LEVEL` | 本次运行覆盖 `settings.fail_on`。 |
| `--pins PATH` | 用于校验工具接口的 ETDI 固定清单。 |
| `--etdi PATH` | 描述线上工具接口的 ETDI 文档。 |
| `--plugin NAME` | 只运行指定插件，可重复。 |
| `--quiet` | 只打印结论。 |

**transcript 格式。**

```json
{
  "agent": "release-bot",
  "calls":   [{"server": "workspace", "tool": "read_file", "arguments": {"path": "a.txt"}}],
  "results": [{"server": "workspace", "tool": "read_file", "content": "..."}],
  "transcript": "自由文本",
  "metadata": {"etdi": {...}, "pins": {...}}
}
```

也接受 `tool_calls` / `tool_results` / `messages` 作为别名。

**文本输出。**

```
policy: mcp-guard-default (0.6.0)
verdict: FAIL  (max severity: CRITICAL)
findings: 3

  [CRITICAL] PATH-001 (path_shape): Path escapes the home/base directory
      location: calls[0].arguments.path
      evidence: ../../.ssh/id_rsa
      fix: Confine filesystem access to the working tree; reject upward traversal.
```

**JSON 输出。** 一个 `CheckReport`：`verdict`、`policy`、`summary`
（`total`、`max_severity`、`by_severity`、`by_plugin`）、`stats` 以及 `findings`。
每条发现项包含 `rule_id`、`plugin`、`severity`、`message`、`evidence`、
`location`、`remediation` 和 `metadata`。

---

## `mcp-guard policy-lint`

在依赖某个策略之前先校验它。

```
mcp-guard policy-lint [POLICY] [--strict] [--format text|json]
```

| 选项 | 说明 |
| --- | --- |
| `POLICY` | 策略文件；不指定则校验内置默认策略。 |
| `--strict` | 把警告当作错误（退出码 `1`）。 |

报告会给出结构性问题（`POL-0xx`）以及语义问题，例如未知插件（`POL-007`）
或未知规则编号（`POL-006`）。

---

## `mcp-guard selftest`

运行产品内置的验证套件，无需任何外部输入。

```
mcp-guard selftest [--verbose] [--format text|json]
```

它会执行每个插件的 `self_test()`、校验默认策略、往返验证固定清单，
并确认干净 transcript 通过、恶意 transcript 失败。任一用例失败即退出 `1`。

---

## `mcp-guard pin-manifest`

管理工具接口的冻结指纹。

```
mcp-guard pin-manifest create --input TOOLS [--output PINS] [--generated-at TS]
mcp-guard pin-manifest verify --pins PINS --input TOOLS [--format text|json]
mcp-guard pin-manifest show   --pins PINS [--format text|json]
```

| 动作 | 说明 |
| --- | --- |
| `create` | 根据 ETDI 文档生成固定清单。 |
| `verify` | 用线上 ETDI 文档与固定清单做比对。 |
| `show` | 打印固定清单内容。 |

`--input -` 表示从标准输入读取 ETDI 文档。当接口发生漂移、增加工具或丢失工具时，
`verify` 会退出 `1`。

---

## `mcp-guard sanitize-output`

在渲染载荷之前清除终端转义序列。

```
mcp-guard sanitize-output [FILE] [--keep-ansi] [--keep-control] [--keep-bidi]
                          [--max-chars N] [--fail-on-change] [--format text|json]
```

| 选项 | 说明 |
| --- | --- |
| `FILE` | 载荷文件，或 `-` 表示标准输入（默认）。 |
| `--keep-ansi` | 保留 ANSI 转义序列。 |
| `--keep-control` | 保留残留的 C0 控制字符。 |
| `--keep-bidi` | 保留双向覆盖字符。 |
| `--max-chars N` | 截断清洗后的输出。 |
| `--fail-on-change` | 载荷被修改时退出 `1`。 |

它会移除 ANSI 转义序列（CSI、OSC、DCS 及其 8 位形式），解析退格与回车造成的
覆盖欺骗，并清除双向覆盖字符。

---

## `mcp-guard canary-check`

扫描载荷中的金丝雀标记与凭据材料。

```
mcp-guard canary-check [FILE] [--policy PATH] [--token TOKEN]... [--format text|json]
```

| 选项 | 说明 |
| --- | --- |
| `FILE` | 载荷文件，或 `-` 表示标准输入（默认）。 |
| `--policy PATH` | 策略文件（默认使用内置策略）。 |
| `--token TOKEN` | 额外要查找的金丝雀标记，可重复。 |

载荷被当作**外发**内容处理。命中已配置的标记产生 `CANARY-001`，
命中通用 `CANARY-XXXX-XXXX` 形态产生 `CANARY-002`，命中凭据产生 `CANARY-003`。

---

## 流水线用法

```bash
# 智能体偏离策略时让 CI 失败。
mcp-guard check transcript.json --policy examples/policy.toml || exit 1

# 确认服务端暴露的接口仍是我们固定的那份。
mcp-guard pin-manifest verify --pins pins.json --input live-tools.json

# 打印到共享终端前先清洗。
tool-output | mcp-guard sanitize-output

# 往环境中注入金丝雀，并断言它永远不会离开。
mcp-guard canary-check --token "$CANARY" --policy policy.toml < outgoing.json
```
