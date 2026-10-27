# 规则目录 — mcp-guard v0.6.0

> English version: [../en/rules.md](../en/rules.md)

mcp-guard 内置 **38 条规则**，分布在四个插件中。每条规则都有稳定的编号、默认严重级别、
修复建议，并且可以在策略中被启用、禁用、调整级别或替换文案。

严重级别由低到高：`INFO`、`LOW`、`MEDIUM`、`HIGH`、`CRITICAL`。

## ETDI 固定（`etdi_pinning`）

| 规则 | 级别 | 含义 |
| --- | --- | --- |
| `ETDI-001` | CRITICAL | 工具输入 schema 相对固定清单发生漂移。 |
| `ETDI-002` | HIGH | 对外公布的工具不在固定清单覆盖范围内。 |
| `ETDI-003` | HIGH | 已固定的工具从对外接口中消失。 |
| `ETDI-004` | MEDIUM | 工具描述自固定以来发生变化。 |
| `ETDI-005` | CRITICAL | 工具新增了必填参数。 |
| `ETDI-006` | HIGH | 工具参数类型被放宽。 |
| `ETDI-007` | HIGH | ETDI 文档格式错误或不可用。 |
| `ETDI-008` | MEDIUM | 固定清单缺失或版本不匹配。 |
| `ETDI-009` | LOW | 固定清单摘要与其内容不匹配。 |
| `ETDI-010` | CRITICAL | 服务器标识或版本自固定以来发生变化。 |

**说明。** `ETDI-001` 与 `ETDI-005` 是最关键的两条：输入 schema 变化或新增必填参数
会改变智能体实际发出的内容，因此会改变行为。`ETDI-004`（描述漂移）是提示词注入的
入口——描述是被模型阅读的，而不是被解析器阅读的。

## ANSI 清洗（`ansi_sanitize`）

| 规则 | 级别 | 含义 |
| --- | --- | --- |
| `ANSI-001` | MEDIUM | 工具输出中发现 ANSI 转义序列。 |
| `ANSI-002` | HIGH | 发现 OSC 序列（标题或超链接伪装）。 |
| `ANSI-003` | CRITICAL | 发现 OSC 52 剪贴板写入序列。 |
| `ANSI-004` | MEDIUM | 发现光标 / 屏幕控制序列。 |
| `ANSI-005` | HIGH | 发现隐藏或被覆盖的文本（退格、回车、CSI 8）。 |
| `ANSI-006` | HIGH | 发现双向文本控制字符（Trojan Source）。 |
| `ANSI-007` | MEDIUM | 输出中发现原始控制字符。 |
| `ANSI-008` | LOW | 输出超过 `settings.ansi.max_output_chars`，将被截断。 |

**说明。** `ANSI-003` 之所以是 critical，是因为 OSC 52 会静默替换操作员的剪贴板，
这是经典的「复制这段再粘贴」陷阱。`ANSI-005` 覆盖的是「显示为 A、实际包含 B」的情况：
`visible\x08\x08\x08hidden` 和 `harmless\r\x1b[2K\rreal` 都会隐藏内容。

## 路径形态（`path_shape`）

| 规则 | 级别 | 含义 |
| --- | --- | --- |
| `PATH-001` | CRITICAL | 路径逃逸出 home / 基础目录。 |
| `PATH-002` | CRITICAL | 路径指向敏感的凭据位置。 |
| `PATH-003` | HIGH | 路径使用了设备命名空间（`\\.\`）或 UNC。 |
| `PATH-004` | HIGH | 路径把穿越藏在百分号编码之后。 |
| `PATH-005` | HIGH | 路径使用了 NTFS 备用数据流（`file:stream`）。 |
| `PATH-006` | HIGH | 路径使用了 Windows 保留设备名（`CON`、`NUL`、`COM1`）。 |
| `PATH-007` | MEDIUM | 路径指向系统位置（`/etc`、`/proc` 等）。 |
| `PATH-008` | MEDIUM | 路径中包含控制字符或 NUL 字节。 |
| `PATH-009` | MEDIUM | 路径是驱动器相对路径（`C:foo`）。 |
| `PATH-010` | LOW | 路径使用了结尾点或结尾空格的混淆手法。 |
| `PATH-011` | HIGH | 路径不在 `settings.path.allowed_roots` 之内。 |

**说明。** `PATH-001` 对 `~/.ssh/../../etc/passwd` 以及 `../../etc/passwd` 这类
相对穿越都会触发（相对路径以基础目录衡量，默认是 home 目录）。

`PATH-010` 覆盖 `report.txt.` 和 `report.txt `——在 Windows 上它们与 `report.txt`
指向同一个文件，因此仅按扩展名放行的策略会被绕过。

URL **不是**路径：`https://example.invalid/a` 不会被路径规则检查（但仍会被金丝雀规则扫描）。

## 金丝雀外泄（`canary_exfil`）

| 规则 | 级别 | 含义 |
| --- | --- | --- |
| `CANARY-001` | CRITICAL | 载荷中检测到已配置的金丝雀标记。 |
| `CANARY-002` | CRITICAL | 检测到金丝雀形态的标记（`CANARY-XXXX-XXXX`）。 |
| `CANARY-003` | CRITICAL | 载荷中检测到凭据材料。 |
| `CANARY-004` | HIGH | 载荷中检测到高熵数据块。 |
| `CANARY-005` | MEDIUM | 检测到类 JWT 标记。 |
| `CANARY-006` | HIGH | 检测到内嵌凭据的 URL。 |
| `CANARY-007` | HIGH | 检测到环境或凭据转储迹象。 |
| `CANARY-008` | CRITICAL | 金丝雀标记被发送给了具备外发能力的工具。 |
| `CANARY-009` | HIGH | 某个 base64 数据块解码后是凭据材料。 |
| `CANARY-010` | HIGH | 工具返回了金丝雀标记。 |

**说明。** `CANARY-008` 是最锐利的信号：工具名出现在
`settings.canary.egress_tools` 中，而外发参数里带着金丝雀标记。这是带证据的操纵，
不是启发式猜测。

`CANARY-004` 是启发式规则，也是最容易误报的一条。它的阈值是
`settings.canary.entropy_threshold`（香农熵，默认 `4.2`）和
`settings.canary.min_blob_len`（默认 `40`）。如果在你的语料上过于吵闹，
可以提高阈值或降低级别。

## 自定义规则

策略可以添加自己的规则。带 `regex` 的规则由引擎按照配置的 `target` 求值：

```toml
[[rule]]
id = "CUSTOM-001"
plugin = "custom"
severity = "HIGH"
regex = "\\b[a-z0-9-]+\\.corp\\.internal\\b"
target = "any"
message = "载荷中引用了内部主机名"
```

| `target` | 求值对象 |
| --- | --- |
| `any`（默认） | 调用参数、返回内容与 transcript |
| `arguments` / `calls` | 仅调用参数 |
| `content` / `results` | 仅返回内容 |
| `transcript` | 仅 transcript |

自定义规则在插件之后执行，其发现项同样会被脱敏和截断。

## 覆盖规则

```toml
[[rule]]
id = "PATH-007"
plugin = "path_shape"
severity = "HIGH"
message = "Path targets a system location"

[[rule]]
id = "ANSI-001"
plugin = "ansi_sanitize"
enabled = false
```

覆盖项必须指明该规则所属的插件；当编号对该插件未知且未提供 `regex` 时，
`policy-lint` 会报告 `POL-006`。
