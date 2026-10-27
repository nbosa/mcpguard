# 策略参考 — mcp-guard v0.6.0

> English version: [../en/policy.md](../en/policy.md)

策略是 TOML 文档，包含三个部分：`[meta]`、`[settings]` 和 `[[rule]]`。
内置默认策略位于 `src/mcp_guard/data/default_policy.toml`，可以直接复制作为起点。

```bash
mcp-guard policy-lint my-policy.toml
mcp-guard check transcript.json --policy my-policy.toml
```

## `[meta]`

| 键 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `name` | string | 是 | 策略名称。 |
| `version` | string | 否 | 策略版本，期望使用语义化版本。 |
| `locale` | string | 否 | 面向操作员的消息语言标签。 |

## `[settings]`

| 键 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `fail_on` | severity | `HIGH` | 达到该级别的发现项会让本次运行失败。 |
| `warn_on` | severity | `MEDIUM` | 达到该级别的发现项产生警告。 |
| `redact_evidence` | bool | `true` | 对证据中的凭据材料脱敏。 |
| `max_evidence_chars` | int | `240` | 证据的最大长度。 |
| `strict` | bool | `true` | 把未知设置当作错误处理。 |

严重级别取值：`INFO`、`LOW`、`MEDIUM`、`HIGH`、`CRITICAL`。

## `[settings.etdi]`

| 键 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `require_pins` | bool | `true` | 存在 ETDI 文档时要求提供固定清单。 |
| `fail_on_drift` | bool | `true` | 把漂移报告为 `CRITICAL` 而不是 `MEDIUM`。 |
| `allow_unpinned` | bool | `false` | 容忍未固定的已公布工具。 |

## `[settings.path]`

| 键 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `sensitive_names` | list[string] | 见默认策略 | 表明凭据材料的目录名。 |
| `sensitive_files` | list[string] | 见默认策略 | 凭据文件名的 glob 模式。 |
| `system_prefixes` | list[string] | 见默认策略 | 表明主机侦察的绝对路径前缀。 |
| `allowed_roots` | list[string] | `[]` | 非空时，每个路径都必须位于这些根目录之下。 |
| `sensitive_root` | string | `"~"` | 判定「路径逃逸」的基准目录。 |

## `[settings.ansi]`

| 键 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `allow_ansi` | bool | `false` | 保留 ANSI 转义序列。 |
| `max_output_chars` | int | `100000` | 截断过长的载荷；`0` 表示关闭。 |
| `strip_control_chars` | bool | `true` | 移除残留的 C0 控制字符。 |
| `detect_bidi` | bool | `true` | 检测双向文本覆盖。 |

## `[settings.canary]`

| 键 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `tokens` | list[string] | `[]` | 埋在环境中的金丝雀标记。 |
| `egress_tools` | list[string] | 见默认策略 | 能够把数据送出环境的工具。 |
| `entropy_threshold` | float | `4.2` | 每字符香农熵超过该值即视为「已编码」。 |
| `min_blob_len` | int | `40` | 应用熵分析前的最小数据块长度。 |
| `scan_results` | bool | `true` | 同时扫描工具返回内容，而不只是调用参数。 |
| `block_on_match` | bool | `true` | 把金丝雀命中当作 `CRITICAL`。 |

### 外发（egress）如何判定

当工具名或 `server.tool` 名出现在 `egress_tools` 中，或者请求元数据在
`egress_tools` 中列出该工具时，该工具调用被视为**外发**。
外发调用中出现金丝雀会记为 `CANARY-008`（critical），而不是 `CANARY-001`。

### 金丝雀如何匹配

1. **完全匹配** —— 标记原样出现在载荷中。
2. **忽略大小写** —— 标记以不同大小写出现。
3. **形态归一化** —— 分隔符不同的标记也能命中（`CANARY-AB12-CD34` 可以匹配
   `CANARY_AB12_CD34` 和 `canaryab12cd34`）。

## `[[rule]]`

| 键 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `id` | string | 必填 | 规则编号，例如 `PATH-001`，需匹配 `[A-Z][A-Z0-9_]*-\d{3}`。 |
| `plugin` | string | 必填 | 该规则所属的插件，或 `custom`。 |
| `enabled` | bool | `true` | 启用或禁用该规则。 |
| `severity` | severity | 插件默认值 | 覆盖严重级别。 |
| `message` | string | 插件默认值 | 覆盖面向操作员的消息。 |
| `regex` | string | — | `custom` 规则要匹配的模式。 |
| `target` | string | `any` | regex 的求值对象。 |
| `description` | string | — | 自由文本备注。 |

### 示例

```toml
# 升级某条规则的级别。
[[rule]]
id = "PATH-007"
plugin = "path_shape"
severity = "HIGH"

# 关闭某条规则。
[[rule]]
id = "ANSI-001"
plugin = "ansi_sanitize"
enabled = false

# 添加自定义规则。
[[rule]]
id = "CUSTOM-001"
plugin = "custom"
severity = "HIGH"
regex = "\\b[a-z0-9-]+\\.corp\\.internal\\b"
target = "any"
message = "载荷中引用了内部主机名"
```

## 校验代码

| 代码 | 级别 | 含义 |
| --- | --- | --- |
| `POL-000` | CRITICAL | 文档不是合法 TOML / 不是表结构。 |
| `POL-001` | LOW | 未知的顶层键或规则键。 |
| `POL-002` | LOW | 未知的设置键。 |
| `POL-003` | HIGH | 缺少 `[meta] name`。 |
| `POL-004` | CRITICAL | 非法严重级别取值。 |
| `POL-005` | CRITICAL | 规则编号重复。 |
| `POL-006` | CRITICAL | 该插件不认识这个规则编号。 |
| `POL-007` | CRITICAL | 未知插件。 |
| `POL-008` | CRITICAL | 非法正则表达式。 |
| `POL-009` | CRITICAL | 缺少规则编号。 |
| `POL-010` | CRITICAL | 缺少规则所属插件。 |
| `POL-011` | LOW | `warn_on` 比 `fail_on` 更严格。 |
| `POL-012` | LOW | `meta.version` 不是语义化版本。 |
| `POL-013` | HIGH | 设置项类型错误或取值越界。 |
| `POL-014` | HIGH | 规则编号不符合预期格式。 |
| `POL-015` | HIGH | 未知的规则 target。 |
| `POL-016` | LOW | 内置规则编号被复用于自定义正则。 |
| `POL-017` | LOW | `settings.canary.tokens` 为空。 |
