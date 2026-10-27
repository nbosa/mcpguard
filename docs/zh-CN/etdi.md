# ETDI 格式 — mcp-guard v0.6.0

> English version: [../en/etdi.md](../en/etdi.md)

**ETDI**（Extended Tool Description & Integrity，扩展工具描述与完整性）是
mcp-guard 用于固定的描述格式。

思路很简单：工具描述是可执行内容。模型会阅读它并据此行动。它一旦变化，行为就会变化。
一个在无人察觉的情况下发生变化的工具接口就是一次完整性事故，因此 mcp-guard 会把它冻结。

## 文档结构

```json
{
  "etdi": "1.0",
  "server": {"name": "workspace", "version": "1.4.2"},
  "tools": [
    {
      "name": "read_file",
      "title": "Read file",
      "description": "Read a UTF-8 text file from the workspace.",
      "inputSchema": {
        "type": "object",
        "properties": {
          "path": {"type": "string", "description": "Workspace relative path"},
          "max_bytes": {"type": "integer"}
        },
        "required": ["path"]
      }
    }
  ]
}
```

| 字段 | 必填 | 规则 |
| --- | --- | --- |
| `etdi` | 是 | 点分版本字符串，当前为 `1.0`。 |
| `server.name` | 否 | 字符串，在清单中作为工具身份的前缀。 |
| `server.version` | 否 | 字符串。 |
| `tools` | 是 | 非空的工具描述数组。 |
| `tools[].name` | 是 | `^[A-Za-z0-9_.\-]{1,64}$`，文档内唯一。 |
| `tools[].title` | 否 | 字符串。 |
| `tools[].description` | 实际必需 | 字符串，最长 4096 字符。 |
| `tools[].inputSchema` | 否 | 类 JSON Schema 的对象，`type` 必须为 `object`。 |
| `tools[].inputSchema.properties` | 否 | 属性 schema 对象。 |
| `tools[].inputSchema.required` | 否 | 字符串数组，每一项都必须存在于 `properties` 中。 |

属性 schema 可以声明 `type`（字符串或字符串数组）、`enum`、`default` 和 `description`。

## 固定清单

```bash
mcp-guard pin-manifest create --input tools.json --output pins.json
```

```json
{
  "manifest_version": "1.0",
  "etdi_version": "1.0",
  "generator": "mcp-guard/0.6.0",
  "generated_at": "2026-01-01T00:00:00Z",
  "server": {"name": "workspace", "version": "1.4.2"},
  "tools": [
    {
      "server": "workspace",
      "tool": "read_file",
      "name": "read_file",
      "description": "Read a UTF-8 text file from the workspace.",
      "required": ["path"],
      "parameters": [
        {"name": "max_bytes", "type": "integer", "required": false},
        {"name": "path", "type": "string", "required": true}
      ],
      "schema": {"type": "object", "properties": {"...": {}}},
      "description_sha256": "…",
      "schema_sha256": "…",
      "tool_sha256": "…"
    }
  ],
  "manifest_sha256": "…"
}
```

### 摘要

所有摘要都是 **规范化 JSON**（键排序、无空白、UTF-8）上的 SHA-256：

| 摘要 | 覆盖范围 |
| --- | --- |
| `description_sha256` | 工具描述文本。 |
| `schema_sha256` | `inputSchema` 对象。 |
| `tool_sha256` | 名称 + 描述 + `inputSchema` 三者。 |
| `manifest_sha256` | 清单的整个 `tools` 数组。 |

规范化编码让摘要在不同机器、不同 Python 版本之间都可复现——同一份文档永远得到同一个哈希。

## 校验

```bash
mcp-guard pin-manifest verify --pins pins.json --input tools.json
```

比对结果有四种状态：

| 状态 | 含义 | 规则 |
| --- | --- | --- |
| `unchanged` | 工具与其固定记录一致。 | — |
| `drift` | schema、描述、必填集合或参数类型发生了变化。 | `ETDI-001`、`ETDI-004`、`ETDI-005`、`ETDI-006` |
| `added` | 出现了清单未固定的工具。 | `ETDI-002` |
| `removed` | 已固定的工具不再对外提供。 | `ETDI-003` |

`drift` 记录中会给出具体的变化类型：

| 类型 | 含义 |
| --- | --- |
| `schema` | 输入 schema 摘要发生变化。 |
| `description` | 描述发生变化。 |
| `required_added` | 某个参数变成了必填。 |
| `required_removed` | 某个参数不再是必填。 |
| `parameter_added` / `parameter_removed` | 参数集合发生变化。 |
| `type_widened` | 某参数现在接受其原有类型的超集。 |
| `type_changed` | 参数类型发生了非放宽型的变化。 |

`type_widened` 之所以被单独列出，是因为它最隐蔽：一个原本只接受 `string` 的参数
现在接受 `string | number`，schema 就这样开始接收没人审阅过的载荷了。

## 在检查中固定

```bash
mcp-guard check transcript.json --etdi tools.json --pins pins.json
```

此时固定插件会把漂移作为常规报告的一部分输出，严重级别与退出码行为完全一致。

## 推荐工作流

1. **发现。** 把工具接口导出为 ETDI 文档。
2. **审阅。** 认真阅读描述——提示词注入就藏在那里。
3. **固定。** `mcp-guard pin-manifest create`。
4. **提交。** 把清单与代码一起纳入版本管理。
5. **在 CI 中校验。** 每次构建都跑 `mcp-guard pin-manifest verify`。
   接口变化必须是一次经过审阅的提交，而不是一个意外。

永远不要自动重新固定。固定的价值就在于：每次变化都需要一个人来做决定。
