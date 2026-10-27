# mcp-guard

面向 Model Context Protocol（MCP）智能体的安全护栏与运行时代理。

`mcp-guard` 由两半组成，两者共享同一套策略模型、同一份规则目录和同一个
严重级别标尺：

- **运行时**：`mcp-guard proxy` 位于 MCP 客户端与上游 MCP 服务器之间。它
  决定哪些工具调用可以放行、拒绝哪些不允许的调用，并把每一个决定写入可
  验证篡改的审计日志。
- **离线**：`mcp-guard check` 用同一批护栏插件扫描已录制的会话记录，因此
  无需启动服务器就能用已知流量检验策略。

核心包**没有任何外部运行时依赖**：Python 3.11 加标准库就足以运行扫描器、
策略引擎、审计链和全部插件。`proxy` 这个附加依赖组只额外引入 MCP SDK，
且仅运行时一半需要它。

## 安装

```bash
pip install mcp-guard          # 仅离线一半，只依赖标准库
pip install "mcp-guard[proxy]" # 同时包含运行时一半
```

安装后会提供一个命令行程序 `mcp-guard`。下面的示例都假定它已经在
`PATH` 中。

## 运行时一半

把代理放在上游服务器前面。`--` 之后的内容就是上游命令：

```bash
mcp-guard proxy --policy examples/policy.toml --audit audit.jsonl -- \
    python -m my_upstream_server
```

代理在标准输入输出上启动一个 MCP 服务器，把客户端的握手转交给上游，然
后接管之后的每一个请求。遇到 `tools/call` 时，它会先用策略评估工具名和
参数，评估通过之后请求才会到达上游。被拒绝的调用不会离开本机，拒绝的决
定同样会写进审计日志。

策略是一份 YAML 文档，最小示例如下：

```yaml
version: "1.0"
rules:
  - id: allow-read
    tool: read_file
    action: allow
    arguments:
      path:
        type: string
        required: true
        max_length: 512
  - id: deny-everything-else
    action: deny
```

策略中没有列出的工具一律拒绝。因此策略描述的是智能体被允许做什么的完整
清单，而不是在开放默认值之上补几条例外。

### 审计日志

每个决定对应一条 JSON Lines 记录。每条记录都带上前一条记录的 SHA-256 摘
要，并且在配置了密钥时还会带上针对自身内容的带密钥 HMAC。被改写、删除或
调换顺序的记录都会破坏这条链，链可以用另一个命令独立验证：

```bash
mcp-guard keygen --out audit.key
mcp-guard verify-audit audit.jsonl --audit-key-file audit.key
```

`verify-audit` 给出五种结果之一：`OK`（验证通过）、`BROKEN`（哈希链不
成立）、`WARN`（链成立但没有任何带密钥的签名）、`KEY`（日志带密钥但密
钥未知）以及 `REFUSED`（在要求带密钥日志的位置发现了旧式的无密钥日志）。
密钥可以轮换到新文件，而不必重写日志：

```bash
mcp-guard rotate-key --audit audit.jsonl --new-key-file audit.key
```

### ETDI 固定

今天展示出来的工具界面，明天可能已经是另一个界面了。`mcp-guard
pin-manifest` 会把一次工具列表的指纹固定下来，此后代理一旦发现列表已经
偏离固定值就会拒绝提供：

```bash
mcp-guard pin-manifest create --input examples/etdi-tools.json --output pins.json
mcp-guard pin-manifest verify --pins pins.json --input examples/etdi-tools.json
```

偏离被记为 `CRITICAL`，因此会直接阻断请求，而不只是给出警告。

## 离线一半

扫描器读取一份会话记录文档（调用、结果以及自由文本），并在上面运行护栏
插件：

```bash
mcp-guard check examples/transcript.json --policy examples/policy.toml
mcp-guard check examples/transcript.json --format json
```

会话记录是 JSON 文档，包含一个 `calls` 数组、一个可选的 `results` 数组和
一个可选的 `transcript` 字符串；备选名称 `tool_calls`、`tool_results` 和
`messages` 同样被接受。具体结构见
[`examples/transcript.json`](examples/transcript.json)。

策略在投入使用之前可以先做检查：

```bash
mcp-guard policy-lint examples/policy.toml
```

`policy-lint` 把 YAML 文件当作运行时策略读取，把 TOML 文件当作离线扫描
策略读取。它会报告结构性和语义上的问题——未知配置项、重复的规则编号、
没有任何插件拥有的规则编号、非法严重级别、非法正则表达式——每种问题都有
稳定的错误码。

另外两个专用命令补全了离线一半。`sanitize-output` 会从载荷中清除终端转
义序列、覆写技巧和双向覆盖字符，这正是让智能体输出可以安全打印到终端的
前提：

```bash
mcp-guard sanitize-output payload.txt --fail-on-change
```

`canary-check` 在载荷中查找金丝雀令牌和蜜罐地址，从而在已经录制的流量中
也能发现泄漏：

```bash
mcp-guard canary-check payload.txt --token "CANARY-XXXX-XXXX"
```

最后，`mcp-guard selftest` 会走一遍代理、审计链、金丝雀探测器、每一个插
件、默认策略以及示例会话记录。它是确认安装是否可用的最快方式。

## 插件

实际执行检查的是四个插件。离线扫描器和代理使用的是同一批插件对象：前者
把它们跑在会话记录上，后者把它们跑在实时流量上。

| 插件 | 规则编号 | 检查目标 |
| --- | --- | --- |
| `etdi_pinning` | `ETDI-001` 至 `ETDI-009` | 已经偏离固定清单的工具界面。 |
| `ansi_sanitize` | `ANSI-001` 至 `ANSI-008` | 终端转义序列、覆写技巧、双向覆盖字符以及其他控制字符。 |
| `path_shape` | `PATH-001` 至 `PATH-011` | 逃出工作目录、或指向凭据材料的路径。 |
| `canary_exfil` | `CANARY-001` 至 `CANARY-010` | 金丝雀令牌、编码后的数据块、URL 中的凭据等外泄迹象。 |

每条结论都带有一个严重级别，取值来自固定的 `INFO`、`LOW`、`MEDIUM`、
`HIGH`、`CRITICAL` 标尺。界线由策略决定：内置默认值在 `HIGH` 级别让运行
失败、在 `MEDIUM` 级别给出警告，而在策略里写 `fail_on = "MEDIUM"` 会让
判定更严格。完整的规则目录见[规则参考](docs/zh-CN/rules.md)。

插件的运行顺序是固定的——先固定值，后内容检查——因为已经发生漂移的工具
值得在查看它的参数之前就被拒绝。

## 命令一览

| 命令 | 作用 |
| --- | --- |
| `mcp-guard proxy` | 在上游 MCP 服务器前运行执行策略的代理。 |
| `mcp-guard check` | 检查会话记录是否违反策略。 |
| `mcp-guard policy-lint` | 校验策略文件。 |
| `mcp-guard selftest` | 运行内置验证套件。 |
| `mcp-guard pin-manifest` | 创建、验证或查看 ETDI 固定清单。 |
| `mcp-guard sanitize-output` | 从载荷中清除终端转义序列。 |
| `mcp-guard canary-check` | 在载荷中查找金丝雀令牌。 |
| `mcp-guard verify-audit` | 验证审计日志的哈希链和带密钥 HMAC 链。 |
| `mcp-guard rotate-key` | 把审计日志的密钥轮换到新的密钥文件。 |
| `mcp-guard keygen` | 创建一个新的审计链密钥文件。 |

`run`、`verify` 和 `verify-log` 仍然可用，分别是 `proxy` 和
`verify-audit` 的别名。

整个命令行共用一套退出码：`0` 表示成功，`1` 表示发现了策略违规或审计
链断裂，`2` 表示用法错误或输入不可读，`3` 表示审计日志无法完成认证。完
整列表见[命令行参考](docs/zh-CN/cli.md)。

## 默认策略

内置的默认策略偏保守，它的设计目的是被复制而不是被直接使用。它在
`HIGH` 级别失败、在 `MEDIUM` 级别警告、从证据中隐去凭据材料，并把下列
内容视为敏感：诸如 `.ssh`、`.aws`、`.gnupg`、`.kube`、`.docker` 之类的目录
名；诸如 `id_rsa`、`.env`、`*.pem` 之类的文件名；以及 `/etc`、`/proc`、
`/sys`、`/dev`、`/boot`、`/var/run`、`/var/log`、`/root` 这些系统前缀。

与内置默认策略对应的策略文件随包分发为
`src/mcp_guard/data/default_policy.toml`；[策略参考](docs/zh-CN/policy.md)
说明了每一个配置项。

仓库里随附三份可直接使用的策略：[`examples/policy.toml`](examples/policy.toml)
把所有路径限制在一个根目录下并在 `MEDIUM` 级别失败；
[`examples/policy.default-deny.yaml`](examples/policy.default-deny.yaml)
只放行一组指名的工具；[`examples/policy.list-paths.yaml`](examples/policy.list-paths.yaml)
允许列出但不允许读取。

## 安全

代理执行策略引擎、阻断金丝雀令牌外泄、防护策略自身正则表达式引发的拒绝
服务、约束工具可以指名的路径，并写出可验证的审计链。[安全模型](SECURITY.md)
说明了这套机制覆盖什么、不覆盖什么，[安全指南](docs/zh-CN/security.md)
描述运维方面的内容。

报告漏洞的方式见 [SECURITY.md](SECURITY.md) 中的报告一节。

## 文档

| 主题 | 英文 | 简体中文 |
| --- | --- | --- |
| 架构 | [docs/en/architecture.md](docs/en/architecture.md) | [docs/zh-CN/architecture.md](docs/zh-CN/architecture.md) |
| 规则 | [docs/en/rules.md](docs/en/rules.md) | [docs/zh-CN/rules.md](docs/zh-CN/rules.md) |
| 命令行 | [docs/en/cli.md](docs/en/cli.md) | [docs/zh-CN/cli.md](docs/zh-CN/cli.md) |
| 策略 | [docs/en/policy.md](docs/en/policy.md) | [docs/zh-CN/policy.md](docs/zh-CN/policy.md) |
| ETDI 固定 | [docs/en/etdi.md](docs/en/etdi.md) | [docs/zh-CN/etdi.md](docs/zh-CN/etdi.md) |
| 安全 | [docs/en/security.md](docs/en/security.md) | [docs/zh-CN/security.md](docs/zh-CN/security.md) |

两半的统一架构描述在 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) 中。

## 开发

```bash
python -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
.venv/bin/mcp-guard selftest
```

测试套件在没有安装的情况下也能直接对检出目录运行，因此在裸克隆中
`.venv/bin/pytest` 同样有效。贡献指南（包括新增规则或插件的流程）见
[CONTRIBUTING.md](CONTRIBUTING.md)。

## 许可证

MIT，见 [LICENSE](LICENSE)。

包的元数据在 [pyproject.toml](pyproject.toml) 中。
