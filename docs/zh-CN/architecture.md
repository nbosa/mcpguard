# 架构说明 — mcp-guard v0.6.0

> English version: [../en/architecture.md](../en/architecture.md)

## 1. 设计目标

mcp-guard 围绕五条约束构建：

1. **一个引擎，多种能力。** 防护逻辑放在插件里，引擎只负责编排。增加一种能力
   永远不需要改动引擎。
2. **确定性。** 同样的输入始终产生相同的发现项、相同的顺序、相同的编号。
   审计需要可复现性。
3. **无副作用。** 不访问文件系统、不联网、不做 `stat`、不解析符号链接。
   护栏必须能够安全地处理恶意输入。
4. **策略驱动。** 严重级别、阈值、启用的规则和插件行为都是数据，而不是代码。
5. **崩溃不会变成盲区。** 抛出异常的插件会被转换成 `ENGINE-000` 发现项，
   审计链不会被静默截断。

## 2. 包结构

```
src/mcp_guard/
├── __init__.py            对外 API 再导出
├── __main__.py            `python -m mcp_guard`
├── version.py             版本唯一来源
├── core/
│   ├── severity.py        有序严重级别模型
│   ├── result.py          Finding / Verdict / CheckReport
│   ├── request.py         ToolCall / ToolResult / CheckRequest
│   ├── textutil.py        规范化 JSON、哈希、熵
│   ├── redact.py          证据脱敏
│   ├── policy.py          策略模型 + TOML 加载器
│   ├── lint.py            策略校验器
│   ├── plugin.py          插件基类、规则解析
│   ├── registry.py        插件注册表
│   ├── engine.py          GuardEngine
│   ├── etdi.py            ETDI 文档 schema
│   ├── manifest.py        ETDI 固定清单
│   └── samples.py         内置示例载荷
├── plugins/
│   ├── etdi_pinning.py
│   ├── ansi_sanitize.py
│   ├── path_shape.py
│   └── canary_exfil.py
├── cli/
│   ├── main.py            argparse 分发器
│   ├── common.py          CLI 公共辅助
│   ├── output.py          渲染与退出码
│   └── cmd_*.py           每个子命令一个模块
└── data/
    └── default_policy.toml
```

除 `registry.py` 之外，`core/` 从不导入 `plugins/`；插件之间也从不互相导入。
依赖关系因此是一棵树。

## 3. 请求模型

一次防护运行可能检查的一切，都会被归一化成 `CheckRequest`：

```python
@dataclass
class CheckRequest:
    agent: str
    calls: list[ToolCall]      # 智能体 -> 工具调用
    results: list[ToolResult]  # 工具 -> 智能体载荷
    transcript: str            # 自由文本
    metadata: dict             # etdi、pins、egress_tools 等
```

`CheckRequest.from_dict()` 接受多种 transcript 写法：

| 输入 | 含义 |
| --- | --- |
| `calls` / `tool_calls` | 工具调用 |
| `results` / `tool_results` | 工具返回内容 |
| `messages` | 折叠进 `transcript` |
| `metadata.etdi`、`metadata.pins` | ETDI 文档与固定清单 |
| `metadata.etdi_path`、`metadata.pins_path` | 同上，但从磁盘读取 |

保持单一归一化形态，意味着插件永远不需要知道载荷来自哪里。

## 4. 引擎

```python
engine = GuardEngine(policy=policy)          # 默认策略
engine = GuardEngine(policy=policy, plugin_names=["path_shape"])
report = engine.check(CheckRequest.from_dict(document))
```

`GuardEngine.check()` 分为五步：

1. **运行插件。** 每个插件返回 `Finding` 列表，异常会被捕获并转成 `ENGINE-000`。
2. **运行自定义规则。** 声明了 `regex` 的策略规则会根据 `target` 对调用参数、
   返回内容和 transcript 求值。
3. **脱敏。** 证据经过 `core.redact.redact()`，已知凭据会被替换成 `<redacted:kind>`。
4. **截断。** 证据长度上限为 `settings.max_evidence_chars`，控制字符会被转义，
   保证报告可以安全打印。
5. **判定。** 最高严重级别达到 `fail_on` 判定 `FAIL`，达到 `warn_on` 判定 `WARN`，
   否则为 `PASS`。

发现项按严重级别降序、再按插件、再按规则编号排序——顺序稳定，两次运行之间可以直接 diff。

## 5. 插件契约

```python
class GuardPlugin:
    name: str            # "path_shape"
    settings_key: str    # "path"，对应 [settings.path] 策略块
    version: str
    RULES: dict[str, dict]   # 规则目录

    def analyze(self, request) -> list[Finding]: ...
    def self_test(self) -> list[SelfTestCase]: ...
```

每个插件自带一份规则目录：

```python
RULES = {
    "PATH-001": {
        "severity": "CRITICAL",
        "message": "Path escapes the home/base directory",
        "remediation": "Confine filesystem access to the working tree; ...",
    },
}
```

同 id 的策略覆盖项会替换 `enabled`、`severity` 和 `message`。
插件拿不到策略的原始结构，它只会请求一条已解析的规则：

```python
rule = self.rule("PATH-001")
if not rule.enabled:
    return []
```

`self.emit(findings, "PATH-001", evidence=..., location=...)` 会用解析后的严重级别
构造发现项；规则被禁用时返回 `None`，因此插件代码可以保持简洁。

### 设置项查找

`settings_key` 把插件名与策略块名解耦：`path_shape` 读取 `[settings.path]`，
`etdi_pinning` 读取 `[settings.etdi]`。`Policy.plugin_settings()` 两种写法都接受，
调用方不必知道插件内部用的是哪一种。

## 6. 新增一个插件

1. 新建 `src/mcp_guard/plugins/<name>.py`，继承 `GuardPlugin`。
2. 声明 `name`、`settings_key`、`version` 和 `RULES`。
3. 实现 `analyze()`。
4. 在 `core/registry.py` 注册（`PLUGIN_CLASSES` 与 `PLUGIN_ORDER`）。
5. 在默认策略中增加 `[settings.<key>]` 块。
6. 编写测试，并实现 `self_test()` 方法。

引擎、CLI 和校验器会自动识别它。`policy-lint` 从插件目录中获知新的规则编号，
因此引用了不存在规则的覆盖项会被 `POL-006` 捕获。

## 7. 典型 CI 运行的数据流

```
$ mcp-guard check transcript.json --format json
  │
  ├─ 解析 transcript            core/request.py
  ├─ 加载策略                   core/policy.py
  ├─ 运行 4 个插件              plugins/*.py
  ├─ 运行自定义规则             core/engine.py
  ├─ 脱敏 + 截断                core/redact.py, core/textutil.py
  ├─ 计算结论                   core/engine.py
  └─ 渲染 + 退出码              cli/output.py
```

结论为 `FAIL` 时退出码为 `1`，因此该命令可以直接当作 CI 门禁使用。
