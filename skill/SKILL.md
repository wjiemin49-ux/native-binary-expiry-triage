---
name: native-binary-expiry-triage
description: Diagnose and repair expired native-component time locks in Windows desktop apps. Use when a closed-source DLL returns a negative error code after a specific date, when an Electron/Tauri app fails to initialize a bundled native module, when logs show errors like -101 or -1000 before any database access, when a GUI opens but stays blank or unresponsive, or when you need to statically locate and extend an embedded expiry timestamp in a PE binary without running the app.
---

# Native Binary Expiry Triage

## Purpose

闭源原生组件（.dll）里常被硬编码一个**到期时刻**。到期后组件在初始化阶段直接返回负数错误码，
上层应用表现为「窗口能打开但界面空白 / 按钮无响应 / 数据库读不到」，但日志里除了一个错误码没有别的线索。

本 Skill 是这类故障的通用作业手册：目标是**在不运行目标程序的前提下静态定位到期常量**，
用最小字节改动延后它，并留下可回滚的备份与可复现的工具链。

## Core Model（先建立这个模型，再动手）

一个「原生组件到期」故障通常由**多个独立检查点**组成，只修一个不够：

| 阶段 | 典型错误码 | 编码形式 | 症状 |
|---|---|---|---|
| 组件自检 / 保护初始化 | `-101` | 32 位 epoch，立即数与当前时间比较 | 窗口能开，界面空白 |
| 引擎 / 数据库初始化 | `-1000` | `struct tm` 字段（年/月/日/时/分/秒） | 连接测试失败，读不到数据 |
| 游标 / 查询阶段 | `-100` | 另一个独立检查点 | 能列表，读不出消息 |
| 授权 / 联网校验 | 超时或失败 | 内部 HTTP 请求 | 初始化卡住不返回，CPU 空闲 |

**关键教训（来自 WeFlow #1222 实例）**：
- 修掉 `-101` 只消除第一阶段；`-1000` 是**另一处独立常量**，必须一起改。
- 报障者只改一处就宣称修好的，通常只是没走到下一阶段。
- 判断依据是**错误码 + 日志停在哪一步**，不是猜测。

## Workflow

### Step 1 — 确认是「到期」而非别的问题

1. 定位日志：`%APPDATA%\<app>\logs\` 下找带组件名的 `.log`。
2. 统计错误码出现次数与**日志最后停在哪一行**。
   - 停在 `InitProtection` / `initialize` → 第一阶段到期。
   - 停在数据库连接 / query → 已过第一阶段，卡在第二阶段。
   - **日志完全没有后续行，且进程 CPU 停止增长** → 组件在等待网络授权，不要盲目改字节。
3. 确认本机组件哈希，与公开 issue 报告者的哈希比对。
   - 哈希不同 → 公开 issue 的现成补丁**不能套用**，必须自己静态分析。

### Step 2 — 先查上游，别急着改二进制

按顺序查：
1. 官方仓库的 Releases / issue / PR，看是否已有更新组件。
2. 组件提供方是否发布了新版本与校验值（SHA-256）。
3. 项目是否已停止维护（停止维护 = 不会有官方修复，只能自行处理）。

**如果上游有正式修复，优先用官方版本，不要打补丁。** 打补丁只用于上游已死或无人回应的场景。

### Step 3 — 静态定位到期常量

用本 Skill 自带脚本（无需 objdump / IDA，纯 Node）：

```bash
node scripts/scan-expiry.js <target.dll>
```

脚本输出三类结果，其中「高置信度」两类的判据是
**人为设定的到期时刻几乎总是落在 23:59:59 / 00:00:00 且靠近月末或年末**，
而编译期随机时间戳几乎不会：

- **比较指令中的截止时间**：`cmp rax, imm32` 里的 imm32 是 epoch
- **栈上 tm 字段写入**：`mov dword ptr [rsp+X], imm` 逐字段写入 tm 结构体
- **tm 结构体数据区**：连续 6 个 int32 的静态数据

每条命中都标注了**所属导出函数名**（通过 PE 导出表 RVA 归属），
这直接告诉你该改哪个函数。

脚本还有 `--json` 模式便于程序化消费。

### Step 4 — 反汇编确认上下文

确认「这个常量确实是时间锁，而不是恰好长得像」：

```bash
npm install iced-x86   # 若未安装
```

用 iced-x86 反汇编命中点前后 ~100 字节，确认：
- 比较的确实是当前时间（`time()` / `GetSystemTimeAsFileTime` 之类调用在紧邻处）
- 超过阈值后 `mov eax, <负数错误码>` 直接返回
- 错误码与日志中实际出现的一致

这一步不能省。扫描是启发式，确认才是结论。

### Step 5 — 备份 + 打补丁

**先备份，后修改。** 备份放在**同目录**、带日期后缀，便于一眼回滚。

```bash
# 1) 生成补丁文件（不改原件）
node scripts/patch-deadline.js <in.dll> <out.dll> --cmp 0x80dc1 --epoch 2037-09-30
node scripts/patch-deadline.js <in.dll> <out.dll> --tm  0xe858d --year 2037

# 2) 备份 + 替换（需要管理员权限，用提权脚本）
#    见 references/elevated-replace.md
```

补丁工具的保守设计（刻意如此）：
- 字节级前置校验，值不像 epoch / tm_year 就中止
- 只改立即数字节，不改指令长度
- 永不原地覆盖，一律输出到新文件
- 打印完整字节级 diff

### Step 6 — 分层验证

**必须用本轮启动新写入的日志来判断**，不要读旧日志：

1. 启动应用 → 日志中**不再出现**该错误码
2. 日志推进到**下一阶段**（数据库连接 / 会话列表）
3. 实际功能验证：打开已知会话、拉取历史消息
4. 关闭重启一次，确认冷启动也正常

**停在哪一步就是下一个要修的点。** 第一阶段通过后如果卡住不动，
说明存在第三、第四个检查点（常见是联网授权），继续用同样方法定位。

### Step 7 — 沉淀

修复完成后，把这次的可复用部分沉淀为：
- 本 Skill（通用方法）
- 目标应用的本地 runbook / 配置备份
- 定期巡检（见下）

## Guardrails

- **不要改系统时间**去「验证」是否过期。这会破坏 TLS 证书校验、破坏签名验证，
  污染整个系统的可信基线，且无法真正修好组件。
- **不要清库、不要重装微信/客户端数据**。到期锁与数据无关，删数据只会造成二次损失。
- **不要在补丁前不备份。** 二进制改动不可逆，没有备份等于赌。
- **不要盲写字节。** 没有前置校验的 hex 编辑可能把 DLL 改坏，且损坏方式是
  「能加载但行为诡异」，比报错更难查。
- **改完必须重启进程**。DLL 已被进程映射，热替换无效。
- **提权时用脚本 + 日志文件**，不要用长内联命令行：提权窗口一旦被关，
  没有任何输出可查，会误判为「已执行」。

## Root Cause Patterns（跨案例的可复用认知）

这些是反复付出成本才看清的模式。新案例先对照这里，再走 Workflow。

### 1. 单一根因，多处表象
到期锁造成「界面空白 / 按钮无反应 / 数据库读不到 / 报表为空」四种表象，
根因是同一个二进制里的多个检查点。**按错误码和日志停点分层定位，不要按现象分类。**

### 2. 上游停更 = 只能自建工具链
闭源组件到期 + 官方停更 = 没有上游修复可用。此时投入应放在**通用化**上：
把一次性手工分析变成可复用脚本，下次同类故障几分钟内定位。

### 3. 公开 issue 的补丁不可直接套用
issue 报告者的 DLL 哈希与本机不同（不同版本 / 不同构建），
字节偏移完全对不上。**必须以本机哈希为准重新静态分析。**

### 4. 「修好了」需要下一阶段来证明
改完第一处只能证明「走到了下一处」。**真正的验收标准是功能跑通，
不是错误码消失。**

### 5. 卡住不动 ≠ 崩溃
进程在、窗口在、CPU 归零 = 阻塞等待（通常是网络授权）。
此时继续改字节是白费功夫，先查网络可达性。

### 6. 网络可达性排查要区分 DNS 劫持
本机代理软件（Clash / Mihomo 等）用 fake-IP 模式时，DNS 会返回 `198.18.x.x` 假地址。
直连测试必然失败，但**不代表目标站点不可达**。要绕过假 IP 验证真实可达性：

```bash
# 用 DoH 拿真实 IP
curl -s "https://dns.alidns.com/resolve?name=HOST&type=A"
# 用 --resolve 指定真实 IP 测连通性
curl -s -m 15 --resolve HOST:443:REAL_IP https://HOST/path
```

fake-IP 段（198.18.0.0/16）出现在解析结果里时，必须做这一步，否则会误判为「站点挂了」。

### 9. 自动化脚本必须自己验证自己
本 Skill 的工具链不是写完就算数，必须用**已知答案**回归：
- `scan-expiry.js` 对**未打补丁**的原始 DLL 应报出 `2026-09-30`（两处）
- 对**已打补丁**的 DLL 应报出 `2037-09-30`
- `patch-deadline.js` 的输出必须与**实际生效的补丁文件逐字节一致**（用 SHA-256 比对）

只有这样才能确信工具可信。而且要**双向测**：
只测「已修好的状态」会掩盖漏检；只测「未修状态」会掩盖误报。

### 10. 计划任务要有日志和退出码，否则等于没建
注册了不等于在跑。必须验证：
- `LastTaskResult` 为 0
- 日志文件**真的有新内容**，且**编码正确**（中文乱码会让巡检结果不可读）
- 退出码透传：0=正常，1=需处理，2=环境问题

踩过的坑：直接用 `cmd.exe /c "node x.js > log"` 时中文全乱码；
加 `chcp 65001` 后 `cmd` 的重定向行为又变了，日志干脆不生成。
最终用 **PowerShell + `ProcessStartInfo` + 显式 UTF-8 编码**才稳定。

**规则：任何定时任务，第一次注册后必须立刻试跑并检查日志内容，不要只看注册返回值。**

### 8. 扫描必然有误报，必须加代码引用校验
`.rdata` / `.pdata` 里堆着海量**恰好长得像 epoch 的字节序列**（MSVC 异常处理数据、
未初始化表、复制的代码片段）。本次在 `WCDB.dll` 里就命中过 `2027-01-30 00:00:00`——
完美符合「边界时刻」启发式，但**零个代码引用它**，纯误报。

两道过滤缺一不可：
1. **边界时刻启发式** —— 截止时刻通常落在 23:59:59 / 00:00:00 且靠近月末或年末，
   编译期随机时间戳几乎不会。（把 602 个 cmp 命中收敛到 2 个）
2. **代码引用校验** —— 遍历 `.text`，把每个 4 字节窗口当作 RIP-relative 位移，
   反查哪些常量真的被指令引用。无引用的直接丢弃。

**规则：任何静态扫描结论，都要先确认「代码确实引用它」再动手改字节。**

## Automation

### 巡检：提前发现即将到期的组件

`watch-expiry.js` 可用于定期巡检已知组件目录：

```bash
node scripts/watch-expiry.js                        # 扫描内置清单
node scripts/watch-expiry.js <dll> [<dll>...]       # 扫描指定文件
node scripts/watch-expiry.js --manifest <json>      # 自定义清单
```

输出会区分「已过期 / 90 天内到期 / 安全」，并打印每个组件的 SHA-256。
**哈希变化 = 组件换了构建 = 之前的定位失效，必须重新扫描。**

### 已落地的自动化（本机）

| 项 | 值 |
|---|---|
| 计划任务名 | `WeFlow_ExpiryWatch` |
| 频率 | 每周一 09:00 |
| 运行身份 | 最高权限（`RunLevel Highest`） |
| 日志 | `D:\tmp\watch-expiry.log` |
| 包装器 | `scripts/run-watch.ps1`（保证 UTF-8 输出与退出码透传） |
| 退出码 | 0=正常　1=有到期风险　2=环境问题 |

注册/修改任务用提权脚本（见 `references/elevated-replace.md` 的「脚本 + 日志」模式），
**不要用长内联命令行**——提权窗口被关掉时不会有任何痕迹。

### 巡检清单维护

新增受监控组件时，编辑 `scripts/manifest.json`（与 `watch-expiry.js` 同目录）：

```json
[
  {
    "app": "应用名 + 版本",
    "file": "D:/path/to/component.dll",
    "note": "用途与已知状态"
  }
]
```

`watch-expiry.js` 会自动读取该文件；不存在时回退到内置示例清单。

### 建议的定期节奏

- 每周一次：跑巡检（已自动化）
- 每次上游发版后重新核对哈希——哈希变了说明补丁失效，必须重新定位
- 应用自动更新 / 重装后**立即**重跑巡检并重新打补丁
- 在组件到期**之前**处理，不要等故障发生

## Tooling Notes

**硬性要求**：只需要 **Node.js**（建议 ≥ 18）。全部脚本纯 Node 实现，无 Python / Rust 依赖。

- 反汇编可选装 `iced-x86`（纯 WASM）：`npm install iced-x86`。
  `scan-expiry.js` 本身**不需要**它，只有要人工确认上下文时才用。
- `dumpbin` / `llvm-objdump` 等只作为可选的人工辅助。
- **Node 可能不在系统 PATH 里**（例如装在 `D:\app\node.exe`）。
  脚本内用绝对路径调用；`run-watch.ps1` 会依次探测 PATH、`D:\app\node.exe`、
  `C:\Program Files\nodejs\node.exe`、`%LOCALAPPDATA%\Programs\nodejs\node.exe`，
  也可用 `-NodePath` 显式指定。
- **不要依赖 bash 路径**：Git 的安装位置各不相同（如 `D:\app\Git`）。
  计划任务一律用 `run-watch.ps1` 包装器——它同时解决 UTF-8 输出问题。
- 应用安装目录通常只有 `Administrators` / `SYSTEM` 可写，普通用户会话改不了，需提权。

## Files

```
native-binary-expiry-triage/
├── SKILL.md
├── scripts/
│   ├── scan-expiry.js      # 静态定位截止时间锁（含误报过滤）
│   ├── patch-deadline.js   # 生成补丁（带前置校验，不原地覆盖）
│   ├── watch-expiry.js     # 巡检（纯 Node，可被计划任务调用）
│   ├── run-watch.ps1       # 计划任务包装器（UTF-8 + 退出码透传）
│   ├── manifest.json       # 受监控组件清单
│   └── watch-expiry.sh     # bash 版巡检（手动用）
└── references/
    ├── elevated-replace.md # 提权替换安装目录文件
    └── weflow-case.md      # 完整案例：WeFlow -101 / -1000 双检查点
```

## Installation

复制 `skill/` 目录到 Claude Code 的 skills 目录即可：

```bash
# Linux / macOS
cp -r skill ~/.claude/skills/native-binary-expiry-triage

# Windows
xcopy /E /I skill "%USERPROFILE%\.claude\skills\native-binary-expiry-triage"
```

然后按需编辑 `scripts/manifest.json` 填入你要监控的组件。

## References

- `references/elevated-replace.md` — 提权替换安装目录文件的可靠做法
- `references/weflow-case.md` — 完整案例记录：WeFlow 5.0.0 的 -101 / -1000 双检查点
