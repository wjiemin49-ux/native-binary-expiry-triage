# native-binary-expiry-triage

闭源原生组件（Windows `.dll`）里被硬编码的**到期时间锁**诊断与修复工具包。

当一个 Electron / Tauri / 原生桌面应用突然「窗口能开但界面空白、按钮无响应、
数据库读不到」，而日志里只有一个负数错误码（如 `-101`）时，
十有八九就是撞上了组件内置的到期检查。

本仓库提供一套**纯静态**的工具链：在不运行目标程序的前提下定位到期常量、
用最小字节改动延后它、并配套定期巡检避免再次踩中。

---

## 快速开始

```bash
# 1. 扫描组件，找出截止时间常量
node skill/scripts/scan-expiry.js /path/to/component.dll

# 2. 生成补丁（不改原件）
node skill/scripts/patch-deadline.js component.dll patched.dll --cmp 0x80dc1 --epoch 2037-09-30
node skill/scripts/patch-deadline.js component.dll patched.dll --tm  0xe858d --year 2037

# 3. 巡检（可接入计划任务）
node skill/scripts/watch-expiry.js
```

作为 Code Assistant Skill 使用：

```bash
cp -r skill ~/.claude/skills/native-binary-expiry-triage
```

**唯一硬性依赖是 Node.js（≥ 18）**，不需要 Python、IDA、objdump 或任何逆向工具。

---

## 核心认知

一个「组件到期」故障通常由**多个独立检查点**组成，只修一个不够：

| 阶段 | 典型错误码 | 二进制中的编码 | 症状 |
|---|---|---|---|
| 组件自检 | `-101` | 32 位 epoch 立即数 | 窗口能开，界面空白 |
| 引擎/数据库初始化 | `-1000` | `struct tm` 字段 | 连接测试失败 |
| 查询/游标 | `-100` | 又一个独立常量 | 能列表，读不出消息 |
| 联网授权 | 超时 | 内部 HTTP 请求 | 初始化卡住，CPU 归零 |

**判断依据是「错误码 + 日志停在哪一步」，不是表象。**

---

## 工具

### `scan-expiry.js` — 静态定位截止时间锁

纯 Node 解析 PE 结构，识别三类模式：

1. **比较指令中的截止时间** — `cmp rax, imm32` 的立即数
2. **栈上 `tm` 字段写入** — `mov dword ptr [rsp+X], imm` 逐字段写入 `struct tm`
3. **`tm` 结构体数据区** — 连续 6 个 int32

每条命中标注**所属导出函数名**（通过 PE 导出表 RVA 归属），直接告诉你该改哪里。

**两道降噪机制**（缺一不可）：

- **边界时刻启发式** — 人工设定的截止时刻几乎总是 `23:59:59` / `00:00:00`
  且靠近月末或年末；编译期随机时间戳几乎不会。实测把 602 个 cmp 命中收敛到 2 个。
- **代码引用校验** — 遍历 `.text` 把每个 4 字节窗口当作 RIP-relative 位移，
  反查常量是否真被指令引用。`.rdata` / `.pdata` 里堆着海量**恰好长得像 epoch**
  的字节序列，不做这步会得到大量误报。

### `patch-deadline.js` — 生成补丁

刻意保守的设计：

- **字节级前置校验** — 值不像 epoch / `tm_year` 直接中止，绝不盲写
- **只改立即数字节** — 不改指令长度，不动代码流
- **永不原地覆盖** — 一律输出到新文件
- **打印完整字节级 diff**

### `watch-expiry.js` / `run-watch.ps1` — 巡检

扫描受监控清单，区分「已过期 / 90 天内到期 / 安全」，并打印每个组件的 SHA-256。

**哈希变化 = 组件换了构建 = 之前的定位失效，必须重新扫描。**

`run-watch.ps1` 是给 Windows 计划任务用的包装器，保证 UTF-8 输出与退出码透传。

---

## 典型工作流

1. **确认是「到期」而非别的问题** — 看日志错误码与最后停在哪一行
2. **先查上游** — 有官方修复就用官方版本，打补丁只用于上游已死的情况
3. **比哈希** — 与公开 issue 报告者的哈希不同则**不能套用**其补丁，必须自己分析
4. **静态定位** — `scan-expiry.js`
5. **反汇编确认** — 确认常量确实被比较、错误码与日志一致
6. **备份 + 打补丁** — 改前必须有备份
7. **分层验证** — 用**本轮启动新写入的日志**判断，不读旧日志
8. **沉淀** — 把巡检自动化

---

## 硬性约束

- **不要改系统时间**去「验证」是否过期 —— 会破坏 TLS 证书校验与签名验证，
  污染整个系统的可信基线，且修不好组件
- **不要清库、不要重装数据** —— 到期锁与数据无关，删数据只会造成二次损失
- **不要盲写字节** —— 没有前置校验的 hex 编辑可能把 DLL 改坏，
  且损坏方式是「能加载但行为诡异」，比报错更难查
- **改完必须重启进程** —— DLL 已被映射，热替换无效
- **提权用脚本 + 日志** —— 不要用长内联命令行，提权窗口被关时不会有任何痕迹

---

## 真实案例

完整案例见 [`skill/references/weflow-case.md`](skill/references/weflow-case.md)。

WeFlow 5.0.0（Windows）撞上 `2026-09-30T23:59:59Z` 到期，
组件内两个独立检查点同时失效：

- `InitProtection` — epoch 比较 → `-101`
- `wcdb_init` — `struct tm` 比较 → `-1000`

**改动 4 个字节**（`0x80dc2/3/4` + `0xe858d`）修复，数据库读取恢复正常。

案例文档还记录了 5 条走过的弯路，以及它们如何转化为本仓库的规则——
包括 fake-IP 代理环境把「站点不可达」误判成「站点挂了」这类隐蔽陷阱。

---

## 目录结构

```
native-binary-expiry-triage/
├── README.md
├── LICENSE
└── skill/
    ├── SKILL.md                # 完整作业手册
    ├── scripts/
    │   ├── scan-expiry.js
    │   ├── patch-deadline.js
    │   ├── watch-expiry.js
    │   ├── run-watch.ps1
    │   ├── manifest.json
    │   └── watch-expiry.sh
    └── references/
        ├── elevated-replace.md
        └── weflow-case.md      # 完整案例
```

---

## 相关链接

- 仓库地址：https://github.com/wjiemin49-ux/native-binary-expiry-triage
- [WeFlow #1222](https://github.com/hicccc77/WeFlow/issues/1222) — 同一根因的上游报告
- [WeFlow #47](https://github.com/hicccc77/WeFlow/issues/47) — 更晚阶段的游标问题

---

## 免责声明

本工具用于**诊断和修复你自己拥有或已获授权的软件**中已过期的组件。
延长组件的试用期可能违反软件许可协议，请自行确认合规性后再使用。
