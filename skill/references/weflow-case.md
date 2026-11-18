# 案例：WeFlow 5.0.0 的 -101 / -1000 双检查点

本案例是本 Skill 的来源。完整记录了「一个表象背后两个独立检查点」的定位过程，
以及过程中几次走错的弯路——那些弯路正是本 Skill 里「Root Cause Patterns」的来源。

## 环境

- Windows x64，WeFlow 5.0.0，安装于 `D:\app\WeFlow\`
- 主组件：`D:\app\WeFlow\resources\resources\wcdb\win32\x64\wcdb_api.dll`
- 微信数据根目录：`D:\me\xwechat_files`
- 日志：`%APPDATA%\weflow\logs\wcdb.log`

## 症状

窗口能打开，但界面空白、按钮无响应、读不到聊天记录。
日志里反复出现：

```
[bootstrap] InitProtection rc=-101 path=D:\app\WeFlow\resources\resources\wcdb\win32\x64
...
[bootstrap] InitProtection failed finalCode=-101
```

## 关键对照

本机主 DLL SHA-256：`6397760DA70DE8062829FBE6A2EC01CF0616D6F2B334E6FE54873898F38F7AD7`

与公开 issue #1222 报告者的哈希 `9b4957fe...` **不同**，
且与 v4.4.5 报告者的 `B6C2441A...` 也不同。

**结论：公开 issue 里的现成补丁不能套用，偏移全对不上，必须自己静态分析。**

## 上游状态

- WeFlow 仓库 Releases 为空，标签 `250` 的说明写明「无限期停止更新」
- issue #1222 被作者关闭并标记为 #1221 的重复项，未给技术说明
- PR #1223 只调整错误提示文案，不改原生组件

**没有官方修复可用，只能自行处理。**

## 静态分析结论

DLL 内有两个**独立**的到期检查点：

### 检查点 1 — InitProtection，epoch 立即数

文件偏移 `0x80dc1`，RVA `0x819bf`：

```asm
0x819b9: call qword ptr [114DE0h]      ; 取当前时间
0x819bf: cmp  rax, 0x6ABDA27F          ; 2026-09-30T23:59:59Z
0x819c5: jle  0x819D1
0x819c7: mov  eax, 0xFFFFFF9B          ; -101
0x819cc: add  rsp, 28h
0x819d0: ret
```

### 检查点 2 — wcdb_init，tm 结构体

文件偏移 `0xe858d`，RVA `0xe9189`。不是连续数据区，而是 MSVC 逐字段写栈：

```asm
mov dword ptr [rsp+6Ch], 7Eh   ; tm_year = 126 → 2026
mov dword ptr [rsp+68h], 8     ; tm_mon  = 9 (10月, 0基)
mov dword ptr [rsp+64h], 1Eh   ; tm_mday = 30
mov dword ptr [rsp+60h], 17h   ; tm_hour = 23
mov dword ptr [rsp+5Ch], 3Bh   ; tm_min  = 59
mov dword ptr [rsp+58h], 3Bh   ; tm_sec  = 59
```

同一函数内还有 `mov eax, 0xFFFFFC18`（-1000）返回点，RVA `0xe8706`。

**两处截止时刻完全相同：2026-09-30T23:59:59Z。**
只改检查点 1 会让 `-101` 消失，然后撞上 `-1000`——这正是 #1222 报告者强调的要点。

### 工具验证

`scan-expiry.js` 自动定位结果与手工分析逐字节吻合：

```
-- 高置信度: 比较指令中的截止时间 (2) --
  off=0x80dbf rva=0x819bf cmp rax, imm32 2137967999 (2037-09-30T23:59:59.000Z)  ← InitProtection
  off=0x80dc0 rva=0x819c0 cmp eax, imm32 2137967999 (2037-09-30T23:59:59.000Z)  ← InitProtection

-- 高置信度: 栈上 tm 字段写入 (1 / 共 1) --
  off=0xe8589 rva=0xe9189 tm=2037-09-30T23:59:59.000Z year_field=0xe858d  ← wcdb_init
```

（脚本在已打补丁的 DLL 上跑，所以显示的是 2037；原值为 2026。）

## 补丁

改动 **4 个字节**：

| 偏移 | 原值 | 新值 | 含义 |
|---|---|---|---|
| `0x80dc2` | `a2` | `cd` | epoch 低字节 |
| `0x80dc3` | `bd` | `6e` | epoch |
| `0x80dc4` | `6a` | `7f` | epoch 高字节（`0x6ABDA27F` → `0x7F6ECD7F`） |
| `0xe858d` | `7e` | `89` | `tm_year` 126 → 137（2026 → 2037） |

补丁后 SHA-256：`74C96063FE619A84C9AB665C7D7D4FCF4EA1DEF866EA5197B407983A858BF175`

DLL 未做 Authenticode 签名（`Get-AuthenticodeSignature` → `NotSigned`），
所以打补丁不会导致签名失效。

## 踩过的弯路（都变成了 Skill 里的规则）

### 弯路 1 — 误以为公开 issue 的补丁能直接用
issue 给了「4 个字节不同」的描述，很想直接套。但哈希不同 → 偏移不同 → 直接套会改坏 DLL。
**规则：先比哈希，不同就自己分析。**

### 弯路 2 — 只改了一处就以为修好了
`-101` 消失 ≠ 修好了。日志推进到下一阶段才会暴露 `-1000`。
**规则：验收标准是功能跑通，不是错误码消失。**

### 弯路 3 — 补丁后卡住不返回，误判为补丁失败
改完补丁后 `InitProtection` 不再返回 -101，但也不返回，一直卡着。CPU 短暂上升后归零。

排查过程：
- 网络连接检查：WeFlow 进程**没有任何对外套接字**
- 线程状态：全部 `Wait / UserRequest`
- DLL 内字符串发现 `https://api.weflow.top/api/token` 等三个 URL，且导入 `WINHTTP.dll`
- 怀疑是联网授权校验

**最终结论：这不是补丁的问题。** 用户后来自己重启了应用，一切正常——
真正卡住的原因是首次运行时代理软件尚未就绪 / DNS fake-IP 劫持导致授权请求无法完成。

**规则：卡住不动 ≠ 崩溃。CPU 归零 + 进程存活 = 阻塞等待，先查网络可达性，别继续改字节。**

### 弯路 4 — 被 fake-IP 误导，误判「站点挂了」
`nslookup api.weflow.top` 返回 `198.18.1.158`——这是 Clash/mihomo 的 fake-IP 段。
直连必然超时，但目标站点其实可达。

绕过方法：用 DoH 拿真实 IP 再测。

```bash
curl -s "https://dns.alidns.com/resolve?name=api.weflow.top&type=A"
# → {"Answer":[{"data":"13.54.62.80"}]}

curl -s -m 15 --resolve api.weflow.top:443:13.54.62.80 https://api.weflow.top/api/token
```

**规则：看到 198.18.x.x 就先意识到 fake-IP，必须用真实 IP 复测。**

### 弯路 5 — 提权内联命令失败无痕迹
第一次用长内联 `Start-Process ... -ArgumentList '-Command', '...'` 提权，
命令跑完无输出，文件哈希没变。无法判断是 UAC 被拒还是命令本身有 bug。

改成「脚本文件 + 日志文件」后，立刻能从日志看出每一步成功与否。

**规则：提权永远用脚本 + 日志，且日志要写 `=== done ===` 结束标记。**

## 最终验证

补丁后重启，日志推进到：

```
[bootstrap] InitProtection call path=...\wcdb\win32\x64
[bootstrap] open accountDir=D:\me\xwechat_files\<wxid_xxxx> dbStorage=...\db_storage
[bootstrap] open sessionDb=...\db_storage\session\session.db
[bootstrap] open ok handle=1
[diag:open] db_status={"is_indexing":false,"indexed_count":0,"total_dbs":0}
[diag:execQuery] contact query ok rows=17 ...
[diag:open] contact count=24736
```

- 无任何 `rc=-101`
- 数据库打开成功
- 联系人 24736 条
- 用户确认可正常进入界面

## 备份位置

`D:\app\WeFlow\resources\resources\wcdb\win32\x64\wcdb_api.dll.bak-20261118`
（原始 SHA-256 `6397760DA70DE8062829FBE6A2EC01CF0616D6F2B334E6FE54873898F38F7AD7`）

**应用自动更新或重装后此补丁会失效，需重新定位。**
