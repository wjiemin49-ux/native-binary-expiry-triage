# 提权替换安装目录文件

应用安装目录（如 `D:\app\...`）的 ACL 通常只给 `Administrators` / `SYSTEM` 写权限。
普通用户会话的 `cp` / `Copy-Item` 会直接 `Permission denied`，即使沙箱已关闭。

## 前置确认

```bash
powershell -NoProfile -Command "[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
```

返回 `False` 就必须提权。

## 推荐：脚本 + 日志文件

**不要用长内联命令行提权。** 提权窗口一旦被用户关闭，没有任何输出可查，
会误判为「已执行」。脚本 + 日志能明确区分「执行了」和「没执行」。

```bash
cat > "D:/tmp/apply_patch.ps1" <<'EOF'
$ErrorActionPreference='Continue'
$log='D:\tmp\apply_patch.log'
"=== start $(Get-Date -Format s) ===" | Out-File $log -Encoding utf8
$d='D:\app\WeFlow\resources\resources\wcdb\win32\x64'
$dll="$d\wcdb_api.dll"
$src='D:\tmp\wcdb_api.patched.dll'
try{
  Copy-Item $dll "$d\wcdb_api.dll.bak-20261118" -Force
  "backup ok" | Out-File $log -Append -Encoding utf8
  Copy-Item $src $dll -Force
  "copy ok" | Out-File $log -Append -Encoding utf8
  (Get-FileHash $dll -Algorithm SHA256).Hash | Out-File $log -Append -Encoding utf8
}catch{ "ERROR: $_" | Out-File $log -Append -Encoding utf8 }
"=== done ===" | Out-File $log -Append -Encoding utf8
EOF

rm -f "D:/tmp/apply_patch.log"
powershell -NoProfile -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','D:\tmp\apply_patch.ps1' -Wait"
cat "D:/tmp/apply_patch.log"
```

`-Verb RunAs` 会弹 UAC 对话框，需要用户点确认。`-Wait` 保证脚本跑完再返回。

## 必须在脚本里做的事

1. **先停目标进程**。DLL 已被进程映射时替换会失败（文件被占用）。
   ```powershell
   Get-Process WeFlow -ErrorAction SilentlyContinue | ForEach-Object { $_.Kill(); Start-Sleep -Milliseconds 800 }
   ```
2. **先备份再替换**，备份与原文件同目录、同名 + 日期后缀，便于回滚。
3. **回写 SHA-256 到日志**，替换后立刻核对哈希是否等于预期值。
4. **写 `=== done ===` 结束标记**，用来确认脚本真的跑完了。

## 回滚

```powershell
Copy-Item "$d\wcdb_api.dll.bak-20261118" "$d\wcdb_api.dll" -Force
```

备份文件权限继承自目录，普通用户可能也读不了，回滚同样需要提权。

## 验证替换是否真的生效

```bash
sha256sum "<目标dll>"
ls -la "<目标目录>"
```

哈希必须等于补丁文件的哈希。若仍等于原值，说明提权脚本没跑成（UAC 被拒或路径写错），
**不要假设成功**。
