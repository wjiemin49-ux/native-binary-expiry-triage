#!/usr/bin/env powershell
# run-watch.ps1 — 巡检包装器：供 Windows 计划任务调用
#
# 用法: powershell -NoProfile -ExecutionPolicy Bypass -File run-watch.ps1 [-LogPath <路径>]
#
# 行为:
#   - 调用 watch-expiry.js 并把 stdout/stderr 写入日志（UTF-8）
#   - 保留退出码：0=正常 1=有到期风险 2=环境问题
#   - 追加运行时间戳，便于识别多次运行

param(
  [string]$LogPath = 'D:\tmp\watch-expiry.log',
  [string]$NodePath = '',
  [string]$WatchScript = ''
)

$ErrorActionPreference = 'Continue'

# Node 路径：显式传入优先，否则依次探测 PATH / 常见安装位置
if (-not $NodePath) {
  $candidates = @(
    (Get-Command node -ErrorAction SilentlyContinue | Select-Object -First 1).Source,
    'D:\app\node.exe',
    'C:\Program Files\nodejs\node.exe',
    "$env:LOCALAPPDATA\Programs\nodejs\node.exe"
  ) | Where-Object { $_ -and (Test-Path $_) }
  $NodePath = $candidates | Select-Object -First 1
}

# 巡检脚本路径：显式传入优先，否则取本脚本同目录
if (-not $WatchScript) {
  $WatchScript = Join-Path $PSScriptRoot 'watch-expiry.js'
}

if (-not $NodePath) {
  Add-Content -Path $LogPath -Value 'ERROR: node not found. Pass -NodePath explicitly.' -Encoding utf8
  exit 2
}
if (-not (Test-Path $WatchScript)) {
  Add-Content -Path $LogPath -Value "ERROR: watch script not found at $WatchScript" -Encoding utf8
  exit 2
}

Add-Content -Path $LogPath -Value ("=== run {0} ===" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) -Encoding utf8

# 用 Process 而非 & 调用，避免控制台编码污染 stdout
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName  = $NodePath
$psi.Arguments = '"' + $WatchScript + '"'
$psi.WorkingDirectory = Split-Path $WatchScript -Parent
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError  = $true
$psi.UseShellExecute = $false
$psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
$psi.StandardErrorEncoding  = [System.Text.Encoding]::UTF8

$p = [System.Diagnostics.Process]::Start($psi)
$stdout = $p.StandardOutput.ReadToEnd()
$stderr = $p.StandardError.ReadToEnd()
$p.WaitForExit()

Add-Content -Path $LogPath -Value $stdout.TrimEnd() -Encoding utf8
if ($stderr.Trim()) { Add-Content -Path $LogPath -Value $stderr.TrimEnd() -Encoding utf8 }
Add-Content -Path $LogPath -Value ("exit_code={0}" -f $p.ExitCode) -Encoding utf8
Add-Content -Path $LogPath -Value "" -Encoding utf8

exit $p.ExitCode
