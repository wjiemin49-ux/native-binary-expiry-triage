#!/usr/bin/env node
/**
 * watch-expiry.js — 巡检受监控的原生组件，发现临近到期的截止时间锁
 *
 * 不依赖 bash / sha256sum / date，纯 Node，便于被 Windows 计划任务直接调用。
 *
 * 用法:
 *   node watch-expiry.js                # 扫描内置清单
 *   node watch-expiry.js <dll> [<dll>]  # 扫描指定文件
 *   node watch-expiry.js --manifest <json文件>
 *
 * 退出码:
 *   0 = 无临近到期
 *   1 = 有 90 天内到期的组件，需处理
 *   2 = 用法/环境错误
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SKILL_DIR = path.resolve(__dirname, '..');
const SCAN = path.join(SKILL_DIR, 'scripts', 'scan-expiry.js');

/**
 * 受监控清单。默认从 manifest.json 读取（与本脚本同目录），
 * 找不到时回退到内置示例。
 *
 * manifest.json 格式：
 *   [
 *     { "app": "应用名 + 版本", "file": "D:/path/to/component.dll", "note": "用途与已知状态" }
 *   ]
 *
 * 维护要点：组件哈希变了 = 换了构建 = 之前的定位失效，必须重新扫描。
 */
const DEFAULT_MANIFEST = [
  {
    app: 'WeFlow 5.0.0',
    file: 'D:/app/WeFlow/resources/resources/wcdb/win32/x64/wcdb_api.dll',
    note: '主组件；曾于 2026-09-30 到期，已打补丁延后至 2037-09-30',
  },
  {
    app: 'WeFlow 5.0.0',
    file: 'D:/app/WeFlow/resources/resources/wcdb/win32/x64/WCDB.dll',
    note: 'WCDB 引擎',
  },
];

function loadManifest() {
  const p = path.join(__dirname, 'manifest.json');
  if (fs.existsSync(p)) {
    try {
      const m = JSON.parse(fs.readFileSync(p, 'utf8'));
      if (Array.isArray(m) && m.length) return m;
    } catch (e) {
      console.error(`警告: manifest.json 解析失败，使用内置清单 (${e.message})`);
    }
  }
  return DEFAULT_MANIFEST;
}

const WARN_DAYS = 90;

function sha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

/** 调用 scan-expiry.js 的 --json 输出 */
function scan(file) {
  const { execFileSync } = require('child_process');
  const out = execFileSync(process.execPath, [SCAN, file, '--json'], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  return JSON.parse(out);
}

/** 从扫描结果里收集所有截止时刻 */
function collectDeadlines(res) {
  const dates = [];
  for (const h of res.deadlineComparisons || []) dates.push({ date: h.iso, where: `cmp @0x${h.off.toString(16)}`, fn: h.export });
  for (const h of res.tmStructs || []) dates.push({ date: h.date, where: `tm @0x${h.off.toString(16)}`, fn: h.export });
  for (const h of res.tmStackWrites || []) dates.push({ date: h.date, where: `tm-stack @0x${h.off.toString(16)}`, fn: h.export });
  return dates;
}

function daysUntil(iso) {
  return Math.round((Date.parse(iso) - Date.now()) / 86400000);
}

function main() {
  const args = process.argv.slice(2);
  let manifest = loadManifest();

  const mi = args.indexOf('--manifest');
  if (mi >= 0) {
    const mf = args[mi + 1];
    if (!mf || !fs.existsSync(mf)) {
      console.error('清单文件不存在: ' + mf);
      process.exit(2);
    }
    manifest = JSON.parse(fs.readFileSync(mf, 'utf8'));
  } else if (args.length) {
    manifest = args.map((f) => ({ app: path.basename(f), file: f, note: '' }));
  }

  console.log(`=== 原生组件到期巡检 ${new Date().toLocaleString('zh-CN')} ===`);
  console.log('');

  let soonCount = 0;
  let errorCount = 0;

  for (const entry of manifest) {
    const file = entry.file;
    console.log(`--- ${entry.app}`);
    console.log(`    文件: ${file}`);
    if (entry.note) console.log(`    说明: ${entry.note}`);

    if (!fs.existsSync(file)) {
      console.log('    ⚠ 文件不存在（应用可能已卸载或路径变更），跳过');
      errorCount++;
      console.log('');
      continue;
    }

    let hash;
    try {
      hash = sha256(file);
    } catch (e) {
      console.log(`    ⚠ 无法计算哈希: ${e.message}`);
      errorCount++;
      console.log('');
      continue;
    }
    console.log(`    SHA-256: ${hash}`);

    let res;
    try {
      res = scan(file);
    } catch (e) {
      console.log(`    ⚠ 扫描失败: ${e.message}`);
      errorCount++;
      console.log('');
      continue;
    }

    const deadlines = collectDeadlines(res);
    if (!deadlines.length) {
      console.log('    ✓ 未检出截止时间锁');
    } else {
      for (const d of deadlines) {
        const days = daysUntil(d.date);
        const expired = days < 0;
        const soon = days >= 0 && days <= WARN_DAYS;
        if (expired) {
          console.log(`    ⛔ 已过期: ${d.date} (${-days} 天前) ${d.where}${d.fn ? ' ← ' + d.fn : ''}`);
          soonCount++;
        } else if (soon) {
          console.log(`    ⚠ 临近到期: ${d.date} (还剩 ${days} 天) ${d.where}${d.fn ? ' ← ' + d.fn : ''}`);
          soonCount++;
        } else {
          console.log(`    ✓ ${d.date} (还剩 ${days} 天) ${d.where}${d.fn ? ' ← ' + d.fn : ''}`);
        }
      }
    }
    console.log('');
  }

  if (soonCount > 0) {
    console.log(`结论: 发现 ${soonCount} 个已过期或临近到期项。`);
    console.log('处理方式: 参考 Skill native-binary-expiry-triage 的 Workflow，');
    console.log('用 scan-expiry.js 定位 → patch-deadline.js 生成补丁 → 提权替换 → 分层验证。');
    process.exit(1);
  }
  if (errorCount > 0) {
    console.log(`结论: 无到期风险，但有 ${errorCount} 项检查未能完成（见上）。`);
    process.exit(2);
  }
  console.log('结论: 全部组件无过期或临近到期项。');
  process.exit(0);
}

main();
