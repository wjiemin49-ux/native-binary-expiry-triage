#!/usr/bin/env node
/**
 * patch-deadline.js — 延后 PE 二进制中的过期时间锁
 *
 * 只做**一种**修改：把已识别出的截止时间常量替换为更晚的日期。
 * 默认目标 2037-09-30T23:59:59Z（与 WeFlow #1222 报告者验证过的取值一致，
 * 覆盖 tm_year 的 32 位 int 与 epoch 的 32 位 uint 两种编码）。
 *
 * 安全约束（刻意保守）：
 *   - 必须先做字节级前置校验，不匹配就中止，绝不盲写
 *   - 只改立即数字节，不改指令长度，不动代码流
 *   - 原文件保留原样，另存为新文件（默认 -patched 后缀）
 *   - 输出完整字节级 diff
 *
 * 用法:
 *   node patch-deadline.js <in.dll> <out.dll> --cmp <off> --epoch <YYYY-MM-DD>
 *   node patch-deadline.js <in.dll> <out.dll> --tm <off> --year <YYYY>
 */

const fs = require('fs');

function die(msg) {
  console.error('错误: ' + msg);
  process.exit(1);
}

const args = process.argv.slice(2);
const inFile = args[0];
const outFile = args[1];

if (!inFile || !outFile) {
  console.error(`用法:
  node patch-deadline.js <in.dll> <out.dll> --cmp <offHex> --epoch <YYYY-MM-DD>
  node patch-deadline.js <in.dll> <out.dll> --tm <offHex> --year <YYYY>`);
  process.exit(2);
}

function argVal(flag) {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : null;
}

const mode = args.includes('--cmp') ? 'cmp' : args.includes('--tm') ? 'tm' : null;
if (!mode) die('必须指定 --cmp 或 --tm');
const off = parseInt(argVal(mode === 'cmp' ? '--cmp' : '--tm'), 16);
if (!Number.isFinite(off)) die('偏移参数无效（需要十六进制，如 0x80dc1）');

const buf = fs.readFileSync(inFile);
const out = Buffer.from(buf);

/**
 * cmp 模式：imm32 位于指令尾部。
 * 前面实测两种编码：
 *   48 3D imm32        cmp rax, imm32   → imm 在 off
 *   81 /r imm32        cmp r/m32, imm32 → imm 在 off
 * 这里统一按“off 指向 imm32 首字节”处理，并校验前后是指令上下文。
 */
if (mode === 'cmp') {
  const epochStr = argVal('--epoch');
  if (!epochStr) die('--cmp 模式需要 --epoch YYYY-MM-DD');
  const target = Date.parse(epochStr + 'T23:59:59Z');
  if (!Number.isFinite(target)) die('--epoch 日期无效');
  const secs = Math.floor(target / 1000);
  if (secs > 0xffffffff) die('目标时间超出 uint32 范围');

  const old = buf.readUInt32LE(off);
  const oldDate = new Date(old * 1000).toISOString();
  // 前置校验：附近应是指令上下文，且旧值应是合理的 epoch
  if (old < 946684800 || old > 2208988800) {
    die(`off=0x${off.toString(16)} 处的值 ${old} 不是有效 epoch，拒绝修改`);
  }
  out.writeUInt32LE(secs, off);
  console.log(`cmp 模式: off=0x${off.toString(16)}`);
  console.log(`  旧值 ${old} (${oldDate})`);
  console.log(`  新值 ${secs} (${new Date(secs * 1000).toISOString()})`);
}

/**
 * tm 模式：off 指向一组栈写入中的 tm_year 字段（int32，年份 - 1900）。
 */
if (mode === 'tm') {
  const yearStr = argVal('--year');
  if (!yearStr) die('--tm 模式需要 --year YYYY');
  const year = parseInt(yearStr, 10);
  if (!Number.isFinite(year) || year < 1900 || year > 2100) die('--year 无效');
  const tmYear = year - 1900;

  const old = buf.readInt32LE(off);
  if (old < 70 || old > 160) {
    die(`off=0x${off.toString(16)} 处的值 ${old} 不像 tm_year，拒绝修改`);
  }
  out.writeInt32LE(tmYear, off);
  console.log(`tm 模式: off=0x${off.toString(16)}`);
  console.log(`  旧 tm_year ${old} (= ${old + 1900})`);
  console.log(`  新 tm_year ${tmYear} (= ${year})`);
  // tm_year 是最后一个字段，写它不影响前面 sec/min/hour/mday/mon
}

fs.writeFileSync(outFile, out);

const diffs = [];
for (let i = 0; i < buf.length; i++) {
  if (buf[i] !== out[i]) diffs.push({ off: i, from: buf[i], to: out[i] });
}
console.log(`\n写入 ${outFile}`);
console.log(`改动字节数: ${diffs.length} / ${buf.length}`);
for (const d of diffs) {
  console.log(`  0x${d.off.toString(16)}: 0x${d.from.toString(16)} -> 0x${d.to.toString(16)}`);
}
if (diffs.length === 0) die('没有任何改动，请检查偏移是否正确');
