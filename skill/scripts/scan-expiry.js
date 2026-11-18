#!/usr/bin/env node
/**
 * scan-expiry.js — 扫描 PE 二进制中内嵌的“过期时间锁”常量
 *
 * 背景：不少闭源原生组件（WeChat 相关工具、DRM/授权库、试用版 SDK）会在 .rdata 里
 * 硬编码一个截止时间戳，到期后函数返回负数错误码。本脚本在**不运行**目标程序的前提下，
 * 静态定位这些常量，用于提前发现即将过期的组件。
 *
 * 用法:
 *   node scan-expiry.js <file.dll> [--json]
 *
 * 识别三类模式:
 *   1. epoch 常量   —— 32 位 Unix 时间戳（秒），落在 [2000-01-01, 2040-01-01] 区间
 *   2. cmp 比较     —— 紧跟 cmp/jle/jg 的 32 位立即数，即“时间锁”本体
 *   3. tm 结构体    —— 连续 6 个 32 位小端字段，形如 {sec,min,hour,mday,mon,year-1900}
 *
 * 注意：epoch 常量命中数会很多（PE 文件里混杂大量时间戳），脚本按“是否紧邻比较指令”
 * 降噪。真正高置信度的是 cmp 模式与 tm 模式。
 */

const fs = require('fs');

const LO = Date.UTC(2000, 0, 1) / 1000;      // 946684800
const HI = Date.UTC(2040, 0, 1) / 1000;      // 2208988800
const DEADLINE_BAND = 3 * 86400;             // ±3 天内的 epoch 视为“疑似截止时间”

/* ---------- PE 解析（仅需 section 表与导出表） ---------- */

function parsePE(buf) {
  if (buf.length < 0x40 || buf.readUInt16LE(0) !== 0x5a4d) return null; // 'MZ'
  const e_lfanew = buf.readUInt32LE(0x3c);
  if (e_lfanew + 24 > buf.length) return null;
  if (buf.readUInt32LE(e_lfanew) !== 0x4550) return null;               // 'PE\0\0'

  const coff = e_lfanew + 4;
  const nsec = buf.readUInt16LE(coff + 2);
  const optSize = buf.readUInt16LE(coff + 16);
  const opt = coff + 20;
  const magic = buf.readUInt16LE(opt);
  const pe32plus = magic === 0x20b;
  const ddOff = opt + (pe32plus ? 112 : 96);

  const secOff = opt + optSize;
  const sections = [];
  for (let i = 0; i < nsec; i++) {
    const s = secOff + i * 40;
    sections.push({
      name: buf.toString('ascii', s, s + 8).replace(/\0.*$/, ''),
      va: buf.readUInt32LE(s + 12),
      vs: buf.readUInt32LE(s + 8),
      raw: buf.readUInt32LE(s + 20),
      rs: buf.readUInt32LE(s + 16),
    });
  }

  const r2o = (rva) => {
    for (const s of sections) {
      if (rva >= s.va && rva < s.va + Math.max(s.vs, s.rs)) return s.raw + (rva - s.va);
    }
    return null;
  };
  const o2r = (off) => {
    for (const s of sections) {
      if (off >= s.raw && off < s.raw + s.rs) return s.va + (off - s.raw);
    }
    return null;
  };
  const sectionOf = (off) =>
    sections.find((s) => off >= s.raw && off < s.raw + s.rs) || null;

  return { buf, sections, r2o, o2r, sectionOf, ddOff, pe32plus };
}

/* ---------- 导出表 ---------- */

function parseExports(pe) {
  const { buf, r2o } = pe;
  const expRva = buf.readUInt32LE(pe.ddOff);
  if (!expRva) return [];
  const eo = r2o(expRva);
  if (eo == null) return [];

  const nFn = buf.readUInt32LE(eo + 20);
  const addrRva = buf.readUInt32LE(eo + 28);
  const nNameRva = buf.readUInt32LE(eo + 32);
  const ordRva = buf.readUInt32LE(eo + 36);
  const ao = r2o(addrRva), no = r2o(nNameRva), oo = r2o(ordRva);
  if (ao == null || no == null || oo == null) return [];

  const out = [];
  for (let i = 0; i < nFn; i++) {
    const rva = buf.readUInt32LE(ao + i * 4);
    if (!rva) continue;
    const nrva = buf.readUInt32LE(no + i * 4);
    const so = r2o(nrva);
    if (so == null) continue;
    let name = '';
    for (let j = 0; buf[so + j]; j++) name += String.fromCharCode(buf[so + j]);
    const off = r2o(rva);
    out.push({ name, rva, off });
  }
  out.sort((a, b) => a.rva - b.rva);
  return out;
}

/** 找到包含给定文件偏移的导出函数（按 rva 区间就近归属） */
function ownerExport(exports, off, rva) {
  let best = null;
  for (const e of exports) {
    if (e.rva <= rva) best = e;
    else break;
  }
  if (!best) return null;
  return best;
}

/* ---------- 模式扫描 ---------- */

// x86-64 立即数比较：
//   48 3D imm32        cmp rax, imm32
//   48 81 F? imm32    cmp reg, imm32
//   3D imm32           cmp eax, imm32
//   81 F? imm32        cmp r/m32, imm32
const CMP_IMM_PATTERNS = [
  { len: 5, prefix: [0x48, 0x3d], immAt: 2, desc: 'cmp rax, imm32' },
  { len: 6, prefix: [0x48, 0x81], immAt: 2, desc: 'cmp reg, imm32' },
  { len: 5, prefix: [0x3d], immAt: 1, desc: 'cmp eax, imm32' },
  { len: 6, prefix: [0x81], immAt: 1, desc: 'cmp r/m32, imm32' },
];

function scanCmpImmediates(buf) {
  const hits = [];
  for (const p of CMP_IMM_PATTERNS) {
    for (let o = 0; o + p.len <= buf.length; o++) {
      let ok = true;
      for (let i = 0; i < p.prefix.length; i++) {
        if (buf[o + i] !== p.prefix[i]) { ok = false; break; }
      }
      if (!ok) continue;
      // cmp reg,imm32 的 ModRM 在 imm 之前，需确认是 imm32 形式
      if (p.prefix[1] === 0x81) {
        const modrm = buf[o + 1];
        if ((modrm & 0x38) !== 0x38) continue; // 必须是 imm32 操作数
      }
      const imm = buf.readUInt32LE(o + p.immAt);
      if (imm < LO || imm > HI) continue;
      hits.push({
        off: o,
        imm,
        desc: p.desc,
        iso: new Date(imm * 1000).toISOString(),
      });
    }
  }
  return hits;
}

// tm 结构体：6 个连续 int32
//   { tm_sec, tm_min, tm_hour, tm_mday, tm_mon, tm_year }
function scanTmStructs(buf) {
  const hits = [];
  const years = [126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137];
  for (let o = 0; o + 24 <= buf.length; o += 4) {
    const sec = buf.readInt32LE(o);
    const min = buf.readInt32LE(o + 4);
    const hour = buf.readInt32LE(o + 8);
    const mday = buf.readInt32LE(o + 12);
    const mon = buf.readInt32LE(o + 16);
    const year = buf.readInt32LE(o + 20);
    if (sec < 0 || sec > 60) continue;
    if (min < 0 || min > 59) continue;
    if (hour < 0 || hour > 23) continue;
    if (mday < 1 || mday > 31) continue;
    if (mon < 0 || mon > 11) continue;
    if (!years.includes(year)) continue;
    hits.push({
      off: o,
      date: new Date(Date.UTC(year + 1900, mon, mday, hour, min, sec)).toISOString(),
      fields: { sec, min, hour, mday, mon, year },
      yearFieldOff: o + 20,
    });
  }
  return hits;
}

// 邻近 epoch：任何落在 ±3 天窗口内的 epoch
function scanEpochBand(buf) {
  const hits = [];
  for (let o = 0; o + 4 <= buf.length; o++) {
    const v = buf.readUInt32LE(o);
    if (v < LO || v > HI) continue;
    hits.push({ off: o, imm: v, iso: new Date(v * 1000).toISOString() });
  }
  return hits;
}

/**
 * “人为设定的到期时刻”启发式。
 *
 * 编译期时间戳几乎不可能恰好落在 23:59:59 / 00:00:00 这种边界，
 * 而人工设定的截止时间几乎总是整点整分整秒。所以：
 *   - 分秒必须为 59/00 组合（23:59:59 或 00:00:00 附近）
 *   - 且日期靠近月末或年末（月末 25–31 日，或 12 月）
 * 这样能把上百万噪声收敛到个位数命中。
 */
function isExpiryBoundary(iso) {
  const d = new Date(iso);
  const min = d.getUTCMinutes();
  const sec = d.getUTCSeconds();
  const hour = d.getUTCHours();
  const dom = d.getUTCDate();
  const mon = d.getUTCMonth();

  const onMinute = min === 59 || min === 0;
  const onSecond = sec === 59 || sec === 0;
  if (!onMinute || !onSecond) return false;
  if (hour !== 23 && hour !== 0 && hour !== 12) return false;

  // 靠近月末 或 12 月（年底）
  const nearMonthEnd = dom >= 25 || dom <= 1;
  const yearEnd = mon === 11;
  return nearMonthEnd || yearEnd;
}

/**
 * tm 结构体第二种编码：不是连续数据区，而是由一串
 *   C7 44 24 <disp8> <imm32>      mov dword ptr [rsp+disp8], imm32
 * 逐字段写入栈上。
 * 字段顺序（MSVC tm）：sec, min, hour, mday, mon, year(=真实年-1900)
 * 这里按“偏移递增 4、每个值落在合法范围”还原语义。
 */
function scanTmStackWrites(buf) {
  const hits = [];
  const MOV_RSP_DISP8_IMM32 = 0xc7;
  for (let o = 0; o + 8 <= buf.length; o++) {
    if (buf[o] !== MOV_RSP_DISP8_IMM32) continue;
    if (buf[o + 1] !== 0x44 || buf[o + 2] !== 0x24) continue;
    const disp = buf[o + 3];
    const imm = buf.readInt32LE(o + 4);
    hits.push({ off: o, disp, imm, fieldOff: o + 4 });
  }

  // 把相邻的写入聚成组：disp 步长 4（升序或降序都要，MSVC 两种都常见）
  const groups = [];
  for (const h of hits) {
    let placed = false;
    for (let gi = groups.length - 1; gi >= 0; gi--) {
      const g = groups[gi];
      const last = g[g.length - 1];
      if (h.disp === last.disp + 4 && h.off - last.off <= 24) {
        g.push(h);
        placed = true;
        break;
      }
      if (h.disp === last.disp - 4 && h.off - last.off <= 24) {
        g.push(h);
        placed = true;
        break;
      }
    }
    if (!placed) groups.push([h]);
  }

  const out = [];
  for (const g of groups) {
    if (g.length < 6) continue;
    // 按 disp 升序还原 tm 字段顺序（sec,min,hour,mday,mon,year）
    const asc = [...g].sort((a, b) => a.disp - b.disp);
    const v = asc.map((x) => x.imm);
    const [sec, min, hour, mday, mon, year] = v;
    if (sec < 0 || sec > 60) continue;
    if (min < 0 || min > 59) continue;
    if (hour < 0 || hour > 23) continue;
    if (mday < 1 || mday > 31) continue;
    if (mon < 0 || mon > 11) continue;
    if (year < 100 || year > 160) continue;
    const date = new Date(Date.UTC(year + 1900, mon, mday, hour, min, sec)).toISOString();
    out.push({
      off: Math.min(...g.map((x) => x.off)),
      date,
      fields: { sec, min, hour, mday, mon, year },
      yearFieldOff: asc[5].fieldOff,
      writes: asc.map((x) => ({ off: x.fieldOff, disp: x.disp, imm: x.imm })),
    });
  }
  return out;
}

/* ---------- 代码引用校验 ---------- */

/**
 * 判断某个文件偏移对应的常量，是否真的被 .text 里的指令引用。
 *
 * 必要性：.rdata / .pdata 里堆积了大量恰好长得像 epoch 的字节序列
 * （MSVC 异常处理数据、未初始化表、被复制的代码片段）。
 * 只有「代码实际引用它」才算真实的时间锁。
 *
 * 做法：遍历 .text 的每 4 字节窗口，把位移视为 RIP-relative，
 * 检查 target 是否等于目标 RVA。
 */
function buildRipReferenceIndex(pe) {
  const { buf, o2r, sections } = pe;
  const text = sections.find((s) => s.name === '.text');
  const index = new Map(); // rva -> [引用处文件偏移]
  if (!text) return index;

  for (let o = text.raw; o + 4 <= text.raw + text.rs; o++) {
    const disp = buf.readInt32LE(o);
    const nextRva = o2r(o + 4);
    if (nextRva === null) continue;
    const target = nextRva + disp;
    if (target < 0 || target > 0xffffffff) continue;
    if (!index.has(target)) index.set(target, []);
    index.get(target).push(o);
  }
  return index;
}

function hasCodeReference(pe, ripIndex, off) {
  const rva = pe.o2r(off);
  if (rva === null) return false;
  return (ripIndex.get(rva) || []).length > 0;
}

/* ---------- 主流程 ---------- */

function main() {
  const args = process.argv.slice(2);
  const jsonOut = args.includes('--json');
  const file = args.find((a) => !a.startsWith('--'));
  if (!file) {
    console.error('用法: node scan-expiry.js <file.dll> [--json]');
    process.exit(2);
  }

  const buf = fs.readFileSync(file);
  const pe = parsePE(buf);
  if (!pe) {
    console.error(`不是有效的 PE 文件: ${file}`);
    process.exit(1);
  }

  const exports = parseExports(pe);
  const ripIndex = buildRipReferenceIndex(pe);
  const cmpHits = scanCmpImmediates(buf);
  const tmHits = scanTmStructs(buf);
  const tmStack = scanTmStackWrites(buf);
  const epochs = scanEpochBand(buf);

  // 把 cmp 命中与最近的 epoch 交叉验证：cmp 的 imm 本身就是 epoch
  const deadlineCmp = cmpHits.map((h) => {
    const rva = pe.o2r(h.off);
    const exp = ownerExport(exports, h.off, rva);
    const sec = pe.sectionOf(h.off);
    return {
      ...h,
      rva,
      section: sec ? sec.name : null,
      export: exp ? exp.name : null,
      boundary: isExpiryBoundary(h.iso),
    };
  });

  // 高置信度：命中“边界时刻”或 tm 结构体
  // 额外要求：常量确实被代码引用（排除 .rdata 中的巧合字节）
  const strongCmp = deadlineCmp.filter(
    (h) => h.boundary && (h.section === '.text' || hasCodeReference(pe, ripIndex, h.off))
  );
  const strongTm = tmHits.filter((h) => isExpiryBoundary(h.date));

  const tmStackOut = tmStack.map((h) => {
    const rva = pe.o2r(h.off);
    const exp = ownerExport(exports, h.off, rva);
    const sec = pe.sectionOf(h.off);
    return {
      ...h,
      rva,
      section: sec ? sec.name : null,
      export: exp ? exp.name : null,
      boundary: isExpiryBoundary(h.date),
    };
  });
  const strongTmStack = tmStackOut.filter((h) => h.boundary);

  const tmOut = tmHits.map((h) => {
    const rva = pe.o2r(h.off);
    const exp = ownerExport(exports, h.off, rva);
    const sec = pe.sectionOf(h.off);
    return { ...h, rva, section: sec ? sec.name : null, export: exp ? exp.name : null };
  });

  const result = {
    file,
    size: buf.length,
    sections: pe.sections.map((s) => s.name),
    exportCount: exports.length,
    deadlineComparisons: strongCmp,
    allDeadlineComparisons: deadlineCmp.length,
    tmStructs: strongTm,
    allTmStructs: tmOut,
    tmStackWrites: strongTmStack,
    allTmStackWrites: tmStackOut,
    epochCandidates: epochs.length,
  };

  if (jsonOut) {
    console.log(JSON.stringify(result, null, 2));
    return;
  }

  console.log(`\n=== 过期时间锁扫描: ${file} ===`);
  console.log(`大小 ${buf.length} 字节 | 段: ${result.sections.join(', ')} | 导出 ${exports.length} 个`);
  console.log(`epoch 类常量总数(含噪声): ${epochs.length}`);
  console.log(`比较指令命中 ${deadlineCmp.length} 处 → 边界时刻 ${strongCmp.length} 处`);

  console.log(`\n-- 高置信度: 比较指令中的截止时间 (${strongCmp.length}) --`);
  if (!strongCmp.length) console.log('  (无)');
  for (const h of strongCmp) {
    console.log(
      `  off=0x${h.off.toString(16)} rva=0x${(h.rva || 0).toString(16)} ` +
      `${h.desc} ${h.imm} (${h.iso})` +
      (h.export ? `  ← ${h.export}` : '') +
      (h.section ? `  [${h.section}]` : '')
    );
  }

  console.log(`\n-- 高置信度: tm 结构体截止时间 (${strongTm.length} / 共 ${tmOut.length}) --`);
  if (!strongTm.length) console.log('  (无)');
  for (const h of strongTm) {
    console.log(
      `  off=0x${h.off.toString(16)} rva=0x${(h.rva || 0).toString(16)} ` +
      `tm=${h.date} year_field=0x${h.yearFieldOff.toString(16)}` +
      (h.export ? `  ← ${h.export}` : '')
    );
  }

  console.log(`\n-- 高置信度: 栈上 tm 字段写入 (${strongTmStack.length} / 共 ${tmStackOut.length}) --`);
  if (!strongTmStack.length) console.log('  (无)');
  for (const h of strongTmStack) {
    console.log(
      `  off=0x${h.off.toString(16)} rva=0x${(h.rva || 0).toString(16)} ` +
      `tm=${h.date} year_field=0x${h.yearFieldOff.toString(16)}` +
      (h.export ? `  ← ${h.export}` : '')
    );
  }

  // 未来 90 天内到期的 epoch（非 cmp 命中）作为预警
  const now = Math.floor(Date.now() / 1000);
  const soon = epochs.filter(
    (e) =>
      e.imm > now &&
      e.imm < now + 90 * 86400 &&
      isExpiryBoundary(e.iso) &&
      hasCodeReference(pe, ripIndex, e.off)
  );
  console.log(`\n-- 预警: 未来 90 天内的 epoch 常量 (${soon.length}) --`);
  if (!soon.length) console.log('  (无)');
  for (const e of soon.slice(0, 40)) {
    console.log(`  off=0x${e.off.toString(16)} ${e.imm} (${e.iso})`);
  }
  console.log('');
}

main();
