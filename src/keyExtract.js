'use strict';

const { execSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const { WINDOWS_CONFIG_XOR_MASK } = require('./constants');
const { detectPlatform } = require('./platform');

/**
 * WeChat 密钥派生参数（用于 collectCandidates 的 PBKDF2 候选推算）。
 * 不同版本可能不同，decrypt.js 会用真实数据库做最终校验，所以这里多算几种无妨。
 */
const PBKDF2_VARIANTS = [
  { iter: 64000, hash: 'sha1' },
  { iter: 256000, hash: 'sha512' },
  { iter: 64000, hash: 'sha512' },
  { iter: 4000, hash: 'sha1' }
];

/**
 * 用掩码按字节循环 XOR 解码（解码与编码是同一运算）。
 * @param {Buffer} buf
 * @param {Buffer} mask
 * @returns {Buffer}
 */
function xorDecode(buf, mask) {
  const out = Buffer.allocUnsafe(buf.length);
  for (let i = 0; i < buf.length; i++) out[i] = buf[i] ^ mask[i % mask.length];
  return out;
}

/**
 * 粗略判断 16 字节是否像 salt（随机、非全 0 / 非全 0xFF）。
 */
function looksLikeSalt(b16) {
  if (!b16 || b16.length !== 16) return false;
  let zeros = 0;
  let ff = 0;
  for (const b of b16) {
    if (b === 0) zeros++;
    else if (b === 0xff) ff++;
  }
  return zeros < 14 && ff < 14;
}

/**
 * 从「已 XOR 解码」的内存区域里收集候选 SQLCipher 密钥（核心、可移植、可测）。
 * 以 8 字节为步长滑动 48 字节窗口：
 *   - 前 32 字节视为原始密钥候选
 *   - 后 16 字节视为 salt
 *   - 同时把 PBKDF2(前32, 后16) 也作为候选（部分版本密钥本身是派生值）
 * 最终由 decrypt.js 用真实数据库做「能否解出 sqlite_master」来判定真伪。
 * @param {Buffer} decoded
 * @returns {string[]} 去重后的 hex 密钥候选
 */
function collectCandidates(decoded) {
  const cands = new Set();
  const WINDOW = 48;
  // 步长 1 字节：真实内存中 (key+salt) 不一定按 8 字节对齐，逐字节滑动才能命中。
  for (let i = 0; i + WINDOW <= decoded.length; i += 1) {
    const key32 = decoded.slice(i, i + 32);
    const salt16 = decoded.slice(i + 32, i + 48);
    if (!looksLikeSalt(salt16)) continue;
    cands.add(key32.toString('hex'));
    for (const v of PBKDF2_VARIANTS) {
      try {
        const derived = crypto.pbkdf2Sync(key32, salt16, v.iter, 32, v.hash);
        cands.add(derived.toString('hex'));
      } catch (e) {
        // 忽略单个失败
      }
    }
  }
  return [...cands];
}

/**
 * 处理一个内存 dump 文件（跨平台、可测）：XOR 解码后收集候选密钥。
 * @param {string} dumpPath
 * @returns {string[]}
 */
function extractKeysFromDump(dumpPath, mask = WINDOWS_CONFIG_XOR_MASK) {
  const raw = fs.readFileSync(dumpPath);
  const decoded = xorDecode(raw, mask);
  return collectCandidates(decoded);
}

/**
 * 查找微信进程 PID（Windows 用 tasklist，macOS 用 pgrep）。
 * @returns {number|null}
 */
function findWeixinPid() {
  const platform = detectPlatform();
  try {
    if (platform === 'win') {
      const out = execSync('tasklist /fi "imagename eq Weixin.exe" /nh', { encoding: 'utf8' });
      const m = out.match(/Weixin\.exe\s+(\d+)/);
      return m ? parseInt(m[1], 10) : null;
    }
    if (platform === 'mac') {
      const out = execSync('pgrep -f "WeChat" | head -1', { encoding: 'utf8' });
      const pid = parseInt(out.trim(), 10);
      return Number.isFinite(pid) ? pid : null;
    }
  } catch (e) {
    // ignore
  }
  return null;
}

/**
 * Windows 实时内存扫描（best-effort，需校验）。
 * 使用 koffi 调用 Kernel32 的 OpenProcess / VirtualQueryEx / ReadProcessMemory。
 * 注意：未在有真实微信 4.x 的机器上验证；若失败请用 --key 或上游 wcdb-key-tool。
 * @param {number} pid
 * @returns {string[]}
 */
function scanProcessMemoryWindows(pid) {
  // eslint-disable-next-line global-require
  const koffi = require('koffi');
  const Kernel32 = koffi.load('Kernel32.dll');
  const MBI = koffi.struct('MEMORY_BASIC_INFORMATION', {
    BaseAddress: 'void*',
    AllocationBase: 'void*',
    AllocationProtect: 'uint32_t',
    PartitionId: 'uint16_t',
    _pad1: 'uint8_t[6]',
    RegionSize: 'uint64_t',
    State: 'uint32_t',
    Protect: 'uint32_t',
    Type: 'uint32_t',
    _pad2: 'uint8_t[4]'
  });
  const OpenProcess = Kernel32.func('void* OpenProcess(uint32_t, bool, uint32_t)');
  const VirtualQueryEx = Kernel32.func('uint64_t VirtualQueryEx(void*, const void*, MEMORY_BASIC_INFORMATION*, uint64_t)');
  const ReadProcessMemory = Kernel32.func(
    'bool ReadProcessMemory(void*, const void*, void*, uint64_t, uint64_t*)'
  );
  const CloseHandle = Kernel32.func('bool CloseHandle(void*)');

  const PROCESS_VM_READ = 0x0010;
  const PROCESS_QUERY_INFORMATION = 0x0400;
  const MEM_COMMIT = 0x1000;
  const PAGE_READONLY = 0x02;
  const PAGE_READWRITE = 0x04;
  const PAGE_EXECUTE_READ = 0x20;
  const PAGE_EXECUTE_READWRITE = 0x40;

  const hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid);
  if (!hProc || hProc === 0 || hProc === koffi.NULL) {
    throw new Error('OpenProcess 失败，可能需要以相同用户权限运行，或微信进程不存在');
  }

  const cands = new Set();
  let addr = 0n;
  const maxAddr = 0x7fffffffffffffffn; // 用户态上限
  try {
    while (addr < maxAddr) {
      const info = koffi.alloc(MBI);
      const ret = VirtualQueryEx(hProc, addr, info, 48n);
      if (!ret || ret === 0n) break;
      const base = info.BaseAddress ? BigInt(info.BaseAddress) : addr;
      const regionSize = info.RegionSize;
      const protect = info.Protect;
      const state = info.State;
      const readable =
        state === MEM_COMMIT &&
        (protect === PAGE_READONLY ||
          protect === PAGE_READWRITE ||
          protect === PAGE_EXECUTE_READ ||
          protect === PAGE_EXECUTE_READWRITE);
      if (readable && regionSize > 0 && regionSize <= 64 * 1024 * 1024) {
        const buf = Buffer.alloc(Number(regionSize));
        const bytesRead = koffi.alloc('uint64_t');
        const ok = ReadProcessMemory(hProc, base, buf, regionSize, bytesRead);
        if (ok) {
          const decoded = xorDecode(buf, WINDOWS_CONFIG_XOR_MASK);
          for (const c of collectCandidates(decoded)) cands.add(c);
        }
      }
      addr = base + regionSize;
      if (regionSize === 0n) break;
    }
  } finally {
    CloseHandle(hProc);
  }
  return [...cands];
}

/**
 * 生成 macOS lldb 辅助脚本（模板）。
 * macOS 因 SIP / 代码签名加固，普通进程无法读取微信内存，
 * 需 sudo 或临时关闭 SIP，再 attach 后用 memory find 定位 XOR 掩码附近数据。
 * 此为起点模板，符号/地址需按实际微信版本微调。
 * @param {number} pid
 * @returns {string}
 */
function generateMacLldbScript(pid) {
  return [
    '# macOS 微信密钥提取 lldb 辅助脚本（模板，需 sudo 运行）',
    `# 用法: sudo lldb -p ${pid} -s this_script.lldb`,
    'process attach',
    '# 1) 在内存中搜索 XOR 掩码特征字节（示意，实际需转义）',
    '# memory find --pid <pid> -e "d2c7442458020000"',
    '# 2) 找到基址后对所在区域 memory read，导出为文件',
    '# memory read -o /tmp/wcdb_blob.bin -b <addr> <addr+0x2000>',
    '# 3) 退出后用本工具: node bin/wcdb.js key --dump /tmp/wcdb_blob.bin',
    'quit'
  ].join('\n');
}

/**
 * 密钥提取总入口。
 * @param {object} opts
 * @param {number} [opts.pid] 指定进程 PID（不传则自动查找）
 * @param {string} [opts.dump] 内存 dump 文件路径（跨平台可测路径）
 * @param {string} [opts.key] 手动提供 hex 密钥，直接返回
 * @param {boolean} [opts.allowMemoryScan] 是否允许实时内存扫描（默认 false）
 * @returns {string[]} hex 密钥候选数组
 */
function extractKeys(opts = {}) {
  if (opts.key) return [opts.key.replace(/^0x/, '').toLowerCase()];
  if (opts.dump) return extractKeysFromDump(opts.dump);

  const platform = detectPlatform();
  const pid = opts.pid || findWeixinPid();
  if (!pid) {
    throw new Error('未找到微信进程，请确认微信已登录运行；或使用 --key / --dump 方式');
  }
  if (!opts.allowMemoryScan) {
    throw new Error(
      '实时内存扫描未启用。请二选一：\n' +
        '  1) 传入 --key <hex> 手动提供密钥；\n' +
        '  2) 用上游工具/任务管理器导出内存 dump 后 --dump <file>；\n' +
        '  3) 显式传入 --allow-memory-scan 启用实验性实时扫描。'
    );
  }
  if (platform === 'win') return scanProcessMemoryWindows(pid);
  if (platform === 'mac') {
    throw new Error(
      'macOS 实时内存读取受 SIP 限制。请：\n' +
        '  a) 用 --key <hex> 手动提供（推荐）；\n' +
        '  b) 运行 `node bin/wcdb.js key --lldb-script --pid ' +
        pid +
        '` 生成 lldb 模板，sudo 导出 dump 后 --dump。'
    );
  }
  throw new Error('未知平台，请使用 --key 或 --dump');
}

module.exports = {
  xorDecode,
  looksLikeSalt,
  collectCandidates,
  extractKeysFromDump,
  findWeixinPid,
  scanProcessMemoryWindows,
  generateMacLldbScript,
  extractKeys
};
