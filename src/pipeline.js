'use strict';

/**
 * 一键流水线：授权通过后自动完成「取密钥 → 解密 → 提取 → 报告」。
 * 供 agent（WorkBuddy / CodeBuddy / Qoder / Claude 等）在宿主弹出权限确认窗、
 * 用户点同意后调用，实现「点一下授权就解出微信消息」。
 *
 * 设计要点：
 * - resolveKeySource() 为纯函数（无 I/O），便于单测与平台门禁（Win/Mac 互斥）。
 * - 所有平台相关能力（frida / Windows 内存扫描）均为惰性调用，不在加载期生效。
 */

const fs = require('fs');

const { detectPlatform, resolveDataDir } = require('./platform');
const { extractKeysFromDump, extractKeys } = require('./keyExtract');
const { capturePassphraseViaFrida } = require('./macKeyFrida');
const { decryptSelective } = require('./decrypt');
const { openPlain, extractChat, loadContacts } = require('./extract');
const { writeReport } = require('./report');

function normalizeKey(k) {
  return String(k).replace(/^0x/, '').toLowerCase();
}

/**
 * 决策密钥来源（纯函数，无 I/O，可测）。
 * 优先级：manual > provided > dump > mac-frida(仅 macOS) > win-memory-scan(仅 Windows)
 * 平台互斥：非 macOS 传 --mac-frida、非 Windows 传 --allow-memory-scan 均抛错。
 * @param {object} opts
 * @returns {'manual'|'provided'|'dump'|'mac-frida'|'win-memory-scan'}
 */
function resolveKeySource(opts = {}) {
  const platform = detectPlatform();
  if (opts.key) return 'manual';
  if (opts.candidates && opts.candidates.length) return 'provided';
  if (opts.dump) return 'dump';
  if (opts.macFrida) {
    if (platform !== 'mac') {
      throw new Error('--mac-frida 仅适用于 macOS，当前平台：' + platform);
    }
    return 'mac-frida';
  }
  if (opts.allowMemoryScan) {
    if (platform !== 'win') {
      throw new Error(
        '--allow-memory-scan 仅适用于 Windows（macOS 受 SIP 限制，请用 --mac-frida 或 --dump），当前平台：' +
          platform
      );
    }
    return 'win-memory-scan';
  }
  throw new Error(
    '缺少密钥来源。请提供 --key <hex> / --dump <file> / --keys <file>；' +
      'macOS 可用 --mac-frida，Windows 可用 --allow-memory-scan'
  );
}

/**
 * 按来源实际获取 passphrase 候选（含 I/O 与平台原生调用）。
 * @param {object} opts
 * @param {string} source resolveKeySource 的返回值
 * @returns {Promise<string[]>}
 */
async function obtainCandidates(opts, source) {
  switch (source) {
    case 'manual':
      return [normalizeKey(opts.key)];
    case 'provided':
      return opts.candidates;
    case 'dump':
      if (!fs.existsSync(opts.dump)) throw new Error('dump 文件不存在：' + opts.dump);
      return extractKeysFromDump(opts.dump);
    case 'mac-frida': {
      const ph = await capturePassphraseViaFrida({ out: opts.passphraseOut });
      return [ph];
    }
    case 'win-memory-scan':
      return extractKeys({ pid: opts.pid, allowMemoryScan: true });
    default:
      throw new Error('未知密钥来源：' + source);
  }
}

/**
 * 一键流水线主入口。
 * @param {object} opts
 * @param {string} [opts.dir] db_storage 目录（不传则按平台自动定位）
 * @param {string} [opts.wxid] 本账号 wxid（辅助定位数据目录）
 * @param {string} opts.username 要提取的会话 wxid / 群 id
 * @param {string} [opts.selfWxid] 本账号 wxid（判定“自己发的”）
 * @param {string} [opts.outDir] 明文输出目录，默认 plain
 * @param {string} [opts.outJson] messages.json 路径
 * @param {string} [opts.outHtml] report.html 路径
 * @returns {Promise<object>} 结果摘要
 */
async function runPipeline(opts = {}) {
  const outDir = opts.outDir || 'plain';
  const jsonOut = opts.outJson || 'messages.json';
  const htmlOut = opts.outHtml || 'report.html';
  const selfWxid = opts.selfWxid || 'self';

  const dir = opts.dir || resolveDataDir({ wxid: opts.wxid });
  if (!dir) {
    throw new Error(
      '无法确定微信 db_storage 目录，请用 --dir 指定（Windows 形如 D:\\xwechat_files\\<wxid>\\db_storage）'
    );
  }
  if (!opts.username) {
    throw new Error('缺少 --username：请指定要提取的会话 wxid 或群 id');
  }

  const source = resolveKeySource(opts);
  const candidates = await obtainCandidates(opts, source);
  if (!candidates || !candidates.length) throw new Error('未获得任何 passphrase 候选');

  const decrypted = await decryptSelective(dir, candidates, outDir, opts.files);
  if (!decrypted.length) {
    throw new Error('未成功解密任何数据库，请确认密钥来源与数据目录正确');
  }

  const outPaths = decrypted.map((r) => r.outPath);
  const msgDbPath = outPaths.find((p) => /message_\d+\.plain\.db$/.test(p));
  if (!msgDbPath) throw new Error('解密结果中没有 message_*.plain.db，无法提取消息');

  const contactPath = outPaths.find((p) => /contact\.plain\.db$/.test(p));
  const contacts = contactPath ? loadContacts(contactPath) : {};

  const db = openPlain(msgDbPath);
  let chat;
  try {
    chat = await extractChat(db, opts.username, { selfWxid });
  } finally {
    db.close();
  }

  const payload = {
    selfWxid,
    contacts,
    chats: [chat],
    meta: { dataDir: dir, keySource: source, decryptedFiles: decrypted.length }
  };
  fs.writeFileSync(jsonOut, JSON.stringify(payload, null, 2), 'utf8');
  writeReport(htmlOut, payload);

  return {
    keySource: source,
    dataDir: dir,
    decryptedFiles: decrypted.length,
    count: chat.count,
    jsonOut,
    htmlOut
  };
}

module.exports = { resolveKeySource, obtainCandidates, runPipeline };
