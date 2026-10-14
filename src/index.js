'use strict';

/**
 * 公共 API 汇总（供以库方式 require 使用；CLI 见 bin/wcdb.js）。
 * 所有平台相关代码均已隔离，本入口跨 Windows / macOS 安全加载。
 */

const { detectPlatform, resolveWindowsDataDir, resolveMacDataDir, resolveDataDir } = require('./platform');
const { xorDecode, collectCandidates, extractKeysFromDump, extractKeys, scanProcessMemoryWindows, generateMacLldbScript } = require('./keyExtract');
const { capturePassphraseViaFrida, DEFAULT_PASSPHRASE_PATH } = require('./macKeyFrida');
const { decryptDatabase, decryptSelective } = require('./decrypt');
const { openPlain, extractChat, loadContacts } = require('./extract');
const { buildReport, writeReport } = require('./report');
const { msgTableName, WINDOWS_CONFIG_XOR_MASK, ZSTD_MAGIC } = require('./constants');

module.exports = {
  // platform
  detectPlatform,
  resolveWindowsDataDir,
  resolveMacDataDir,
  resolveDataDir,
  // key extraction
  xorDecode,
  collectCandidates,
  extractKeysFromDump,
  extractKeys,
  scanProcessMemoryWindows,
  generateMacLldbScript,
  // mac frida
  capturePassphraseViaFrida,
  DEFAULT_PASSPHRASE_PATH,
  // decrypt
  decryptDatabase,
  decryptSelective,
  // extract
  openPlain,
  extractChat,
  loadContacts,
  // report
  buildReport,
  writeReport,
  // constants
  msgTableName,
  WINDOWS_CONFIG_XOR_MASK,
  ZSTD_MAGIC
};
