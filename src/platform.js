'use strict';

const os = require('os');
const path = require('path');
const fs = require('fs');

/**
 * 判断当前操作系统平台。
 * @returns {'win'|'mac'|'other'}
 */
function detectPlatform() {
  const p = process.platform;
  if (p === 'win32') return 'win';
  if (p === 'darwin') return 'mac';
  return 'other';
}

/**
 * 读取 Windows 微信 db 根目录。
 * 微信把 db 根写进 %APPDATA%\Tencent\xwechat\config\*.ini 的首行。
 * 若读取不到则回退到常见默认路径 D:\xwechat_files\<wxid>\db_storage。
 * @param {string} [wxid] 可选，指定 wxid 以拼出默认路径
 * @returns {string|null} db_storage 目录，找不到返回 null
 */
function resolveWindowsDataDir(wxid) {
  try {
    const configDir = path.join(process.env.APPDATA || '', 'Tencent', 'xwechat', 'config');
    if (fs.existsSync(configDir)) {
      const iniFiles = fs.readdirSync(configDir).filter((f) => f.endsWith('.ini'));
      for (const f of iniFiles) {
        const firstLine = fs.readFileSync(path.join(configDir, f), 'utf8').split(/\r?\n/)[0].trim();
        if (firstLine && fs.existsSync(firstLine)) return firstLine;
      }
    }
  } catch (e) {
    // ignore，走回退路径
  }
  if (wxid) {
    const fallback = `D:\\xwechat_files\\${wxid}\\db_storage`;
    return fs.existsSync(fallback) ? fallback : null;
  }
  return null;
}

/**
 * 读取 macOS 微信 db 根目录。
 * 路径随微信版本变化，形如：
 * ~/Library/Containers/com.tencent.xinWeChat/Data/Library/Application Support/
 *   com.tencent.xinWeChat/<version>/<wxid>/db_storage
 * 这里做版本目录的通配扫描。
 * @param {string} [wxid] 可选
 * @returns {string|null}
 */
function resolveMacDataDir(wxid) {
  const base = path.join(
    os.homedir(),
    'Library',
    'Containers',
    'com.tencent.xinWeChat',
    'Data',
    'Library',
    'Application Support',
    'com.tencent.xinWeChat'
  );
  if (!fs.existsSync(base)) return null;
  let candidates = [];
  for (const ver of fs.readdirSync(base)) {
    const verDir = path.join(base, ver);
    if (!fs.statSync(verDir).isDirectory()) continue;
    if (wxid) {
      const p = path.join(verDir, wxid, 'db_storage');
      if (fs.existsSync(p)) candidates.push(p);
    } else {
      // 扫描所有子目录找 db_storage
      try {
        for (const user of fs.readdirSync(verDir)) {
          const p = path.join(verDir, user, 'db_storage');
          if (fs.existsSync(p)) candidates.push(p);
        }
      } catch (e) {
        // ignore
      }
    }
  }
  return candidates.length ? candidates[0] : null;
}

/**
 * 跨平台定位 db_storage 目录。
 * @param {object} [opts]
 * @param {string} [opts.wxid]
 * @param {string} [opts.override] 手动覆盖路径，优先级最高
 * @returns {string|null}
 */
function resolveDataDir(opts = {}) {
  if (opts.override) return opts.override;
  const platform = detectPlatform();
  if (platform === 'win') return resolveWindowsDataDir(opts.wxid);
  if (platform === 'mac') return resolveMacDataDir(opts.wxid);
  return null;
}

module.exports = {
  detectPlatform,
  resolveWindowsDataDir,
  resolveMacDataDir,
  resolveDataDir
};
