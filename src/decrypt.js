'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { decryptBuffer } = require('./wcdbDecode');

/**
 * WCDB / SQLCipher 4 解密参数（已实测，来源：wechat-chatlog-export-mac）。
 * - 页大小 4096，AES-256-CBC
 * - page 1: [0:16] salt | [16:4016] 密文 | [4016:4032] IV | [4032:4096] HMAC-SHA512
 * - page N: [0:4016] 密文 | [4016:4032] IV | [4032:4096] HMAC-SHA512
 * - enc_key = PBKDF2-HMAC-SHA512(passphrase, db_salt, ITER, 32)
 * - mac_salt = db_salt XOR 0x3A；mac_key = PBKDF2-HMAC-SHA512(enc_key, mac_salt, 2, 32)
 *   （mac_salt / mac_key 由 sqlcipher 模块按 SQLCipher4 默认自动完成，
 *     我们只需传入原始 enc_key 与对应 PRAGMA）
 */
const PAGE_SIZE = 4096;
const KDF_ITERS = [256000, 64000]; // 优先 4.x 实测值，回退 3.x 常见值

function lazySqlcipher() {
  try {
    // eslint-disable-next-line global-require
    return require('sqlcipher');
  } catch (e) {
    throw new Error(
      '缺少 sqlcipher 原生模块。请先完成原生编译：\n' +
        '  npm install sqlcipher\n' +
        '  （需要 python3 与 C 编译器：Windows 装 VS Build Tools，macOS 装 Xcode Command Line Tools）\n' +
        '若编译困难，可改用外部工具（官方 sqlcipher CLI / DB Browser for SQLite 的 SQLCipher 版）解密为明文后，\n' +
        '用本工具的 --plaintext 模式直接提取。\n原始错误: ' +
        e.message
    );
  }
}

function dbRun(db, sql) {
  return new Promise((resolve, reject) => {
    db.run(sql, (err) => (err ? reject(err) : resolve()));
  });
}

function dbAll(db, sql) {
  return new Promise((resolve, reject) => {
    db.all(sql, (err, rows) => (err ? reject(err) : resolve(rows || [])));
  });
}

function closeDb(db) {
  return new Promise((resolve) => {
    if (!db) return resolve();
    db.close(() => resolve());
  });
}

/**
 * 由 passphrase + 该 db 首页 salt 派生 enc_key。
 * @param {string} passphraseHex 32 字节 hex
 * @param {Buffer} salt 该库首页前 16 字节
 * @param {number} iter
 * @returns {string} enc_key hex
 */
function deriveEncKey(passphraseHex, salt, iter) {
  const out = crypto.pbkdf2Sync(Buffer.from(passphraseHex, 'hex'), salt, iter, 32, 'sha512');
  return out.toString('hex');
}

/**
 * 用单一 enc_key + SQLCipher4 PRAGMA 尝试打开加密库。
 * 成功返回 db 句柄，失败抛错（调用方负责关闭）。
 */
async function tryOpenWithEncKey(encPath, encKeyHex) {
  const sqlite3 = lazySqlcipher();
  return new Promise((resolve, reject) => {
    let db;
    try {
      db = new sqlite3.Database(encPath, sqlite3.OPEN_READONLY);
    } catch (e) {
      return reject(e);
    }
    let settled = false;
    db.on('error', (err) => {
      if (!settled) {
        settled = true;
        closeDb(db).then(() => reject(err));
      }
    });
    db.serialize(() => {
      db.run('PRAGMA cipher_page_size = 4096');
      db.run('PRAGMA cipher_hmac_algorithm = HMAC_SHA512');
      db.run('PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512');
      db.run(`PRAGMA key = "x'${encKeyHex}'"`, (keyErr) => {
        if (keyErr) {
          settled = true;
          return closeDb(db).then(() => reject(keyErr));
        }
        db.all('SELECT count(*) AS c FROM sqlite_master', (e2, rows) => {
          if (settled) return;
          if (e2 || !rows || !rows[0] || rows[0].c === 0) {
            settled = true;
            return closeDb(db).then(() =>
              reject(e2 || new Error('sqlite_master 为空，密钥/参数不匹配'))
            );
          }
          settled = true;
          resolve(db);
        });
      });
    });
  });
}

/**
 * 导出为明文 SQLite 文件（KEY '' 表示不加密）。
 */
async function exportPlaintext(db, outPath) {
  await dbRun(db, `ATTACH DATABASE '${outPath}' AS plain KEY ''`);
  await dbRun(db, `SELECT sqlcipher_export('plain')`);
  await dbRun(db, `DETACH DATABASE plain`);
}

/**
 * 解密单个加密库到明文文件。
 * 优先用纯 JS 解码（无原生编译，跨平台一致）；失败再回退 sqlcipher 原生模块。
 * 自动遍历候选 passphrase × 迭代次数，首个能解出有效 SQLite 的即成功。
 * @param {string} encPath 加密 .db 路径
 * @param {string[]} passphraseCandidates hex 候选（来自 keyExtract）
 * @param {string} outPath 输出明文 .db 路径
 * @returns {Promise<{outPath:string, passphrase:string, iter:number, backend:string}>}
 */
async function decryptDatabase(encPath, passphraseCandidates, outPath) {
  if (!passphraseCandidates || !passphraseCandidates.length) {
    throw new Error('没有可用 passphrase 候选，请先运行 key 命令或传入 --key');
  }
  const encBuf = fs.readFileSync(encPath);
  const salt = encBuf.subarray(0, 16);
  let lastErr;
  for (const ph of passphraseCandidates) {
    for (const iter of KDF_ITERS) {
      const encKey = deriveEncKey(ph, salt, iter);
      // 1) 纯 JS 解码
      try {
        const plain = decryptBuffer(encBuf, encKey);
        if (!plain.subarray(0, 16).equals(Buffer.from('SQLite format 3\0', 'binary'))) {
          throw new Error('解密后首页 magic 不正确');
        }
        fs.writeFileSync(outPath, plain);
        return { outPath, passphrase: ph, iter, backend: 'js' };
      } catch (e) {
        lastErr = e;
      }
      // 2) 回退 sqlcipher 原生模块
      let r = null;
      try {
        r = await tryOpenWithEncKey(encPath, encKey);
        await exportPlaintext(r, outPath);
        await closeDb(r);
        return { outPath, passphrase: ph, iter, backend: 'sqlcipher' };
      } catch (e) {
        lastErr = e;
        if (r) await closeDb(r).catch(() => {});
      }
    }
  }
  throw new Error('所有 (passphrase × 迭代) 组合均失败，最后错误: ' + (lastErr && lastErr.message));
}

/**
 * 批量解密（仅解密必需库，避免全量 TB 级数据）。
 * 先用第一个库定位能解开的 passphrase，再用它解密全部目标库。
 * @param {string} dbDir 加密库目录
 * @param {string[]} passphraseCandidates 密钥候选
 * @param {string} outDir 明文输出目录
 * @param {string[]} [files] 指定文件名，默认只解密 message_*.db / contact.db / session.db
 * @returns {Promise<Array<object>>}
 */
async function decryptSelective(dbDir, passphraseCandidates, outDir, files) {
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  const all = fs.readdirSync(dbDir).filter((f) => f.endsWith('.db'));
  const target =
    files && files.length
      ? files
      : all.filter((f) => /^(message_\d+\.db|contact\.db|session\.db)$/.test(f));

  // 用第一个库定位可用的 passphrase
  let working = null;
  for (const f of target) {
    try {
      const tmp = path.join(outDir, '.probe.' + f + '.plain.db');
      const r = await decryptDatabase(path.join(dbDir, f), passphraseCandidates, tmp);
      working = r;
      fs.rmSync(tmp, { force: true });
      break;
    } catch (e) {
      // try next
    }
  }
  if (!working) {
    throw new Error('未能用任何候选 passphrase 解密任一数据库，请确认密钥提取正确（Mac 需 frida 抓取 passphrase）');
  }

  const results = [];
  for (const f of target) {
    const outPath = path.join(outDir, f.replace(/\.db$/, '.plain.db'));
    try {
      const r = await decryptDatabase(path.join(dbDir, f), [working.passphrase], outPath);
      results.push({ file: f, ...r });
      // eslint-disable-next-line no-console
      console.log(`[ok] ${f} -> ${outPath} (kdf_iter=${r.iter})`);
    } catch (e) {
      // eslint-disable-next-line no-console
      console.warn(`[skip] ${f}: ${e.message}`);
    }
  }
  return results;
}

module.exports = {
  PAGE_SIZE,
  KDF_ITERS,
  deriveEncKey,
  tryOpenWithEncKey,
  exportPlaintext,
  decryptDatabase,
  decryptSelective
};
