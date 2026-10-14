'use strict';

const crypto = require('crypto');

/**
 * 纯 JS 实现 WCDB / SQLCipher 4 页面解密（无需原生编译，Win / macOS 一致）。
 * 参数来源：wechat-chatlog-export-mac（实测，微信 4.1.11）。
 *
 * 页大小 4096，AES-256-CBC，HMAC-SHA512。
 *  page 1：[0:16] salt | [16:4016] 密文 | [4016:4032] IV | [4032:4096] HMAC
 *  page N：[0:4016] 密文 | [4016:4032] IV | [4032:4096] HMAC
 *  mac_salt = salt XOR 0x3A；mac_key = PBKDF2-HMAC-SHA512(enc_key, mac_salt, 2, 32)
 *  HMAC 覆盖：page1 = [16:4032]，pageN = [0:4032]
 *  解密后 page1 前 16 字节还原为 "SQLite format 3\0"
 *
 * 说明：WCDB 在每页尾部保留 IV(16)+HMAC(64)=80 字节（reserved 区），
 * 明文页的这 80 字节本就是 SQLCipher 保留区（零），故还原时末 80 字节留零即可，
 * 且明文 SQLite 文件头 reserved 字段应为 80。
 */

const PAGE_SIZE = 4096;
const HMAC_SALT_MASK = 0x3a;

function xorMaskSalt(salt) {
  const out = Buffer.allocUnsafe(16);
  for (let i = 0; i < 16; i++) out[i] = salt[i] ^ HMAC_SALT_MASK;
  return out;
}

function computeMacKey(encKeyBuf, salt) {
  const macSalt = xorMaskSalt(salt);
  return crypto.pbkdf2Sync(encKeyBuf, macSalt, 2, 32, 'sha512');
}

/**
 * 解密整个加密库文件为明文 SQLite 字节流。
 * @param {Buffer} encBuf 加密库完整字节
 * @param {string} encKeyHex 64 hex（32 字节 enc_key）
 * @returns {Buffer} 明文 SQLite 字节（reserved 区为零）
 */
function decryptBuffer(encBuf, encKeyHex) {
  const encKeyBuf = Buffer.from(encKeyHex, 'hex');
  if (encBuf.length % PAGE_SIZE !== 0) {
    throw new Error(`文件大小 ${encBuf.length} 不是 ${PAGE_SIZE} 的整数倍`);
  }
  const salt = encBuf.subarray(0, 16);
  const macKey = computeMacKey(encKeyBuf, salt);
  const out = Buffer.alloc(encBuf.length); // 末 80 字节默认零（reserved）

  const pageCount = encBuf.length / PAGE_SIZE;
  for (let p = 0; p < pageCount; p++) {
    const off = p * PAGE_SIZE;
    const page = encBuf.subarray(off, off + PAGE_SIZE);
    const isFirst = p === 0;
    const iv = page.subarray(4016, 4032);
    const storedHmac = page.subarray(4032, 4096);
    const covered = isFirst ? page.subarray(16, 4032) : page.subarray(0, 4032);
    const computedHmac = crypto.createHmac('sha512', macKey).update(covered).digest();
    if (computedHmac.length !== storedHmac.length || !crypto.timingSafeEqual(computedHmac, storedHmac)) {
      throw new Error(`第 ${p} 页 HMAC 校验失败：enc_key 错误（或参数不匹配）`);
    }
    const cipher = isFirst ? page.subarray(16, 4016) : page.subarray(0, 4016);
    const decipher = crypto.createDecipheriv('aes-256-cbc', encKeyBuf, iv);
    decipher.setAutoPadding(false);
    const pt = Buffer.concat([decipher.update(cipher), decipher.final()]);

    if (isFirst) {
      out.write('SQLite format 3\u0000', 0, 'binary');
      pt.copy(out, 16, 0, pt.length);
    } else {
      pt.copy(out, off, 0, pt.length);
    }
  }
  return out;
}

/**
 * 解密单个加密库文件到明文文件。
 * @param {string} encPath
 * @param {string} encKeyHex
 * @param {string} outPath
 */
function decryptFile(encPath, encKeyHex, outPath) {
  const encBuf = require('fs').readFileSync(encPath);
  const plain = decryptBuffer(encBuf, encKeyHex);
  require('fs').writeFileSync(outPath, plain);
  return outPath;
}

/**
 * 加密（仅用于自测：与 decryptBuffer 互逆，用于构造合成 WCDB 库验证解密）。
 * 明文要求：每页末 80 字节为零（模拟 SQLCipher reserved 区）。
 * @param {Buffer} plainBuf
 * @param {string} encKeyHex
 * @returns {Buffer}
 */
function encryptBuffer(plainBuf, encKeyHex) {
  const encKeyBuf = Buffer.from(encKeyHex, 'hex');
  if (plainBuf.length % PAGE_SIZE !== 0) throw new Error('plaintext 大小须为 4096 整数倍');
  const out = Buffer.alloc(plainBuf.length);
  const salt = plainBuf.subarray(0, 16); // 用首页前 16 字节作 salt（实际为随机，测试无妨）
  const macKey = computeMacKey(encKeyBuf, salt);
  const pageCount = plainBuf.length / PAGE_SIZE;
  for (let p = 0; p < pageCount; p++) {
    const off = p * PAGE_SIZE;
    const page = plainBuf.subarray(off, off + PAGE_SIZE);
    const isFirst = p === 0;
    const iv = crypto.randomBytes(16);
    const plaintextData = isFirst ? page.subarray(16, 4016) : page.subarray(0, 4016);
    const cipher = crypto.createCipheriv('aes-256-cbc', encKeyBuf, iv);
    cipher.setAutoPadding(false);
    const ct = Buffer.concat([cipher.update(plaintextData), cipher.final()]);
    if (isFirst) {
      salt.copy(out, off, 0, 16); // salt 明文存放
      ct.copy(out, off + 16, 0, ct.length);
    } else {
      ct.copy(out, off, 0, ct.length);
    }
    iv.copy(out, off + 4016, 0, 16);
    const covered = isFirst ? out.subarray(off + 16, off + 4032) : out.subarray(off, off + 4032);
    const hmac = crypto.createHmac('sha512', macKey).update(covered).digest();
    hmac.copy(out, off + 4032, 0, 64);
  }
  return out;
}

module.exports = { PAGE_SIZE, decryptBuffer, decryptFile, encryptBuffer, computeMacKey };
