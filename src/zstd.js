'use strict';

const { ZSTD_MAGIC } = require('./constants');

let _mod = null;
let _loading = null;

/**
 * 懒加载 @foxglove/wasm-zstd（wasm，无原生编译，跨平台一致）。
 * 该模块异步加载 wasm，须先 `await ensureZstd()` 再调用 compress/decompress。
 * @returns {Promise<object>} 模块对象（含 compress/decompress）
 */
function ensureZstd() {
  if (_mod) return Promise.resolve(_mod);
  if (_loading) return _loading;
  _loading = (async () => {
    // eslint-disable-next-line global-require
    const mod = require('@foxglove/wasm-zstd');
    if (typeof mod.isLoaded === 'object' && typeof mod.isLoaded.then === 'function') {
      await mod.isLoaded;
    }
    if (typeof mod.compress !== 'function' || typeof mod.decompress !== 'function') {
      throw new Error('@foxglove/wasm-zstd 接口异常，未找到 compress/decompress');
    }
    _mod = mod;
    return mod;
  })();
  return _loading;
}

/**
 * 判断 Buffer 是否为 zstd 压缩数据（无需加载 wasm）。
 * @param {Buffer|Uint8Array} buf
 * @returns {boolean}
 */
function isZstd(buf) {
  if (!buf || buf.length < 4) return false;
  return (
    buf[0] === ZSTD_MAGIC[0] &&
    buf[1] === ZSTD_MAGIC[1] &&
    buf[2] === ZSTD_MAGIC[2] &&
    buf[3] === ZSTD_MAGIC[3]
  );
}

/**
 * 解压 zstd 数据。
 * @foxglove/wasm-zstd 的 decompress 需提供目标容量 destSize（底层 C 接口），
 * 这里用「指数增大目标容量」的策略自动适配，避免调用方预估解压后长度。
 * @param {Buffer|Uint8Array} buf
 * @returns {Promise<Buffer>}
 */
async function decompress(buf) {
  const Z = await ensureZstd();
  const input = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let destSize = Math.max(input.length * 4, 1024);
  for (let attempt = 0; attempt < 10; attempt++) {
    try {
      return Buffer.from(Z.decompress(input, destSize));
    } catch (e) {
      destSize *= 8;
      if (destSize > 200 * 1024 * 1024) throw e;
    }
  }
  throw new Error('zstd 解压失败：目标容量超出上限');
}

/**
 * 压缩（主要用于自测与工具自身用途）。
 * @param {Buffer|Uint8Array} buf
 * @param {number} [level]
 * @returns {Promise<Buffer>}
 */
async function compress(buf, level) {
  const Z = await ensureZstd();
  const input = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  const out = level == null ? Z.compress(input) : Z.compress(input, level);
  return Buffer.from(out);
}

module.exports = { ensureZstd, isZstd, decompress, compress };
