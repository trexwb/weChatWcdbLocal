'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const Database = require('better-sqlite3');

const { msgTableName, WINDOWS_CONFIG_XOR_MASK } = require('../src/constants');
const { isZstd, decompress, compress } = require('../src/zstd');
const { xorDecode, collectCandidates } = require('../src/keyExtract');
const { extractChat } = require('../src/extract');
const { deriveEncKey } = require('../src/decrypt');
const { decryptBuffer, encryptBuffer, PAGE_SIZE } = require('../src/wcdbDecode');

let pass = 0;
let fail = 0;
function assert(cond, msg) {
  if (cond) {
    pass++;
    // eslint-disable-next-line no-console
    console.log('  ✓ ' + msg);
  } else {
    fail++;
    // eslint-disable-next-line no-console
    console.error('  ✗ ' + msg);
  }
}

// ── 1. zstd 往返 ──
async function testZstd() {
  // eslint-disable-next-line no-console
  console.log('[zstd]');
  const data = Buffer.from('微信聊天记录压缩测试 '.repeat(50));
  const c = await compress(data);
  assert(isZstd(c), 'compress 产物带 zstd magic');
  const d = await decompress(c);
  assert(Buffer.compare(d, data) === 0, '解压后与原文一致');
}

// ── 2. msgTableName ──
function testTableName() {
  // eslint-disable-next-line no-console
  console.log('[msgTableName]');
  const expect = 'Msg_' + crypto.createHash('md5').update('testuser', 'utf8').digest('hex');
  assert(msgTableName('testuser') === expect, 'Msg_ + md5(username) 正确');
}

// ── 3. XOR 往返 + 候选收集 ──
function testKey() {
  // eslint-disable-next-line no-console
  console.log('[keyExtract]');
  const buf = crypto.randomBytes(200);
  const twice = xorDecode(xorDecode(buf, WINDOWS_CONFIG_XOR_MASK), WINDOWS_CONFIG_XOR_MASK);
  assert(Buffer.compare(twice, buf) === 0, 'xorDecode(xorDecode(buf)) === buf');

  const decoded = crypto.randomBytes(256);
  const key = crypto.randomBytes(32);
  const salt = crypto.randomBytes(16);
  key.copy(decoded, 10);
  salt.copy(decoded, 42);
  const cands = collectCandidates(decoded);
  assert(cands.includes(key.toString('hex')), 'collectCandidates 能回收嵌入的 32B 密钥');
}

// ── 5. deriveEncKey（passphrase + 每库 salt -> enc_key，SQLCipher4 派生）──
function testDerive() {
  // eslint-disable-next-line no-console
  console.log('[deriveEncKey]');
  const ph = 'a'.repeat(64); // 32 字节 passphrase（hex）
  const salt = Buffer.from('salt-salt-salt-01'); // 16 字节
  const k1 = deriveEncKey(ph, salt, 256000);
  const k2 = deriveEncKey(ph, salt, 256000);
  assert(k1 === k2, '同参派生稳定一致');
  assert(/^[0-9a-f]{64}$/.test(k1), 'enc_key 为 64 hex（32 字节）');
  const k3 = deriveEncKey(ph, Buffer.from('salt-salt-salt-02'), 256000);
  assert(k1 !== k3, '不同 db salt 派生出不同 enc_key（符合每库独立密钥）');
}

// ── 6. 纯 JS WCDB 页面解码往返（AES-256-CBC + HMAC-SHA512 + IV）──
function testWcdbDecode() {
  // eslint-disable-next-line no-console
  console.log('[wcdbDecode]');
  // 构造合成「明文 SQLite」：每页 4096，末 80 字节为零（模拟 reserved 区）
  const pages = 3;
  const plain = Buffer.alloc(PAGE_SIZE * pages);
  plain.write('SQLite format 3\0', 0, 'binary');
  // 写入一些非零内容到每页数据区
  for (let i = 0; i < pages; i++) {
    const base = i * PAGE_SIZE;
    for (let j = 0; j < 200; j++) plain[base + 16 + j] = (i * 31 + j) & 0xff;
  }
  const encKey = 'f'.repeat(64); // 32 字节 enc_key
  const enc = encryptBuffer(plain, encKey);
  const dec = decryptBuffer(enc, encKey);
  assert(Buffer.compare(dec, plain) === 0, '加密后再解密与原文逐字节一致');
  assert(dec.subarray(0, 16).equals(Buffer.from('SQLite format 3\0', 'binary')), '解密后首页 magic 正确');

  // 错误密钥应触发 HMAC 校验失败
  let threw = false;
  try {
    decryptBuffer(enc, '0'.repeat(64));
  } catch (e) {
    threw = true;
  }
  assert(threw, '错误 enc_key 触发 HMAC 校验失败（反例）');
}

// ── 4. 合成明文库 + 完整提取 ──
async function testExtract() {
  // eslint-disable-next-line no-console
  console.log('[extract]');
  const tmp = path.join(os.tmpdir(), 'wcdb_selftest_' + Date.now() + '.db');
  if (fs.existsSync(tmp)) fs.unlinkSync(tmp);
  const db = new Database(tmp);
  const table = msgTableName('testuser');
  db.exec(`
    CREATE TABLE "${table}" (
      localId INTEGER,
      real_sender_id INTEGER,
      local_type INTEGER,
      create_time INTEGER,
      message_content TEXT,
      compress_content BLOB
    )
  `);
  const insert = db.prepare(
    `INSERT INTO "${table}" (localId, real_sender_id, local_type, create_time, message_content, compress_content)
     VALUES (@localId, @sid, @type, @ct, @msg, @cmp)`
  );
  const rows = [
    { localId: 1, sid: 7, type: 1, ct: 1700000000, msg: 'wxid_abc:\n大家好', cmp: null },
    { localId: 2, sid: 8, type: 1, ct: 1700000100, msg: 'wxid_def:\n收到', cmp: null },
    { localId: 3, sid: 7, type: 1, ct: 1700000200, msg: '第二条来自 abc', cmp: null },
    { localId: 4, sid: 99, type: 1, ct: 1700000300, msg: '我发的（无前缀无映射）', cmp: null },
    { localId: 5, sid: 7, type: 1, ct: 1700000400, msg: null, cmp: await compress(Buffer.from('wxid_abc:\n压缩消息')) },
    { localId: 6, sid: 8, type: 244813135921, ct: 1700000500, msg: '类型消息', cmp: null }
  ];
  const tx = db.transaction(() => rows.forEach((r) => insert.run(r)));
  tx();

  const chat = await extractChat(db, 'testuser', { selfWxid: 'me' });
  db.close();
  fs.unlinkSync(tmp);

  assert(chat.count === 6, '提取 6 条消息（实际 ' + chat.count + '）');
  assert(
    chat.messages[0].sender === 'wxid_abc' && chat.messages[0].content === '大家好',
    '前缀解析：发送者 wxid_abc，正文去前缀'
  );
  assert(chat.messages[2].sender === 'wxid_abc', 'real_sender_id 反推：sid=7 -> wxid_abc');
  assert(
    chat.messages[3].sender === 'me' && chat.messages[3].is_self === true,
    '无前缀且无映射 -> 本人'
  );
  assert(chat.messages[4].content === '压缩消息', 'compress_content 列 zstd 解压成功');
  assert(chat.messages[5].local_type === 49, 'local_type 低 32 位掩码：244813135921 -> 49');
}

(async function main() {
  testTableName();
  testKey();
  testDerive();
  testWcdbDecode();
  await testZstd();
  await testExtract();
  // eslint-disable-next-line no-console
  console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
  process.exit(fail ? 1 : 0);
})().catch((e) => {
  // eslint-disable-next-line no-console
  console.error(e);
  process.exit(1);
});
