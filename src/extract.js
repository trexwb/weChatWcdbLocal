'use strict';

const Database = require('better-sqlite3');
const { msgTableName } = require('./constants');
const { isZstd, decompress } = require('./zstd');

/**
 * 以只读方式打开明文（已解密的）SQLite 库。
 * @param {string} plainPath
 * @returns {import('better-sqlite3').Database}
 */
function openPlain(plainPath) {
  return new Database(plainPath, { readonly: true, fileMustExist: true });
}

/**
 * 列出所有消息表（Msg_<md5>）。
 * @param {import('better-sqlite3').Database} db
 * @returns {string[]}
 */
function getMessageTables(db) {
  const rows = db
    .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'")
    .all();
  return rows.map((r) => r.name);
}

/**
 * 把 BLOB/字符串内容解析为可读文本。
 * - 若为 zstd 压缩则解压；
 * - 否则按 UTF-8 解析，含大量替换字符则判定为二进制，返回占位符。
 */
async function decodeContent(bufOrStr) {
  if (bufOrStr == null) return null;
  if (typeof bufOrStr === 'string') return bufOrStr;
  let buf = Buffer.isBuffer(bufOrStr) ? bufOrStr : Buffer.from(bufOrStr);
  if (isZstd(buf)) {
    try {
      buf = await decompress(buf);
    } catch (e) {
      return buf.toString('utf8');
    }
  }
  const s = buf.toString('utf8');
  // 粗略判别二进制：出现替换字符且解码长度远小于原始
  if (s.includes('�') && s.length < buf.length / 2) return '[binary/protobuf]';
  return s;
}

/**
 * 兼容不同微信版本的字段命名，解析出列名映射。
 */
function resolveColumns(db, table) {
  const info = db.prepare(`PRAGMA table_info("${table}")`).all();
  const cols = info.map((c) => c.name);
  const find = (...names) => names.find((n) => cols.includes(n)) || null;
  return {
    localId: find('localId', 'local_id', 'localid'),
    senderId: find('real_sender_id', 'real_sender_id', 'TalkerId', 'talkerId', 'talker_id'),
    localType: find('local_type', 'localType', 'localtype', 'Type', 'type'),
    createTime: find('create_time', 'createTime', 'CreateTime', 'createtime'),
    msg: find('message_content', 'messageContent', 'Message', 'message', 'str_content', 'strContent'),
    compress: find('compress_content', 'compressContent', 'Message2', 'message2', 'compress_content'),
    hasColumns: cols
  };
}

const PREFIX_RE = /^([A-Za-z0-9_@-]+):\n/;

/**
 * 构建 (real_sender_id -> wxid) 映射。
 * 原理：群文本消息内容形如 `wxid_xxx:\n正文`，该行的 senderId 即发送者 xxx 的本地索引。
 * 全表扫描所有文本消息，用前缀实证建立映射。
 */
async function buildSenderMap(db, table, cols) {
  const map = {};
  const sql = `SELECT "${cols.senderId}" AS sid, "${cols.msg}" AS m, "${cols.compress}" AS c FROM "${table}"`;
  const rows = db.prepare(sql).all();
  for (const row of rows) {
    const text = await decodeContent(row.m != null ? row.m : row.c);
    if (!text) continue;
    const m = text.match(PREFIX_RE);
    if (m && row.sid != null) map[row.sid] = m[1];
  }
  return map;
}

/**
 * 提取单个会话的消息。
 * @param {import('better-sqlite3').Database} db 明文消息库
 * @param {string} username 对方 wxid 或群 id
 * @param {object} [opts]
 * @param {string} [opts.selfWxid] 本账号 wxid（用于判定“自己发的消息”）
 * @returns {{username:string, table:string, count:number, messages:Array<object>}}
 */
async function extractChat(db, username, opts = {}) {
  const selfWxid = opts.selfWxid || 'self';
  const table = msgTableName(username);
  const tables = getMessageTables(db);
  if (!tables.includes(table)) {
    throw new Error(`未找到消息表 ${table}（username=${username}）。可用表: ${tables.join(', ')}`);
  }
  const cols = resolveColumns(db, table);
  if (!cols.senderId || !cols.localType) {
    throw new Error(`表 ${table} 缺少必要列（real_sender_id / local_type），实际列: ${cols.hasColumns.join(', ')}`);
  }

  const senderMap = await buildSenderMap(db, table, cols);
  const orderCol = cols.createTime || cols.localId;
  const sql = `SELECT * FROM "${table}" ORDER BY "${orderCol}" ASC`;
  const rows = db.prepare(sql).all();

  const messages = [];
  for (const row of rows) {
    const rawMsg = row[cols.msg] != null ? row[cols.msg] : row[cols.compress];
    let content = await decodeContent(rawMsg);

    let sender = null;
    const prefixMatch = content && content.match(PREFIX_RE);
    if (prefixMatch) {
      sender = prefixMatch[1];
      content = content.slice(prefixMatch[0].length);
    } else {
      const sid = row[cols.senderId];
      sender = sid != null && senderMap[sid] ? senderMap[sid] : selfWxid;
    }

    // local_type 取低 32 位（高位是子类型标志）
    const rawType = row[cols.localType];
    const localType = rawType == null ? null : (rawType >>> 0) & 0xffffffff;

    const createTime = row[cols.createTime];
    messages.push({
      local_id: row[cols.localId],
      sender,
      is_self: sender === selfWxid,
      local_type: localType,
      create_time: createTime,
      create_time_iso: createTime ? new Date(createTime * 1000).toISOString() : null,
      content
    });
  }

  return { username, table, count: messages.length, messages };
}

/**
 * 从 contact.db（明文）读取 wxid -> 昵称 映射，供报告展示。
 * @param {string} contactPlainPath
 * @returns {Object<string,string>}
 */
function loadContacts(contactPlainPath) {
  try {
    const db = openPlain(contactPlainPath);
    const info = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map((r) => r.name);
    const table = info.find((n) => /contact/i.test(n)) || info[0];
    if (!table) return {};
    const cols = db.prepare(`PRAGMA table_info("${table}")`).all().map((c) => c.name);
    const wxCol = cols.find((c) => /username|wxid|id/i.test(c)) || cols[0];
    const nameCol = cols.find((c) => /nick|name|remark|alias/i.test(c)) || cols[1];
    const rows = db.prepare(`SELECT "${wxCol}" AS w, "${nameCol}" AS n FROM "${table}"`).all();
    const map = {};
    for (const r of rows) if (r.w) map[r.w] = r.n || r.w;
    db.close();
    return map;
  } catch (e) {
    return {};
  }
}

module.exports = {
  openPlain,
  getMessageTables,
  decodeContent,
  resolveColumns,
  buildSenderMap,
  extractChat,
  loadContacts,
  PREFIX_RE
};
