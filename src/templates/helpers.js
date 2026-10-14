'use strict';

/**
 * 报告模板公共辅助层。
 *
 * 所有内置模板（html / md / json）共用同一份归一化结果（normalizeReport），
 * 保证同一份 messages.json 在不同格式下字段语义完全一致，
 * 便于其它应用（脚本 / agent / 数据管道）直接消费。
 */

/** HTML 转义。 */
function escapeHtml(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Markdown 表格单元格转义：
 * 反斜杠与竖线会破坏表格结构，换行会让行断裂，统一转义。
 */
function escapeMdCell(s) {
  if (s == null) return '';
  return String(s)
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|')
    .replace(/\r\n|\r|\n/g, '<br>');
}

/** wxid -> 展示名（自己显示为「我(wxid)」，否则取通讯录昵称，兜底 wxid）。 */
function resolveName(wxid, contacts, selfWxid) {
  if (wxid === selfWxid) return '我(' + wxid + ')';
  return (contacts && contacts[wxid]) || wxid;
}

/** 人类可读时间（Markdown 用）；ISO 去掉 T 与毫秒。 */
function displayTime(m) {
  if (!m) return '';
  const iso = m.create_time_iso || (m.create_time ? new Date(m.create_time * 1000).toISOString() : null);
  if (!iso) return '';
  return String(iso).replace('T', ' ').replace(/\.\d+Z?$/, '');
}

/**
 * 归一化报告数据。
 * @param {object} data { chats, contacts, selfWxid, meta }
 * @returns {{meta:object, selfWxid:string, contacts:object, chats:Array<object>}}
 */
function normalizeReport(data) {
  const src = data || {};
  const now = new Date();
  const rawChats = Array.isArray(src.chats) ? src.chats : [];
  const contacts = src.contacts || {};
  const selfWxid = src.selfWxid || 'self';
  let messageCount = 0;

  const chats = rawChats.map((chat) => {
    const messages = (chat.messages || []).map((m) => {
      const sender = m.sender || selfWxid;
      const createTime = m.create_time == null ? null : m.create_time;
      return {
        local_id: m.local_id == null ? null : m.local_id,
        sender,
        sender_name: resolveName(sender, contacts, selfWxid),
        is_self: m.is_self === undefined ? sender === selfWxid : !!m.is_self,
        local_type: m.local_type == null ? null : m.local_type,
        create_time: createTime,
        create_time_iso:
          m.create_time_iso || (createTime ? new Date(createTime * 1000).toISOString() : null),
        content: m.content == null ? '' : m.content
      };
    });
    messageCount += messages.length;
    return {
      username: chat.username,
      title: (contacts && contacts[chat.username]) || chat.username,
      table: chat.table || '',
      count: messages.length,
      messages
    };
  });

  const meta = Object.assign({}, src.meta || {}, {
    tool: 'wechat-wcdb-node',
    schemaVersion: 1,
    generatedAt: now.toISOString(),
    generatedAtLocal: now.toLocaleString('zh-CN'),
    selfWxid,
    chatCount: chats.length,
    messageCount
  });

  return { meta, selfWxid, contacts, chats };
}

module.exports = { escapeHtml, escapeMdCell, resolveName, displayTime, normalizeReport };
