'use strict';

const { normalizeReport } = require('./helpers');

/**
 * 生成 JSON 字符串（面向其它应用消费）。
 * 相比 extract 直接写出的 messages.json，这里额外补充：
 * - meta：生成时间 / schemaVersion / 会话数与消息数（含 pipeline 的 dataDir 等）
 * - 每条消息的 sender_name（已解析昵称）、缺失的 create_time_iso
 *
 * @param {object} data
 * @param {object} [opts]
 * @param {boolean} [opts.compact] 压成单行（默认按 2 空格缩进）
 * @param {number} [opts.indent] 自定义缩进，0 等价于 compact
 */
function render(data, opts = {}) {
  const r = normalizeReport(data);
  const payload = {
    meta: r.meta,
    selfWxid: r.selfWxid,
    contacts: r.contacts,
    chats: r.chats
  };
  let indent = 2;
  if (typeof opts.indent === 'number') indent = opts.indent;
  if (opts.compact) indent = 0;
  return JSON.stringify(payload, null, indent);
}

module.exports = {
  id: 'json',
  ext: '.json',
  description: 'JSON 报告（带 meta 与昵称解析，供其它应用直接解析）',
  render
};
