'use strict';

const fs = require('fs');

function escapeHtml(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function resolveName(wxid, contacts, selfWxid) {
  if (wxid === selfWxid) return '我(' + wxid + ')';
  return (contacts && contacts[wxid]) || wxid;
}

/**
 * 生成自包含 HTML 报告字符串。
 * @param {object} data
 * @param {Array<object>} data.chats extractChat 返回结果数组
 * @param {Object<string,string>} [data.contacts] wxid -> 昵称
 * @param {string} [data.selfWxid]
 * @returns {string}
 */
function buildReport(data) {
  const chats = data.chats || [];
  const contacts = data.contacts || {};
  const selfWxid = data.selfWxid || 'self';
  const generatedAt = new Date().toLocaleString('zh-CN');

  const sections = chats
    .map((chat) => {
      const rows = chat.messages
        .map((m) => {
          const name = escapeHtml(resolveName(m.sender, contacts, selfWxid));
          const time = escapeHtml(m.create_time_iso || m.create_time || '');
          const content = escapeHtml(m.content);
          const cls = m.is_self ? 'self' : '';
          return `<tr class="${cls}"><td class="t">${time}</td><td class="s">${name}</td><td class="c">${content}</td></tr>`;
        })
        .join('\n');
      return `
      <section>
        <h2>会话：${escapeHtml(chat.username)} <small>(${chat.count} 条，表 ${escapeHtml(chat.table)})</small></h2>
        <table>
          <thead><tr><th>时间</th><th>发送者</th><th>内容</th></tr></thead>
          <tbody>
          ${rows}
          </tbody>
        </table>
      </section>`;
    })
    .join('\n');

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>微信聊天记录报告</title>
<style>
  body { font-family: -apple-system, "PingFang SC", "Microsoft YaHei", sans-serif; margin: 24px; color: #222; }
  h1 { font-size: 20px; }
  h2 { font-size: 16px; margin-top: 28px; border-bottom: 1px solid #eee; padding-bottom: 6px; }
  table { border-collapse: collapse; width: 100%; font-size: 13px; }
  th, td { border: 1px solid #e0e0e0; padding: 6px 8px; text-align: left; vertical-align: top; }
  th { background: #fafafa; }
  td.t { white-space: nowrap; color: #888; width: 180px; }
  td.s { white-space: nowrap; width: 140px; color: #1a73e8; }
  tr.self td.s { color: #d93025; }
  td.c { word-break: break-word; }
  .meta { color: #999; font-size: 12px; }
</style>
</head>
<body>
  <h1>微信桌面版 4.x 聊天记录报告</h1>
  <p class="meta">生成时间：${escapeHtml(generatedAt)} ｜ 共 ${chats.length} 个会话 ｜ 本机离线生成，数据未上传</p>
  ${sections || '<p>无数据</p>'}
</body>
</html>`;
}

/**
 * 写入报告文件。
 */
function writeReport(outPath, data) {
  const html = buildReport(data);
  fs.writeFileSync(outPath, html, 'utf8');
  return outPath;
}

module.exports = { buildReport, writeReport, escapeHtml };
