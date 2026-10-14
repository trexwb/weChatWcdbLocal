'use strict';

const { escapeHtml, normalizeReport } = require('./helpers');

/** 生成自包含 HTML 报告字符串（CSS 内联，浏览器直接打开）。 */
function render(data) {
  const r = normalizeReport(data);
  const m = r.meta;

  const sections = r.chats
    .map((chat) => {
      const rows = chat.messages
        .map((msg) => {
          const name = escapeHtml(msg.sender_name);
          const time = escapeHtml(msg.create_time_iso || msg.create_time || '');
          const content = escapeHtml(msg.content);
          const cls = msg.is_self ? 'self' : '';
          return `<tr class="${cls}"><td class="t">${time}</td><td class="s">${name}</td><td class="c">${content}</td></tr>`;
        })
        .join('\n');
      return `
      <section>
        <h2>会话：${escapeHtml(chat.title)} <small>(${chat.count} 条，表 ${escapeHtml(chat.table)})</small></h2>
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
  <p class="meta">生成时间：${escapeHtml(m.generatedAtLocal)} ｜ 共 ${m.chatCount} 个会话 / ${m.messageCount} 条消息 ｜ 本机离线生成，数据未上传</p>
  ${sections || '<p>无数据</p>'}
</body>
</html>`;
}

module.exports = {
  id: 'html',
  ext: '.html',
  description: '自包含 HTML 报告（CSS 内联，浏览器直接打开）',
  render
};
