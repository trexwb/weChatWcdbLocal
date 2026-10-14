'use strict';

const { escapeMdCell, displayTime, normalizeReport } = require('./helpers');

/**
 * 生成 Markdown 报告字符串。
 * 每个会话一个二级标题 + 一张表格；单元格内的 `|` 与换行已转义，
 * 表格不会被聊天内容撑坏，可直接贴进文档 / 喂给 LLM / 转 HTML。
 */
function render(data) {
  const r = normalizeReport(data);
  const m = r.meta;

  const head = [
    '# 微信桌面版 4.x 聊天记录报告',
    '',
    `> 生成时间：${m.generatedAtLocal} ｜ 共 ${m.chatCount} 个会话 / ${m.messageCount} 条消息 ｜ 本机离线生成，数据未上传`,
    ''
  ];
  if (!r.chats.length) {
    head.push('无数据', '');
    return head.join('\n');
  }

  const body = r.chats
    .map((chat) => {
      const lines = [
        `## 会话：${escapeMdCell(chat.title)}（${escapeMdCell(chat.username)}）`,
        '',
        `> ${chat.count} 条消息 ｜ 表 \`${escapeMdCell(chat.table)}\``,
        '',
        '| 时间 | 发送者 | 内容 |',
        '| --- | --- | --- |'
      ];
      for (const msg of chat.messages) {
        const content = msg.content === '' ? ' ' : escapeMdCell(msg.content);
        lines.push(
          `| ${escapeMdCell(displayTime(msg))} | ${escapeMdCell(msg.sender_name)} | ${content} |`
        );
      }
      lines.push('');
      return lines.join('\n');
    })
    .join('\n');

  // head 与 body 之间必须留空行，否则首个 '##' 会被当成引用块的惰性续行
  return head.join('\n') + '\n' + body;
}

module.exports = {
  id: 'md',
  ext: '.md',
  description: 'Markdown 报告（标题 + 表格，便于文档 / LLM / 转 HTML）',
  render
};
