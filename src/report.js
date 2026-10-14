'use strict';

/**
 * 报告输出层：把同一份数据渲染成 html / md / json（可同时多种），
 * 也支持载入用户自定义模板。内置模板见 src/templates/。
 */

const fs = require('fs');
const templates = require('./templates');
const { escapeHtml } = require('./templates/helpers');

/**
 * 渲染报告字符串。
 * @param {object} data { chats, contacts, selfWxid, meta }
 * @param {string} [format] html | md | json
 * @param {object} [opts] 透传给模板；opts.template 存在时走自定义模板
 * @returns {string}
 */
function buildReport(data, format = 'html', opts = {}) {
  if (opts.template) return templates.renderWithTemplate(opts.template, data, opts);
  return templates.render(format, data, opts);
}

/**
 * 写入单个报告文件。格式优先级：opts.format > 输出路径扩展名推断 > html。
 * @returns {string} 实际写入的路径
 */
function writeReport(outPath, data, opts = {}) {
  const format = opts.format || templates.detectFormat(outPath) || 'html';
  fs.writeFileSync(outPath, buildReport(data, format, opts), 'utf8');
  return outPath;
}

/**
 * 一次写出多种格式的报告（同一基准路径，扩展名按格式改写）。
 * @param {string} basePath 基准路径，如 report.html
 * @param {object} data
 * @param {string[]} [formats] ['html','md','json']，默认 ['html']
 * @param {object} [opts] { template, compact }
 * @returns {Array<{format:string, path:string}>}
 */
function writeReports(basePath, data, formats, opts = {}) {
  const list = formats && formats.length ? formats : ['html'];
  return list.map((f) => {
    const id = templates.normalizeFormat(f);
    if (!id) {
      throw new Error(
        '未知报告格式：' + f + '（可选：' + templates.listFormats().map((x) => x.id).join(', ') + '）'
      );
    }
    const target = templates.outPathFor(basePath, id);
    fs.writeFileSync(target, buildReport(data, id, opts), 'utf8');
    return { format: id, path: target };
  });
}

module.exports = {
  buildReport,
  writeReport,
  writeReports,
  renderReport: buildReport,
  escapeHtml,
  templates,
  listFormats: templates.listFormats,
  normalizeFormat: templates.normalizeFormat,
  detectFormat: templates.detectFormat,
  outPathFor: templates.outPathFor
};
