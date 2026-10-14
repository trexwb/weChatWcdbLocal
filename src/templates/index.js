'use strict';

/**
 * 报告模板注册中心。
 *
 * 内置 html / md / json 三种；新增格式只需在此注册一个
 * `{ id, ext, description, render(data, opts) }` 模块。
 * 自定义模板通过 --template <file.js> 载入，不改动仓库代码即可扩展出
 * 任意格式（csv / txt / 自定义 HTML / 推送给下游的 JSON 方言等）。
 */

const path = require('path');
const helpers = require('./helpers');
const html = require('./html');
const markdown = require('./markdown');
const json = require('./json');

const REGISTRY = { html, md: markdown, json };

const ALIAS = {
  htm: 'html',
  html: 'html',
  markdown: 'md',
  mdown: 'md',
  mdx: 'md',
  md: 'md',
  json: 'json'
};

const EXT_TO_FORMAT = {
  '.html': 'html',
  '.htm': 'html',
  '.md': 'md',
  '.markdown': 'md',
  '.mdown': 'md',
  '.json': 'json'
};

/** 可用格式清单（供 CLI --help / 错误信息展示）。 */
function listFormats() {
  return Object.keys(REGISTRY).map((id) => ({
    id,
    ext: REGISTRY[id].ext,
    description: REGISTRY[id].description
  }));
}

/** 归一化格式名；未识别返回 null。 */
function normalizeFormat(fmt) {
  if (!fmt) return null;
  const key = String(fmt).trim().toLowerCase();
  return ALIAS[key] || (REGISTRY[key] ? key : null);
}

/** 由输出文件扩展名推断格式；未识别返回 null。 */
function detectFormat(filePath) {
  if (!filePath) return null;
  return EXT_TO_FORMAT[path.extname(String(filePath)).toLowerCase()] || null;
}

/** 按格式改写输出路径的扩展名（report.html + md -> report.md）。 */
function outPathFor(base, format) {
  const id = normalizeFormat(format);
  if (!id) throw new Error('未知报告格式：' + format + '（可选：' + Object.keys(REGISTRY).join(', ') + '）');
  const target = REGISTRY[id].ext;
  const s = String(base);
  const ext = path.extname(s).toLowerCase();
  if (EXT_TO_FORMAT[ext]) {
    if (EXT_TO_FORMAT[ext] === id) return s;
    return s.slice(0, s.length - ext.length) + target;
  }
  return s + target;
}

/** 用内置模板渲染。 */
function render(format, data, opts = {}) {
  const id = normalizeFormat(format);
  if (!id) {
    throw new Error('未知报告格式：' + format + '（可选：' + Object.keys(REGISTRY).join(', ') + '，或用 --template 指定自定义模板）');
  }
  return REGISTRY[id].render(data, opts);
}

/** 载入自定义模板模块：module.exports = (data, ctx) => string 或 { render }。 */
function loadTemplateFile(tplPath) {
  const mod = require(path.resolve(tplPath));
  const fn = typeof mod === 'function' ? mod : mod && (mod.render || mod.default);
  if (typeof fn !== 'function') {
    throw new Error('自定义模板需导出 render(data, ctx) 函数：' + tplPath);
  }
  return fn;
}

/** 用自定义模板渲染；ctx = helpers + opts（escapeHtml / normalizeReport 等）。 */
function renderWithTemplate(tplPath, data, opts = {}) {
  const fn = loadTemplateFile(tplPath);
  const ctx = Object.assign({}, helpers, opts);
  const out = fn(data, ctx);
  return out == null ? '' : String(out);
}

module.exports = {
  REGISTRY,
  EXT_TO_FORMAT,
  helpers,
  listFormats,
  normalizeFormat,
  detectFormat,
  outPathFor,
  render,
  loadTemplateFile,
  renderWithTemplate
};
