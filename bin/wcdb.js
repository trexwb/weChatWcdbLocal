#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const { extractKeys, generateMacLldbScript } = require('../src/keyExtract');
const { capturePassphraseViaFrida, DEFAULT_PASSPHRASE_PATH } = require('../src/macKeyFrida');
const { decryptSelective } = require('../src/decrypt');
const { openPlain, extractChat, loadContacts } = require('../src/extract');
const { writeReports } = require('../src/report');
const templates = require('../src/templates');
const { resolveDataDir } = require('../src/platform');
const { runPipeline } = require('../src/pipeline');

/**
 * commander v15+ 是纯 ESM（package.json: "type": "module"），
 * 在 CommonJS 里 require('commander') 会抛 ERR_REQUIRE_ESM（Node 18 / 20 早期必崩）。
 * 这里统一动态 import，并兼容 ESM 具名导出与 CJS 互操作默认导出两种形态。
 */
async function loadCommander() {
  const mod = await import('commander');
  const Command = mod.Command || (mod.default && mod.default.Command);
  if (!Command) throw new Error('无法从 commander 载入 Command，请执行 npm install commander');
  return Command;
}

async function buildProgram(Command) {
  const program = new Command();

  program
    .name('wcdb')
    .description('微信桌面版 4.x (WCDB) 本地数据库离线解密与消息提取 —— Node.js 跨平台版（Win / macOS）')
    .version('1.0.0');

  // ───────────────────────── 1. key ─────────────────────────
  program
    .command('key')
    .description('提取 SQLCipher 密钥候选（Win 内存扫描 / Mac lldb 模板 / dump / 手动）')
    .option('--dump <file>', '从一个内存 dump 文件提取候选密钥（跨平台，可测）')
    .option('--key <hex>', '直接提供 hex passphrase，跳过提取')
    .option('--pid <pid>', '指定微信进程 PID', (v) => parseInt(v, 10))
    .option('--allow-memory-scan', '启用实验性实时内存扫描（默认关闭）')
    .option('--lldb-script', '生成 macOS lldb 辅助脚本并退出')
    .option(
      '--mac-frida',
      'macOS：用 frida 在微信启动时抓取 passphrase（需重签名副本，见 scripts/resign-wechat.sh；同用户非 root 即可，无需 sudo）'
    )
    .option('-o, --out <file>', '候选密钥输出文件', 'keys.json')
    .action(async (opts) => {
      if (opts.lldbScript) {
        const pid = opts.pid || '<PID>';
        // eslint-disable-next-line no-console
        console.log(generateMacLldbScript(pid));
        return;
      }
      if (opts.macFrida) {
        const ph = await capturePassphraseViaFrida({ out: opts.out.replace(/\.json$/, '.hex') });
        // 同时以 passphrase 候选形式写回 keys.json，便于 decrypt 直接复用
        fs.writeFileSync(opts.out, JSON.stringify([ph], null, 2), 'utf8');
        // eslint-disable-next-line no-console
        console.log(`已抓取 passphrase 并写入 ${opts.out}（同时存于 ${DEFAULT_PASSPHRASE_PATH}）`);
        return;
      }
      const cands = extractKeys({
        dump: opts.dump,
        key: opts.key,
        pid: opts.pid,
        allowMemoryScan: opts.allowMemoryScan
      });
      fs.writeFileSync(opts.out, JSON.stringify(cands, null, 2), 'utf8');
      // eslint-disable-next-line no-console
      console.log(`提取到 ${cands.length} 个候选密钥，已写入 ${opts.out}`);
      if (cands.length) {
        // eslint-disable-next-line no-console
        console.log('首个候选（供快速试解密）：', cands[0]);
      }
    });

  // ──────────────────────── 2. decrypt ────────────────────────
  program
    .command('decrypt')
    .description('选择性解密加密库（默认 message_*.db / contact.db / session.db）')
    .option('--dir <dir>', '加密库目录（db_storage）；默认按平台自动定位')
    .option('--keys <file>', '候选密钥 JSON 文件（来自 key 命令）', 'keys.json')
    .option('--key <hex>', '直接指定单个 hex 密钥')
    .option('--out <dir>', '明文输出目录', 'plain')
    .option('--files <list>', '仅解密指定文件，逗号分隔', (v) => v.split(',').map((s) => s.trim()))
    .action((opts) => {
      const dir = opts.dir || resolveDataDir();
      if (!dir) throw new Error('无法确定 db_storage 目录，请用 --dir 指定');
      let candidates = [];
      if (opts.key) candidates = [opts.key.replace(/^0x/, '')];
      else if (fs.existsSync(opts.keys)) candidates = JSON.parse(fs.readFileSync(opts.keys, 'utf8'));
      if (!candidates.length) throw new Error('没有候选密钥，请先运行 key 命令或传入 --key');
      decryptSelective(dir, candidates, opts.out, opts.files);
    });

  // ──────────────────────── 3. extract ────────────────────────
  program
    .command('extract')
    .description('从明文库提取会话消息（zstd 解压 / local_type 掩码 / 发送者反推）')
    .requiredOption('--db <file>', '明文消息库路径（如 plain/message_0.plain.db）')
    .requiredOption('--username <wxid>', '对方 wxid 或群 id')
    .option('--self-wxid <wxid>', '本账号 wxid，用于判定“自己发的消息”')
    .option('--contact <file>', '明文 contact 库路径（用于昵称映射）')
    .option('-o, --out <file>', '输出 messages.json', 'messages.json')
    .action(async (opts) => {
      const db = openPlain(opts.db);
      const chat = await extractChat(db, opts.username, { selfWxid: opts.selfWxid });
      db.close();
      const contacts = opts.contact ? loadContacts(opts.contact) : {};
      const payload = {
        selfWxid: opts.selfWxid || 'self',
        contacts,
        chats: [chat]
      };
      fs.writeFileSync(opts.out, JSON.stringify(payload, null, 2), 'utf8');
      // eslint-disable-next-line no-console
      console.log(`已提取 ${chat.count} 条消息 -> ${opts.out}`);
    });

  // ──────────────────────── 4. report ────────────────────────
  program
    .command('report')
    .description('由 messages.json 生成报告（html / md / json，可一次同时输出多种）')
    .requiredOption('--in <file>', 'messages.json 路径')
    .option('-o, --out <file>', '报告基准路径；多格式时按格式改写扩展名', 'report.html')
    .option(
      '-f, --format <list>',
      '报告格式，逗号分隔：' + templates.listFormats().map((x) => x.id).join(',') + '（默认由 --out 扩展名推断，兜底 html）'
    )
    .option('--template <file>', '自定义模板 JS 模块，导出 (data, ctx) => string')
    .option('--compact', 'json 格式压成单行（默认 2 空格缩进）')
    .action((opts) => {
      const data = JSON.parse(fs.readFileSync(opts.in, 'utf8'));
      const formats = opts.format
        ? String(opts.format)
            .split(',')
            .map((s) => s.trim())
            .filter(Boolean)
        : [templates.detectFormat(opts.out) || 'html'];
      const reports = writeReports(opts.out, data, formats, {
        template: opts.template,
        compact: !!opts.compact
      });
      // eslint-disable-next-line no-console
      console.log(`报告已生成（${reports.length} 个文件）：`);
      for (const r of reports) {
        // eslint-disable-next-line no-console
        console.log(`  ${r.format.toUpperCase()} -> ${r.path}`);
      }
      if (!opts.format) {
        // eslint-disable-next-line no-console
        console.log('  提示：加 -f html,md,json 可在生成 HTML 的同时输出 Markdown / JSON，供其它应用直接使用。');
      }
      if (reports.some((r) => r.format === 'html')) {
        // eslint-disable-next-line no-console
        console.log('建议用浏览器或 headless 截图做一次渲染级目视核验（表格对齐 / 文字清晰 / 无错位）。');
      }
    });

  // ──────────────────────── 5. pipeline ────────────────────────
  program
    .command('pipeline')
    .description('一键流水线：授权后自动完成 取密钥 → 解密 → 提取 → 报告（供 agent 弹窗授权后调用）')
    .option('--dir <dir>', 'db_storage 目录（默认按平台自动定位）')
    .option('--wxid <wxid>', '本账号 wxid（辅助定位数据目录）')
    .option('--key <hex>', '直接提供 passphrase hex')
    .option('--keys <file>', '候选密钥 JSON 文件（显式传入才生效，避免误用旧文件）')
    .option('--dump <file>', '内存 dump 文件（跨平台）')
    .option('--mac-frida', 'macOS：frida 抓取 passphrase（需重签名副本，见 scripts/resign-wechat.sh；同用户非 root 即可，无需 sudo）')
    .option('--allow-memory-scan', 'Windows：启用实时内存扫描（实验性）')
    .option('--pid <pid>', '指定微信进程 PID', (v) => parseInt(v, 10))
    .requiredOption('--username <wxid>', '要提取的会话 wxid 或群 id')
    .option('--self-wxid <wxid>', '本账号 wxid，用于判定“自己发的消息”')
    .option('--files <list>', '仅解密指定文件，逗号分隔', (v) => v.split(',').map((s) => s.trim()))
    .option('--out-dir <dir>', '明文输出目录', 'plain')
    .option('-o, --out <file>', 'messages.json 路径', 'messages.json')
    .option('--html <file>', '报告基准路径；多格式时按格式改写扩展名', 'report.html')
    .option(
      '-f, --format <list>',
      '报告格式，逗号分隔：' + templates.listFormats().map((x) => x.id).join(',') + '（默认 html）'
    )
    .option('--template <file>', '自定义模板 JS 模块，导出 (data, ctx) => string')
    .option('--compact', 'json 格式压成单行（默认 2 空格缩进）')
    .action(async (opts) => {
      let candidates;
      if (opts.keys) {
        if (!fs.existsSync(opts.keys)) throw new Error('--keys 文件不存在：' + opts.keys);
        candidates = JSON.parse(fs.readFileSync(opts.keys, 'utf8'));
      }
      const r = await runPipeline({
        dir: opts.dir,
        wxid: opts.wxid,
        key: opts.key,
        candidates,
        dump: opts.dump,
        macFrida: opts.macFrida,
        allowMemoryScan: opts.allowMemoryScan,
        pid: opts.pid,
        username: opts.username,
        selfWxid: opts.selfWxid,
        files: opts.files,
        outDir: opts.outDir,
        outJson: opts.out,
        outHtml: opts.html,
        formats: opts.format
          ? String(opts.format)
              .split(',')
              .map((s) => s.trim())
              .filter(Boolean)
          : null,
        template: opts.template,
        compact: !!opts.compact
      });
      // eslint-disable-next-line no-console
      console.log(
        `一键完成：密钥来源=${r.keySource} ｜ 解密 ${r.decryptedFiles} 个库 ｜ 提取 ${r.count} 条消息`
      );
      // eslint-disable-next-line no-console
      console.log(`  消息数据 JSON -> ${r.jsonOut}`);
      for (const rep of r.reports || []) {
        // eslint-disable-next-line no-console
        console.log(`  报告 ${rep.format.toUpperCase()} -> ${rep.path}`);
      }
      if ((r.reports || []).length === 1 && r.reports[0].format === 'html') {
        // eslint-disable-next-line no-console
        console.log('  提示：加 -f html,md,json 可在生成 HTML 的同时输出 Markdown / JSON，供其它应用直接使用。');
      }
    });

  return program;
}

async function main() {
  const Command = await loadCommander();
  const program = await buildProgram(Command);

  if (!process.argv.slice(2).length) {
    program.outputHelp();
    return;
  }
  await program.parseAsync(process.argv);
}

// 统一兜住同步/异步异常，输出可操作提示而非裸栈
main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error('错误：' + (err && err.message ? err.message : String(err)));
  process.exit(1);
});
