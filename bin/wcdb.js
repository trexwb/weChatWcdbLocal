#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { Command } = require('commander');

const { extractKeys, generateMacLldbScript } = require('../src/keyExtract');
const { capturePassphraseViaFrida, DEFAULT_PASSPHRASE_PATH } = require('../src/macKeyFrida');
const { decryptSelective } = require('../src/decrypt');
const { openPlain, extractChat, loadContacts } = require('../src/extract');
const { writeReport } = require('../src/report');
const { resolveDataDir } = require('../src/platform');

const program = new Command();

program
  .name('wcdb')
  .description('微信桌面版 4.x (WCDB) 本地数据库离线解密与消息提取 —— Node.js 跨平台版（Win / macOS）')
  .version('0.1.0');

// ───────────────────────── 1. key ─────────────────────────
program
  .command('key')
  .description('提取 SQLCipher 密钥候选（Win 内存扫描 / Mac lldb 模板 / dump / 手动）')
  .option('--dump <file>', '从一个内存 dump 文件提取候选密钥（跨平台，可测）')
  .option('--key <hex>', '直接提供 hex passphrase，跳过提取')
  .option('--pid <pid>', '指定微信进程 PID', (v) => parseInt(v, 10))
  .option('--allow-memory-scan', '启用实验性实时内存扫描（默认关闭）')
  .option('--lldb-script', '生成 macOS lldb 辅助脚本并退出')
  .option('--mac-frida', 'macOS：用 frida 在微信启动时抓取 passphrase（需重签名微信 + root）')
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
  .description('由 messages.json 生成 HTML 报告')
  .requiredOption('--in <file>', 'messages.json 路径')
  .option('-o, --out <file>', '输出 HTML 文件', 'report.html')
  .action((opts) => {
    const data = JSON.parse(fs.readFileSync(opts.in, 'utf8'));
    const out = writeReport(opts.out, data);
    // eslint-disable-next-line no-console
    console.log(`报告已生成 -> ${out}`);
    // eslint-disable-next-line no-console
    console.log('建议用浏览器或 headless 截图做一次渲染级目视核验（表格对齐 / 文字清晰 / 无错位）。');
  });

program.parse(process.argv);

if (!process.argv.slice(2).length) {
  program.outputHelp();
}
