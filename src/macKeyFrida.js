'use strict';

const fs = require('fs');
const { execSync } = require('child_process');

/**
 * macOS 微信密钥抓取（frida 方案，来源：wechat-chatlog-export-mac）。
 *
 * 原理：在微信「启动的瞬间」拦截系统函数 CCKeyDerivationPBKDF。
 * 微信用 rounds=256000、passwordLen=32 的那次调用，其第一个参数就是
 * 32 字节 passphrase。拿到 passphrase 后，各库 enc_key 由
 *   enc_key = PBKDF2-HMAC-SHA512(passphrase, <该库首页 salt>, 256000, 32)
 * 派生（见 decrypt.js）。
 *
 * 前置条件（必须用户本人操作，触碰系统安全边界）：
 *   1) 已把 /Applications/WeChat.app 复制并重签名到 ~/Applications/WeChat.app，
 *      且重签名保留了 com.apple.security.app-sandbox（否则微信切数据目录）。
 *   2) 本机已装 frida（npm install frida）。
 *   3) 运行本命令需 root（frida 读微信内存），且要在「本命令运行后立刻启动微信」。
 *
 * 注意：抓到后务必 session.detach()，否则微信会变成杀不掉的僵尸进程。
 */

function findWeChatPid() {
  try {
    const out = execSync('pgrep -f "WeChat.app/Contents/MacOS/WeChat" | head -1', {
      encoding: 'utf8'
    });
    const pid = parseInt(out.trim(), 10);
    return Number.isFinite(pid) ? pid : null;
  } catch (e) {
    return null;
  }
}

// 注入到微信进程内的 frida 脚本
const HOOK_SOURCE = `
(function () {
  const CC = Module.findGlobalExportByName('CCKeyDerivationPBKDF');
  if (!CC) { send({ type: 'error', msg: 'CCKeyDerivationPBKDF export not found' }); return; }
  Interceptor.attach(CC, {
    onEnter(args) {
      const passwordPtr = args[0];
      const passwordLen = args[1].toInt32();
      const rounds = args[4].toInt32();
      // 微信用 rounds=256000、32 字节密码的那次调用即目标 passphrase
      if (rounds === 256000 && passwordLen === 32) {
        const buf = passwordPtr.readByteArray(passwordLen);
        const arr = new Uint8Array(buf);
        let hex = '';
        for (let i = 0; i < arr.length; i++) hex += arr[i].toString(16).padStart(2, '0');
        send({ type: 'passphrase', hex });
      }
    }
  });
  send({ type: 'ready' });
})();
`;

/**
 * 通过 frida 抓取微信 passphrase。
 * 会轮询等待微信进程出现并 attach，直到抓到 passphrase 或超时。
 * @param {object} [opts]
 * @param {number} [opts.timeoutMs] 等待超时（默认 90s）
 * @param {string} [opts.out] 写出 passphrase 的文件（默认 /tmp/wxdb/passphrase.hex）
 * @returns {Promise<string>} passphrase hex（64 字符）
 */
async function capturePassphraseViaFrida(opts = {}) {
  let frida;
  try {
    // eslint-disable-next-line global-require
    frida = require('frida');
  } catch (e) {
    throw new Error('缺少 frida：请先 `npm install frida`，并确保已按 Mac 方案重签名微信并授权');
  }

  const timeoutMs = opts.timeoutMs || 90000;
  const deadline = Date.now() + timeoutMs;

  // eslint-disable-next-line no-console
  console.error('等待微信进程出现（请在 90 秒内从 ~/Applications/WeChat.app 启动微信）...');
  let pid = null;
  while (Date.now() < deadline) {
    pid = findWeChatPid();
    if (pid) break;
    await new Promise((r) => setTimeout(r, 1000));
  }
  if (!pid) throw new Error('超时未检测到微信进程。请确认运行的是 ~/Applications/WeChat.app（重签名版）。');

  const session = await frida.attach(pid);
  const script = await session.createScript(HOOK_SOURCE);
  let captured = null;
  let doneResolve;
  const done = new Promise((res) => (doneResolve = res));

  script.message.connect((msg) => {
    if (msg.type === 'send' && msg.payload) {
      if (msg.payload.type === 'passphrase') {
        captured = msg.payload.hex;
        doneResolve();
      } else if (msg.payload.type === 'error') {
        doneResolve(new Error(msg.payload.msg));
      }
    } else if (msg.type === 'error') {
      doneResolve(new Error(msg.description || 'frida script error'));
    }
  });

  await script.load();
  try {
    const r = await Promise.race([
      done,
      new Promise((_, rej) => setTimeout(() => rej(new Error('抓取超时，未在启动阶段命中 CCKeyDerivationPBKDF')), timeoutMs))
    ]);
    if (r instanceof Error) throw r;
  } finally {
    // 必须 detach，避免微信变僵尸进程
    try {
      await session.detach();
    } catch (e) {
      // ignore
    }
  }

  if (!captured) throw new Error('未抓到 passphrase');
  if (!/^[0-9a-f]{64}$/.test(captured)) {
    throw new Error('抓到的 passphrase 格式异常（应为 64 hex）：' + captured);
  }
  const out = opts.out || '/tmp/wxdb/passphrase.hex';
  fs.mkdirSync(require('path').dirname(out), { recursive: true });
  fs.writeFileSync(out, captured, 'utf8');
  return captured;
}

module.exports = { capturePassphraseViaFrida, findWeChatPid, HOOK_SOURCE };
