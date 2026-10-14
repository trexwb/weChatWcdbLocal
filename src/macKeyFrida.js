'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execSync, execFileSync } = require('child_process');

/**
 * passphrase 默认落盘路径，跨平台（Windows 用 os.tmpdir()，避免写死 /tmp）。
 */
const DEFAULT_PASSPHRASE_PATH = path.join(os.tmpdir(), 'wxdb', 'passphrase.hex');

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

/**
 * 候选微信 app 根目录：重签名副本优先，其次系统安装位置。
 */
function weChatAppCandidates() {
  return [path.join(os.homedir(), 'Applications', 'WeChat.app'), path.join('/Applications', 'WeChat.app')];
}

/**
 * 列出微信「主进程」（只匹配主二进制，排除 WeChatAppEx / WeChatHelper / crashpad_handler 等子进程）。
 * pgrep -f 的特征串会同时命中这些子进程，早期实现取 head -1 属于侥幸，这里按完整路径精确匹配。
 * @returns {Array<{pid:number, appPath:string, resigned:boolean}>} 重签名副本的进程排在前面
 */
function listWeChatMainProcesses() {
  let out;
  try {
    out = execSync('ps -axo pid=,args=', { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
  } catch (e) {
    return [];
  }
  const found = [];
  for (const line of out.split('\n')) {
    const m = line.match(/^\s*(\d+)\s+(.*)$/);
    if (!m) continue;
    const args = m[2];
    for (const appPath of weChatAppCandidates()) {
      const main = path.join(appPath, 'Contents', 'MacOS', 'WeChat');
      if (args === main || args.startsWith(main + ' ')) {
        found.push({ pid: parseInt(m[1], 10), appPath, resigned: appPath !== '/Applications/WeChat.app' });
        break;
      }
    }
  }
  // 重签名副本（带 get-task-allow，才可能被 attach）优先
  return found.sort((a, b) => Number(b.resigned) - Number(a.resigned));
}

/**
 * 目标进程属主用户名。同用户 attach 不需要 sudo、只有跨用户才需要提权，
 * 所以诊断前必须先拿到「属主是谁」这个事实。
 * @param {number} pid
 * @returns {string|null} 取不到时返回 null（不臆断）
 */
function processOwner(pid) {
  try {
    const out = execFileSync('ps', ['-o', 'user=', '-p', String(pid)], { encoding: 'utf8' });
    return out.trim() || null;
  } catch (e) {
    return null;
  }
}

/**
 * 目标进程属主是否与当前用户一致。
 * @param {number} pid
 * @returns {boolean|null} null 表示无法判定（此时不得声称「跨用户」）
 */
function isTargetSameUser(pid) {
  const owner = processOwner(pid);
  if (!owner) return null;
  let me = null;
  try {
    me = os.userInfo().username;
  } catch (e) {
    // ignore
  }
  return me ? owner === me : null;
}

/**
 * attach 失败的可操作诊断（与 platform.js 的权限提示同一取向：不要让 agent 拿到裸异常）。
 *
 * 主路径是「非 root」：属主与当前用户一致 + 目标带 get-task-allow 时，同用户 attach 不需要 sudo。
 * 因此这里按「属主是否与当前用户一致 + 目标是否带 get-task-allow」两条事实给指引：
 * 只有属主是另一个用户时才提示提权；缺 get-task-allow 时给的是「不需要 sudo 的重签名」指引。
 */
function diagnoseAttachFailure(target) {
  const hints = [];
  const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
  const sameUser = target ? isTargetSameUser(target.pid) : true;
  if (sameUser === false) {
    hints.push(
      '  1) 目标进程（pid=' +
        target.pid +
        '）属主是 ' +
        processOwner(target.pid) +
        '，与当前用户不一致：frida 跨用户 attach 必须提权 ——\n' +
        '     sudo node bin/wcdb.js key --mac-frida\n' +
        '     或直接切到该用户账号下运行本命令（同用户即不需要 sudo）。'
    );
  } else if (!isRoot) {
    hints.push(
      '  1) 当前是普通用户（非 root），这正是预期的主路径：属主一致 + 目标带 get-task-allow 时无需 sudo。\n' +
        '     若仍被拒，请按下面各条逐项排查，不要直接改用 sudo。'
    );
  }
  let sip = '';
  try {
    sip = execFileSync('csrutil', ['status'], { encoding: 'utf8' });
  } catch (e) {
    /* 忽略 */
  }
  const appPath = target ? target.appPath : weChatAppCandidates()[0];
  let entitlements = '';
  try {
    // 用 argv 数组而非 shell 字符串：路径含空格/括号（甚至 $()）时不会被 shell 解释
    entitlements = execFileSync('codesign', ['-d', '--entitlements', ':-', appPath], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe']
    });
  } catch (e) {
    // codesign 把 entitlements 写到 stderr，签名有效但无 entitlements 时也返回非 0
    entitlements = (e && e.stdout ? e.stdout : '') + (e && e.stderr ? e.stderr : '');
  }
  const hasGetTaskAllow = /com\.apple\.security\.get-task-allow/.test(entitlements);
  if (!hasGetTaskAllow) {
    hints.push(
      '  2) 目标 ' +
        appPath +
        ' 没有 com.apple.security.get-task-allow 授权（App Store 原版必然如此），' +
        'SIP 下无论是否 root 都 attach 不进去。\n' +
        '     需要一份重签名副本（不需要 sudo，只动 ~/Applications 下的副本）：\n' +
        '       bash scripts/resign-wechat.sh        # 一键复制 + 重签名 + 校验\n' +
        '     或手工等价步骤：\n' +
        '       cp -R /Applications/WeChat.app ~/Applications/\n' +
        '       codesign -d --entitlements :- /Applications/WeChat.app > ~/wx_ent_orig.plist\n' +
        '       # 编辑该 plist：新增 get-task-allow=true、删除 application-identifier 与 team-identifier，\n' +
        '       # 务必保留 com.apple.security.app-sandbox（删掉会让微信切到另一个数据目录，读不到记录）\n' +
        '       codesign --force --deep --sign - --entitlements ~/wx_ent.plist ~/Applications/WeChat.app\n' +
        '     然后完全退出原版微信（否则命中的仍是未重签名的进程），再从 ~/Applications/WeChat.app 启动。'
    );
  }
  if (!target) {
    hints.push(
      '  3) 没有在跑中的微信主进程。attach 必须落在「启动瞬间」：先运行本命令，再立刻从 ~/Applications/WeChat.app 启动微信。'
    );
  } else if (!target.resigned) {
    hints.push('  3) 命中的是 /Applications 下的原版微信进程（pid=' + target.pid + '），它没有 get-task-allow、无法被 attach；请完全退出原版，用 scripts/resign-wechat.sh 生成副本后从 ~/Applications/WeChat.app 启动。');
  }
  if (/enabled/i.test(sip) && hasGetTaskAllow) {
    hints.push(
      '  4) SIP 已开启且目标已带 get-task-allow：若仍失败，多为 AMFI 对 ad-hoc 签名的限制，请核对重签名是否成功（codesign -dv --entitlements :- ~/Applications/WeChat.app）。'
    );
  }
  if (sameUser !== false && hasGetTaskAllow) {
    hints.push(
      '  5) 首次以非 root 身份 attach 时，macOS 可能要求授权：打开「系统设置 → 隐私与安全性 → 开发者工具」，' +
        '把当前终端（或 Node）加入并打开开关后重跑本命令即可，这一步不需要 sudo。'
    );
  }
  return hints.join('\n');
}

function findWeChatPid() {
  const c = listWeChatMainProcesses();
  return c.length ? c[0].pid : null;
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
 * @param {string} [opts.out] 写出 passphrase 的文件（默认跨平台临时目录下的 wxdb/passphrase.hex）
 * @returns {Promise<string>} passphrase hex（64 字符）
 */
async function capturePassphraseViaFrida(opts = {}) {
  let frida;
  try {
    // eslint-disable-next-line global-require
    frida = require('frida');
  } catch (e) {
    throw new Error('缺少 frida：请先 `npm install frida`；Mac 侧还需要一份重签名副本（bash scripts/resign-wechat.sh，不需要 sudo）');
  }

  const timeoutMs = opts.timeoutMs || 90000;
  const deadline = Date.now() + timeoutMs;

  // eslint-disable-next-line no-console
  console.error('等待微信进程出现（请在 90 秒内从 ~/Applications/WeChat.app 启动微信）...');
  let pid = null;
  let target = null;
  while (Date.now() < deadline) {
    target = listWeChatMainProcesses()[0] || null;
    if (target) {
      pid = target.pid;
      break;
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  if (!pid) throw new Error('超时未检测到微信进程。请确认运行的是 ~/Applications/WeChat.app（重签名副本，普通用户运行即可，不需要 sudo）。');

  let session;
  try {
    session = await frida.attach(pid);
  } catch (e) {
    // frida 的原生错误（如 Unable to access process with pid N from the current user account）
    // 对 agent 没有可执行信息，这里补齐「为什么进不去、下一步做什么」
    throw new Error(
      'attach 微信进程失败（pid=' + pid + '）：' + e.message + '\n' + diagnoseAttachFailure(target)
    );
  }
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
  const out = opts.out || DEFAULT_PASSPHRASE_PATH;
  fs.mkdirSync(require('path').dirname(out), { recursive: true });
  fs.writeFileSync(out, captured, 'utf8');
  return captured;
}

module.exports = {
  capturePassphraseViaFrida,
  findWeChatPid,
  listWeChatMainProcesses,
  weChatAppCandidates,
  diagnoseAttachFailure,
  HOOK_SOURCE,
  DEFAULT_PASSPHRASE_PATH
};
