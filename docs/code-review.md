# 代码审查报告 — wechat-wcdb-node

- 审查日期：2026-10-14
- 审查范围：`bin/wcdb.js`、`src/*.js`（11 个）、`test/selftest.js`，约 1900 行；并交叉核对 `README.md` / `SKILL.md` 的命令契约
- 审查方式：逐文件静态审查 + 关键结论本地实测（实测数据见文末「附录 A：验证证据」）
- 运行环境：Node.js v24.21.0 / darwin arm64
- 基线：`node test/selftest.js` → **26 通过 / 0 失败**（自测本身质量良好，本报告不影响该结论）

> 说明：本项目是 Node.js CLI，不是 Java/Vue，因此按等价的审查维度执行——空值/异常路径、并发与资源释放、SQL 与数据层、安全（密钥与隐私数据处置）、性能与内存、编码规范。

---

## 概览

| 严重度 | 数量 | 分布 |
|--------|------|------|
| Critical | 3 | `src/keyExtract.js`、`src/macKeyFrida.js` + `bin/wcdb.js`、`bin/wcdb.js` |
| Major | 6 | `src/decrypt.js`(2)、`src/wcdbDecode.js`、`src/extract.js`、`bin/wcdb.js`、`src/macKeyFrida.js` |
| Minor | 10 | `bin/wcdb.js`(2)、`src/extract.js`(4)、`src/zstd.js`、`src/platform.js`、`src/macKeyFrida.js`、`src/decrypt.js` |
| Info | 6 | 含 4 处对既有良好实践的确认 |
| **合计** | **25** | |

一句话结论：**算法层（WCDB 页面解密、报告转义、平台门禁决策）质量高且自测充分；问题集中在「工程外壳」——性能量级失控、密钥这类敏感数据的处置方式、CLI 的异步/资源释放契约。** 三个 Critical 中至少两个会让文档主推的调用路径在真实数据上直接不可用。

---

## 问题详情

### Critical

#### [Critical] C-1 `collectCandidates` 复杂度失控，`--dump` / `--allow-memory-scan` 实际不可用

- **位置**: `src/keyExtract.js:56-75`（步长 1 的滑窗 + 每偏移 4 次 PBKDF2）；调用方 `src/keyExtract.js:179`（对最大 64MB 的内存区域整块调用）、`src/keyExtract.js:82-86`
- **问题**: 窗口以 **1 字节** 为步长滑动，每个偏移都无条件执行 4 次 PBKDF2（`PBKDF2_VARIANTS`，`src/keyExtract.js:13-18`）。而 `looksLikeSalt`（`src/keyExtract.js:35-44`）对随机数据几乎恒为真（仅过滤全 0/全 FF），起不到降量作用。
- **实测**: 单偏移 4 变体合计 **81.75 ms**（sha1/64000=15.49ms、sha512/256000=52.67ms、sha512/64000=12.77ms、sha1/4000=0.82ms）。据此：

  | 输入 | 预计耗时 | 候选数（Set） |
  |------|----------|----------------|
  | 2 KB | ≈ 170 s | 1 万 |
  | 1 MB | ≈ **24 小时** | ≈ **520 万** |
  | 64 MB（单次内存区域上限，`src/keyExtract.js:173`） | ≈ **63 天** | ≈ 3.3 亿 |

  我实测 2 KB 输入时命令直接超过 2 分钟被强制转入后台 —— 这不是外推，是真实表现。
- **风险**: ① 文档主推的两条取密钥路径（`--dump`、`--allow-memory-scan`）在真实规模上永远跑不完；② 即便跑完，5.2M × 64 hex 字符串的 Set 会占数百 MB 常驻内存；③ agent 调用（`SKILL.md` 的推荐用法）表现为「无输出挂死」，无法与「密钥错误」区分。
- **更深一层（需 owner 确认口径）**: 这里在候选生成阶段做的派生与解密阶段的派生**口径不一致**——`src/keyExtract.js:67` 用「内存里 key 后面紧跟的 16 字节」当 salt，而真实 enc_key 是 `PBKDF2(passphrase, 该库首页 salt, 256000, 32)`（见 `src/decrypt.js:13` 注释与 `src/decrypt.js:136`）。除非内存块尾部的 salt 恰好等于某个库的首页 salt，否则这 4 个派生候选永远命中不了，属于纯开销。
- **修复**:
  ```js
  // 修复前：候选生成阶段就做 4 次重 KDF（81.75 ms / 偏移）
  for (let i = 0; i + WINDOW <= decoded.length; i += 1) {
    ...
    for (const v of PBKDF2_VARIANTS) {
      const derived = crypto.pbkdf2Sync(key32, salt16, v.iter, 32, v.hash); // O(n)×82ms
      cands.add(derived.toString('hex'));
    }
  }

  // 修复后：候选生成只做 O(1) 采集，重 KDF 延后到「按某库真实 salt 验证首页 HMAC」阶段
  const MAX_CANDIDATES = 20000;
  function collectKeySaltPairs(decoded) {
    const pairs = [];
    for (let i = 0; i + WINDOW <= decoded.length; i++) {
      const salt16 = decoded.subarray(i + 32, i + 48);
      if (!looksLikeSalt(salt16)) continue;
      pairs.push({ key: decoded.subarray(i, i + 32), salt: salt16 }); // 不派生
      if (pairs.length >= MAX_CANDIDATES) break;                      // 硬上限
    }
    return pairs;
  }
  ```
  配套三件事：① 先用 **1 次** 真实库首页 salt 派生 + 单页 HMAC 验证（约 53ms + 亚毫秒），命中才继续；② 步长与预筛：对窗口做熵/重复模式粗筛，或按已知 `Config.Cipher` 结构锚定（掩码特征字节）后再展开，避免逐字节；③ 给 `--dump` 加进度输出与 `--max-candidates` 上限，让 agent 能区分「还在跑」和「跑不完」。

#### [Critical] C-2 passphrase / 密钥候选以世界可读权限落盘，且默认写入共享临时目录

- **位置**: `src/macKeyFrida.js:11`（`path.join(os.tmpdir(), 'wxdb', 'passphrase.hex')`）、`src/macKeyFrida.js:137-138`；`bin/wcdb.js:44`、`bin/wcdb.js:55`（`keys.json`）
- **问题**: `fs.writeFileSync(out, captured, 'utf8')` 未指定 `mode` → 默认 0644；`fs.mkdirSync(..., { recursive: true })` 默认 0777&~umask（在 `/tmp` 下得到 0755，目录本身可读）。
- **暴露范围（已实测修正，勿照搬「/tmp 世界可读」的想当然）**: 本机实测普通终端下 `os.tmpdir()` 返回**私有 per-user 目录** `$TMPDIR`（`/var/folders/…/T`，属主自身、通常不可被他人读），此时风险主要是「0644 + 路径可预测」。但**文档主推的调用方式是 `sudo`**（`README.md:107`、`SKILL.md:88`、`README.md:194` 的 pipeline 同样带 sudo），macOS 默认 `env_reset` 会清掉 `TMPDIR` → `os.tmpdir()` 回落到 `/tmp`，路径即 `README.md:108` 自己写明的 `/tmp/wxdb/passphrase.hex`：`/tmp` 世界可读写、新目录 0755、文件 0644 → **同机任意本地用户可读**。
  ⚠️ 该 sudo 分支我未能执行验证（需要密码），是基于 macOS sudoers 默认策略与 README 自述路径的推断；`keys.json` 的 0644 与「写入当前工作目录」两点为直接代码事实，不受此影响。
- **风险**: 这 32 字节是**主密钥**——`enc_key = PBKDF2(passphrase, 各库 salt, 256000)` 可由它离线推出（`src/decrypt.js:63-66`），拿到它 = 拿到全部微信库的解密能力。此外 `keys.json` 落在工作目录，易被终端日志、Time Machine、云同步目录（iCloud/Dropbox）、误提交带走。
- **修复**:
  ```js
  // 修复前
  fs.mkdirSync(require('path').dirname(out), { recursive: true });
  fs.writeFileSync(out, captured, 'utf8');

  // 修复后：私有目录 + 0600 + 已存在文件补 chmod；默认路径移出共享 tmp
  const DEFAULT_PASSPHRASE_PATH = path.join(os.homedir(), '.wcdb-local', 'passphrase.hex');
  const dir = path.dirname(out);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(out, captured, { encoding: 'utf8', mode: 0o600 });
  try { fs.chmodSync(out, 0o600); } catch (e) { /* Windows 下忽略 */ }
  ```
  `bin/wcdb.js:44` 与 `:55` 写 `keys.json` 处同样加 `{ mode: 0o600 }`。
  附：`.gitignore` 已忽略 `keys.json` / `plain/` / `messages.json` / `report.html`，这一点做得对，予以肯定；缺的是文件权限维度。

- **另需注意**: `src/macKeyFrida.js:134` 在 passphrase 格式异常时把原文拼进错误信息（`'...：' + captured`），异常会经 `bin/wcdb.js:178` 打到 stderr → 密钥进日志。建议只输出长度与前 8 位。

#### [Critical] C-3 `decrypt` 子命令的浮空 Promise 绕过了统一错误处理（已实测复现）

- **位置**: `bin/wcdb.js:73-81`，具体 `bin/wcdb.js:80`
- **问题**: action 是同步函数，内部调用 `async` 的 `decryptSelective` 却既不 `return` 也不 `await`；`bin/wcdb.js:176-180` 的 `parseAsync(...).catch(...)` 收不到它。
- **实测**: 用同构的 commander 最小复现（同样的「同步 action 内浮空调用 async」写法）验证：
  - `parseAsync` 的 `.catch` **没有**捕获到异步内部的异常，约定的 `错误：<message>` + `exit 1` 输出没有发生；
  - 实际行为是 Node 抛出 unhandled rejection，打印**裸栈**并以退出码 1 结束；
  - 且 `parseAsync` 在真实工作完成前就已 resolve（复现中 `[ok] work finished` 出现在 handler 返回之后）。
- **风险**: `decrypt` 是 `README.md:73/90/109`、`SKILL.md:93/95` 列出的 agent 主调用路径。后果有两类：① 失败时 agent 拿到的是堆栈而不是「怎么办」的提示，无法自我纠错（项目其它地方专门为此把 EPERM 转成了可操作提示，见 `src/platform.js:72-77`，说明这本是设计目标）；② 成功路径上「命令已返回」与「明文文件已写完」不再同步，调用方若紧接着 `extract`/采集结果，存在读到半成品或空目录的竞态。
- **修复**:
  ```js
  // 修复前 (bin/wcdb.js:73,80)
  .action((opts) => {
    ...
    decryptSelective(dir, candidates, opts.out, opts.files);
  });

  // 修复后：async + await（或 return），让 parseAsync 的统一 catch 生效
  .action(async (opts) => {
    ...
    const results = await decryptSelective(dir, candidates, opts.out, opts.files);
    if (!results.length) throw new Error('未解密任何库：请确认 --dir 与密钥来源');
  });
  ```
- **顺带**: 同类浮空风险在 `bin/wcdb.js` 其余 action 均已正确 `await`（`:42`、`:94`、`:146`），只有此一处遗漏。

---

### Major

#### [Major] M-1 解密全量驻留内存，真实大库存在 OOM 风险

- **位置**: `src/decrypt.js:135`（`fs.readFileSync(encPath)` 整库读入）+ `src/wcdbDecode.js:48`（`Buffer.alloc(encBuf.length)` 再分配同尺寸输出）
- **问题**: 峰值约 2–3× 文件大小；`decryptDatabase` 在候选循环里反复调用，每次都重新整读（`src/decrypt.js:131-166`）。真实微信 `message_*.db` 常见 500MB–2GB。
- **实测**: JS 逐页解密吞吐 **≈ 150 MB/s**（16MB 用时 101ms），算法本身完全没问题；但 16MB 合成输入对应的进程 RSS 已达 **120MB**，线性放大到 2GB 库即需数 GB 常驻 → 进程被系统杀掉或分配失败，而报错表现为 `[skip]` 的模糊信息（`src/decrypt.js:211-213`）。
- **修复**: 代码已按 4096 页组织，改造成本很低——改成流式：`fs.openSync` + 每次 `read` 一页 → HMAC 校验 → 解密 → 写入 `fs.createWriteStream(outPath)`；输出不再整体 `alloc`。`encBuf.subarray(0,16)` 的 salt 单独读首页即可获得。

#### [Major] M-2 `exportPlaintext` 用字符串拼接 SQL，路径含单引号即破坏语句（SQL 注入面）

- **位置**: `src/decrypt.js:117`：`` `ATTACH DATABASE '${outPath}' AS plain KEY ''` ``
- **问题**: `outPath` 来自 `--out` 与目录扫描结果，未做 `'` 转义。Windows/macOS 均允许文件名含 `'`（如 `D:\data\o'b\db_storage`），会拼成语法错误，或把库附加到非预期目标；`--out` 由 agent 传入时构成可操纵的 SQL 文本。
- **验证状态**: ⚠️ **未运行时验证**——本地安全策略拦截了我的验证脚本。此条为静态代码判断，结论确定但请自行复核。
- **修复**:
  ```js
  // 修复前
  await dbRun(db, `ATTACH DATABASE '${outPath}' AS plain KEY ''`);

  // 修复后：参数化（KEY '' 是关键字，留在 SQL 文本里）
  await new Promise((res, rej) =>
    db.run('ATTACH DATABASE ? AS plain KEY \'\'', [outPath], (e) => (e ? rej(e) : res())));
  // 或最低成本：outPath.replace(/'/g, "''")
  ```

#### [Major] M-3 sqlcipher 回退分支在默认安装下永远不可用，并污染真实失败原因

- **位置**: `src/decrypt.js:152-162`（候选循环内的第二次尝试）、`src/decrypt.js:21-35`（`lazySqlcipher`）、`package.json:33-35`（`sqlcipher` 在 optionalDependencies）
- **问题**: 已确认当前 `node_modules` **未安装 sqlcipher**（可选依赖，未编译即缺失）。此时每个 passphrase 候选都会白跑一次 `lazySqlcipher()`，抛出的「缺少 sqlcipher 原生模块」覆盖掉 `lastErr`（`src/decrypt.js:160`），最终用户看到 `src/decrypt.js:165` 的错误尾部信息是「装个原生模块」，而真正的原因可能是「passphrase 不对」。
- **风险**: 错误归因导致用户往错误方向排查（白白去做原生编译）；JS 路径的确定性失败原因被吞掉。
- **修复**: 把后端可用性探测移到候选循环外只做一次；分别保留并汇总 `jsFirstError` / `sqlcipherFirstError`；当后端不可用时显式说明「JS 路径失败原因：…；sqlcipher 回退未安装，已跳过」。
- **另外**: `src/decrypt.js:161` 的 `closeDb(r).catch(() => {})` 是无效写法——`closeDb`（`src/decrypt.js:49-54`）内部永不 reject，`catch` 是死代码；且 `src/decrypt.js:157` 成功路径已 `closeDb(r)`，异常路径若错误发生在 close 之后会二次 close。建议用一个 `finally` 收口。

#### [Major] M-4 同一张消息表被扫描并解码两次，整表一次性载入内存

- **位置**: `src/extract.js:77-78`（`buildSenderMap` 全表 `.all()` + 逐行 `await decodeContent`）与 `src/extract.js:110-116`（`extractChat` 再全表 `.all()` + 再逐行解码）
- **问题**: 为反推 `real_sender_id → wxid` 先做一次全表扫描解压，随后正式提取又做一次；两次都把整表行物化到内存。数十万行的会话表 → 内存翻倍、zstd 解压量翻倍。
- **风险**: `--db` 直连真实明文库时 OOM 或长时间无响应；zstd 是 wasm 同步接口却包在 `await` 里（`src/zstd.js:59`），逐行 await 让事件循环反复让出，属无谓开销。
- **修复**: 单次遍历产出消息数组并在同一次遍历里建立 `senderMap`（前缀命中的行既写 map 也留正文），最后按 `create_time` 排序；用 `stmt.iterate()`/`.each()` 代替 `.all()`；同一次调用内缓存已解压结果避免二次解压。

#### [Major] M-5 候选密钥原文打印到 stdout

- **位置**: `bin/wcdb.js:58-61`：`console.log('首个候选（供快速试解密）：', cands[0])`
- **问题**: 密钥明文进入标准输出。对 agent 驱动的工具，stdout 会被会话上下文、终端录像、CI 日志、`tee` 归档持久化——等同密钥外泄面。与 C-2 同源风险。
- **修复**: 只输出指纹：`` console.log(`首个候选指纹：${cands[0].slice(0, 8)}…（完整值见 ${opts.out}，请视为机密文件）`)``

#### [Major] M-6 frida 抓取成功后的 90 秒定时器未清理，且 resolve/reject 混用

- **位置**: `src/macKeyFrida.js:99-130`，定时器 `src/macKeyFrida.js:120`；`done` 只 resolve（`:101`、`:107-112`）
- **问题**:
  1. `new Promise((_, rej) => setTimeout(() => rej(...), timeoutMs))` 的定时器既不 `clearTimeout` 也不 `unref` → 即使 1 秒就抓到 passphrase，进程仍会存活到 90 秒定时器到期。CLI 表现为「结果已打印但命令不返回」，agent 侧容易误判为超时而重复触发（对微信启动时机的 hook 尤其敏感）。
  2. `doneResolve(new Error(...))` 用 resolve 传错误，再靠 `if (r instanceof Error) throw r`（`:122`）区分——若脚本先 send `error`、随后仍 send 到 passphrase，`captured` 被赋值但 Promise 已定，行为取决于消息到达顺序，难排查。
  3. `script.unload()` 未调用（只 `session.detach()`，`:126`）。
- **修复**:
  ```js
  let timer;
  try {
    await Promise.race([done, new Promise((_, rej) => {
      timer = setTimeout(() => rej(new Error('抓取超时…')), timeoutMs);
    })]);
  } finally {
    clearTimeout(timer);
    try { await script.unload(); } catch (e) { /* ignore */ }
    try { await session.detach(); } catch (e) { /* ignore */ }
  }
  ```
  并把 `done` 改成标准 `{ resolve, reject }`，`doneResolve` → `fail(new Error(...))`，去掉 `instanceof Error` 判定。

---

### Minor

| # | 位置 | 问题 | 建议 |
|---|------|------|------|
| m-1 | `bin/wcdb.js:93-95` | `extract` action 里 `db.close()` 不在 `finally`：`extractChat` 抛错（表不存在、列缺失，见 `src/extract.js:101,105`）时句柄泄漏 | 与 `src/pipeline.js:129-135` 对齐，改 `try/finally`（该处写法是正确的） |
| m-2 | `bin/wcdb.js:5` | 引入 `path` 但全文件未使用（已 grep 确认） | 删除 |
| m-3 | `src/extract.js:59`、`:63` | `find('real_sender_id','real_sender_id',…)` 与 `compress_content` 各重复一次，第二个永不生效；说明兼容列表其实没被认真校对 | 去重并补 `realSender` / `Message` 等真实变体 |
| m-4 | `src/extract.js:130` | `(rawType >>> 0) & 0xffffffff` 后半段恒等冗余；若 `better-sqlite3` 启用 `safeIntegers` 返回 BigInt，`>>>` 直接抛 TypeError | `Number(rawType) >>> 0`，并去掉冗余掩码 |
| m-5 | `src/extract.js:139` | `new Date(createTime * 1000)` 假定秒；某版本若为毫秒会得到荒谬年份且不报错 | 按位数判定：`createTime > 1e12 ? createTime : createTime * 1000` |
| m-6 | `src/extract.js:152-169` | `loadContacts` 把「权限不足 / 路径错 / 表结构不符」全部静默成 `{}`（`:166-168`），且 `db.close()` 在 try 内、中途异常会泄漏 | `try/finally` + 首次失败 `console.warn` 一行原因；昵称映射缺失会让报告只有 wxid，用户需要知道为什么 |
| m-7 | `src/zstd.js:13-29` | `_loading` 缓存了 rejected promise：一次瞬时失败后，本进程内所有后续 `decompress` 永久失败 | `.catch(e => { _loading = null; throw e; })` |
| m-8 | `src/decrypt.js:180-183` + `bin/wcdb.js:72` | `--files` 未约束：`--files ../../x.db` 可越出 `--dir` 读取任意 `.db`（`path.join(dbDir, f)`） | `path.basename(f)` + 用 `target` 白名单正则再校验一次 |
| m-9 | `src/platform.js:83` | `fs.statSync(verDir).isDirectory()` 未捕获异常，遇断链或权限拒绝会裸崩；同文件 `:66-79` 已认真处理 `readdirSync` 的 EPERM/EACCES，风格不一致 | 包 `try/catch`，与 `:72-77` 一样转成可操作提示或跳过 |
| m-10 | `src/macKeyFrida.js:46`、`package.json` | `Module.findGlobalExportByName` 在 Frida 17 已移除（现为 `Module.findExportByName(null, name)`）；`frida` 未声明进 package.json（仅 `README.md:64` 手工说明），缺依赖时报错还会被 `:81` 说成「缺少 frida」 | 兼容写法 + 把 frida 加入 optionalDependencies，错误信息区分「未安装」与「API 不兼容」 |

---

### Info / 值得保留的实践

- **I-1** `src/wcdbDecode.js:59` 用 `crypto.timingSafeEqual` 比较 HMAC，并先校验长度——正确且不多余。
- **I-2** `src/report.js` 对 content / sender / time / username / table **全部**走 `escapeHtml`（`src/report.js:5-13`、`:38-47`），HTML 注入面覆盖完整，没有遗漏字段。
- **I-3** `src/pipeline.js:33-57` 的 `resolveKeySource` 是无 I/O 纯函数 + 显式平台互斥门禁，并被 `test/selftest.js:163-201` 完整覆盖；`src/platform.js:72-77` 把系统权限错误转成「去开完全磁盘访问权限」的可操作提示，还有对应断言（`test/selftest.js:205-227`）。这是本项目最值得保持的设计取向：**给 agent 的每条失败路径都要能自我解释**。
- **I-4** 惰性 `require` 原生模块（`src/decrypt.js:24`、`src/keyExtract.js:120`、`src/macKeyFrida.js:79`）保证跨平台加载期安全；`src/decrypt.js:189-192` 用 `.probe.` 临时文件定位 passphrase 后清理，思路正确。
- **I-5** `src/extract.js:46` 的二进制判别（替换字符 + 长度比）对 GBK/混合内容可能误判；工具已提取 `local_type`（`:129-130`）却没有用它来指导解码策略，建议以 `local_type` 为主、启发式为兜底。
- **I-6** `src/decrypt.js:19` 的 `KDF_ITERS = [256000, 64000]`、`src/keyExtract.js:13-18` 的 `PBKDF2_VARIANTS` 是两处独立的版本参数，建议合并进 `src/constants.js` 与 `references/wcdb-crypto.md` 同源，避免版本适配时改漏。

---

## 测试覆盖缺口

`test/selftest.js` 的 26 条断言集中在**算法层**（zstd 往返、md5 表名、XOR、页面加解密互逆、提取语义、平台门禁）。缺口恰是本次 Critical/Major 的落点：

1. **无 CLI 层测试**——C-3（浮空 Promise）只要有一条「跑 `node bin/wcdb.js decrypt` 并对不存在的密钥断言 stdout 以 `错误：` 开头、退出码为 1」的 smoke test 就会立刻暴露。
2. **无候选规模/耗时上限断言**——C-1 可用「`collectCandidates` 处理 256KB 输入须在 X ms 内、候选数须 ≤ N」守住量级。
3. **无密钥文件权限断言**——C-2 可用一行 `fs.statSync(out).mode & 0o777 === 0o600` 守住。
4. `tryOpenWithEncKey` / `exportPlaintext` / `decryptSelective` / `runPipeline` 全部无测试（M-2、M-3 落在此区）。

---

## 总结

整体判断：**核心解密算法与报告生成是可靠的，且有认真写过的自测；风险几乎全部集中在「外壳层」——密钥这类敏感数据的落地/输出方式、异步与资源释放契约、以及被复杂度量级压垮的密钥搜索路径。**

优先级建议（按「先恢复可用性，再堵住泄密面，最后清理规范」排序）：

1. **C-1 + M-1**：先让 `--dump` / `--allow-memory-scan` 与真实大库解密跑得完、不 OOM。这是文档主推路径当前的实际阻塞点。
2. **C-2 + C-3 + M-5**：密钥只以 0600 存于私有目录、不再原文打印；`decrypt` 的 `await` 补回，恢复 agent 依赖的「错误：可操作提示 + 退出码」契约。这三条改动量小（各约 5–15 行）、收益直接。
3. **M-3 + M-6 + M-4**：修错误归因（别把「密钥不对」报成「缺原生模块」）、清理 frida 定时器、消息表单次遍历。

若只想先动最小的一刀：改 `bin/wcdb.js:80`（加 `await`）与 `bin/wcdb.js:60`、`src/macKeyFrida.js:11/138`、`bin/wcdb.js:44/55`（权限与打印），10 行内即可消除两个 Critical 的实际暴露面。

---

## 附录 A：验证证据

| 结论 | 验证方式 | 结果 |
|------|----------|------|
| 基线自测 | `node test/selftest.js` | 26 通过 / 0 失败 |
| 单偏移 PBKDF2 成本 | 本地实测各变体耗时（Node v24.21.0，darwin arm64） | sha1/64000=15.49ms、sha512/256000=52.67ms、sha512/64000=12.77ms、sha1/4000=0.82ms → **81.75 ms/偏移** |
| C-1 量级 | 直接对 `collectCandidates` 跑 2KB 输入 | **超 2 分钟未完成**（被强制转后台），与外推一致 |
| JS 解密吞吐 / 内存 | 合成 4MB、16MB WCDB 页做 `decryptBuffer` | 27ms / 101ms（**≈150 MB/s**），16MB 输入对应 **RSS 120MB** |
| M-1 算法无需重写 | 同上 | 吞吐足够，瓶颈只在「整库驻留」 |
| C-3 浮空 Promise | 用已安装的 commander 构造同构最小复现（同步 action 内浮空调用 async） | `.catch` 未捕获 → 打印裸栈、exit 1；handler 返回早于异步完成 |
| sqlcipher 是否可用 | `ls node_modules`、`ls node_modules/sqlcipher` | **未安装**（仅 `@foxglove`、`better-sqlite3`、`commander`、`koffi`、`node-addon-api`） → M-3 成立 |
| frida 是否声明 | grep `package.json` / `package-lock.json` | **未声明**，仅 `README.md:64` 要求手工 `npm install frida` → m-10 成立 |
| `path` 未使用 | grep `path\.` in `bin/wcdb.js` | 无匹配 → m-2 成立 |
| `decrypt` 未 await | grep `await` in `bin/wcdb.js` | 仅 `:42`、`:94`、`:146` 三处有 await，`:80` 无 → C-3 定位确认 |
| M-2 拼接 SQL | ⚠️ **未运行时验证**（验证脚本被本地安全策略拦截） | 静态判断：`src/decrypt.js:117` 未转义 `'`，请自行复核 |
| C-2 落盘位置与权限 | `node -e "console.log(require('os').tmpdir())"` + 静态代码 | 普通终端 `$TMPDIR` 为**私有 per-user 目录**（非 `/tmp`）；但文档主推 `sudo` 调用，sudo 重置 `TMPDIR` 后回落 `/tmp/wxdb/`（见 `README.md:108` 自述）。sudo 分支**未能实测**（需密码），`writeFileSync` 无 `mode` → 0644 为代码事实 |
